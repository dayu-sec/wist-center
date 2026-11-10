// 制品存储抽象：版本发布时把外部制品镜像到本地文件或云对象存储（S3 兼容 / MinIO），
// 返回快的可下载地址（避免直接依赖 GitHub 等慢源分发）。

use std::{fs, path::PathBuf, sync::Arc};

use async_trait::async_trait;

use crate::config::{CenterConfig, ObjectStorageConfig};

#[async_trait]
pub trait ArtifactStore: Send + Sync + std::fmt::Debug {
    /// 存储制品字节，返回可下载 URL。
    async fn store(
        &self,
        component: &str,
        version: &str,
        filename: &str,
        bytes: Vec<u8>,
    ) -> Result<String, String>;
}

/// 三段都必须是真的「一段」（非空、非 `.` / `..`、无分隔符与控制字符），否则 `Path::join`
/// 与对象存储 key 会逃出目标目录。调用方（管理面 / 下载路由）已各自校验过，这里是存储层的**兜底**：
/// 存储层不该依赖调用方记得校验。
fn validate_segments(component: &str, version: &str, filename: &str) -> Result<(), String> {
    for (label, value) in [
        ("component", component),
        ("version", version),
        ("filename", filename),
    ] {
        if !wist_release::package::is_safe_path_segment(value) {
            return Err(format!(
                "{label} must be a single safe path segment, got {value:?}"
            ));
        }
    }
    Ok(())
}

/// 本地文件存储：写 `{artifact_dir}/{component}/{version}/{filename}`，
/// 下载地址由 center 的制品下载服务提供。
#[derive(Debug)]
pub struct LocalArtifactStore {
    dir: PathBuf,
    public_url: String,
}

impl LocalArtifactStore {
    pub fn new(dir: PathBuf, public_url: &str) -> Self {
        Self {
            dir,
            public_url: public_url.to_string(),
        }
    }
}

#[async_trait]
impl ArtifactStore for LocalArtifactStore {
    async fn store(
        &self,
        component: &str,
        version: &str,
        filename: &str,
        bytes: Vec<u8>,
    ) -> Result<String, String> {
        validate_segments(component, version, filename)?;
        let dir = self.dir.join(component).join(version);
        fs::create_dir_all(&dir).map_err(|err| format!("create artifact dir failed: {err}"))?;
        fs::write(dir.join(filename), &bytes)
            .map_err(|err| format!("write artifact failed: {err}"))?;
        Ok(format!(
            "{}/api/v1/releases/artifact/{component}/{version}/{filename}",
            self.public_url.trim_end_matches('/')
        ))
    }
}

/// 云对象存储（S3 兼容 / MinIO）：上传 `{bucket}/{component}/{version}/{filename}`，
/// 返回对象存储直接 URL。
#[derive(Debug)]
pub struct ObjectStorageArtifactStore {
    endpoint: String,
    bucket: String,
    client: aws_sdk_s3::Client,
}

impl ObjectStorageArtifactStore {
    pub fn new(config: &ObjectStorageConfig) -> Result<Self, String> {
        use aws_sdk_s3::Config;
        use aws_sdk_s3::config::{Credentials, Region};

        let creds = Credentials::new(
            &config.access_key,
            &config.secret_key,
            None,
            None,
            "artifact-store",
        );
        let cfg = Config::builder()
            .endpoint_url(&config.endpoint)
            .region(Region::new("us-east-1"))
            .credentials_provider(creds)
            .build();
        let client = aws_sdk_s3::Client::from_conf(cfg);
        Ok(Self {
            endpoint: config.endpoint.clone(),
            bucket: config.bucket.clone(),
            client,
        })
    }
}

#[async_trait]
impl ArtifactStore for ObjectStorageArtifactStore {
    async fn store(
        &self,
        component: &str,
        version: &str,
        filename: &str,
        bytes: Vec<u8>,
    ) -> Result<String, String> {
        use aws_sdk_s3::primitives::ByteStream;

        validate_segments(component, version, filename)?;
        let key = format!("{component}/{version}/{filename}");
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(|err| format!("object storage put failed: {err}"))?;
        Ok(format!(
            "{}/{}/{}",
            self.endpoint.trim_end_matches('/'),
            self.bucket,
            key
        ))
    }
}

/// 按配置选择制品存储：对象存储初始化失败时回退本地文件。
pub fn build_artifact_store(config: &CenterConfig) -> Arc<dyn ArtifactStore> {
    if let Some(object_storage) = &config.object_storage
        && let Ok(store) = ObjectStorageArtifactStore::new(object_storage)
    {
        return Arc::new(store);
    }
    Arc::new(LocalArtifactStore::new(
        config.artifact_dir.clone(),
        &config.public_url,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    /// 临时目录名的**进程内序号**。
    ///
    /// 只用 `SystemTime::now().as_nanos()` 不够：macOS 的时钟只有微秒级精度，
    /// cargo test 默认并行跑，两个测试可能在同一微秒内取到**同一个**值 ——
    /// 于是一个测试建出来的目录会把另一个测试「一个文件都不该落盘」的断言弄红
    /// （CI 上就这么错过一次）。加一个递增序号后名字必定唯一。
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn local_store() -> (LocalArtifactStore, PathBuf) {
        let seq = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "wist-center-artifacts-{}-{seq}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        (
            LocalArtifactStore::new(dir.clone(), "https://127.0.0.1:3100"),
            dir,
        )
    }

    /// 临时目录名必须每次不同（否则两个并行测试共用一个目录，结果随调度顺序变）。
    #[test]
    fn temp_dirs_are_unique_per_call() {
        let dirs: Vec<PathBuf> = (0..16).map(|_| local_store().1).collect();
        let unique: std::collections::HashSet<&PathBuf> = dirs.iter().collect();
        assert_eq!(unique.len(), dirs.len(), "临时目录名重叠：{dirs:?}");
    }

    #[tokio::test]
    async fn store_writes_the_expected_layout_and_returns_the_download_url() {
        let (store, dir) = local_store();
        let url = store
            .store(
                "wist-gateway-stack",
                "0.1.17",
                "gw.tar.gz",
                b"bytes".to_vec(),
            )
            .await
            .expect("store");
        assert_eq!(
            url,
            "https://127.0.0.1:3100/api/v1/releases/artifact/wist-gateway-stack/0.1.17/gw.tar.gz"
        );
        assert_eq!(
            std::fs::read(dir.join("wist-gateway-stack/0.1.17/gw.tar.gz")).expect("read back"),
            b"bytes"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn store_refuses_escaping_segments() {
        // 存储层的兜底：即便调用方忘了校验，后端也不接受能逃出制品目录的段。
        let (store, dir) = local_store();
        for (component, version, filename) in [
            ("../etc", "0.1.0", "x.bin"),
            ("wist-gateway-stack", "../..", "x.bin"),
            ("wist-gateway-stack", "0.1.0", "../../x.bin"),
            ("", "0.1.0", "x.bin"),
            (".", "0.1.0", "x.bin"),
            ("wist-gateway-stack", "0.1.0", "a\\b"),
        ] {
            let err = store
                .store(component, version, filename, b"bytes".to_vec())
                .await
                .expect_err("unsafe segments must be refused");
            assert!(err.contains("must be a single safe path segment"), "{err}");
        }
        // 一个文件都不该落盘（连目录都不该建）。
        assert!(!dir.exists(), "{} should not exist", dir.display());
    }
}
