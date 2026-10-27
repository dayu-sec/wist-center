//! 通用后台任务队列：持久化任务 + 按 kind 注册的 handler + 串行 worker。
//!
//! 这一层只关心「**可靠地把一件事执行完并报告状态**」，不认识具体业务：
//! - 任务载荷 / 结果都是 JSON（业务侧自己序列化）；
//! - 执行逻辑通过 [`JobHandler`] 按 `kind` 注册；
//! - 状态机：`queued → running → succeeded / failed`；
//! - 进度通过 [`JobContext::report`] 回写（每完成一个子步骤一次，别在循环里刷库）；
//! - 任务落库（PG / FileStore 双实现），进程重启时把 `running` 排回 `queued`
//!   （业务侧需要保证执行幂等）。
//!
//! 当前调刻保持薄：没有重试 / 租约 / 队列深度上限（这些是下一步）。先把
//! 「入队 → 执行 → 查询 → 取消 → 清理」这条主干做成所有中心本地作业共用的能力。
//!
//! **执行器隔离**：handler 在独立 task 里跑；它 panic 只会让这一条任务失败
//! （`job_panicked`），不会掀翻整个 worker 循环。

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use wist_control::types::DateTime;

use super::store::{Store, StoreError};

/// 任务状态：排队中。
pub const JOB_QUEUED: &str = "queued";
/// 任务状态：执行中（worker 已认领）。
pub const JOB_RUNNING: &str = "running";
/// 任务状态：成功（`result` 带业务结果）。
pub const JOB_SUCCEEDED: &str = "succeeded";
/// 任务状态：失败（`error_code` / `error_detail` 说明原因）。
pub const JOB_FAILED: &str = "failed";
/// 任务状态：已取消（仅排队中的任务可取消；不会被执行）。
pub const JOB_CANCELED: &str = "canceled";

/// 默认任务保留天数：终态任务超过它会被后台清理（成功 / 失败 / 已取消）。
pub const DEFAULT_JOB_RETENTION_DAYS: i64 = 7;

/// worker 空闲时的兜底唤醒周期：别的中心实例可能往库里写了任务，本实例没收到 `notify`。
const IDLE_WAIT: Duration = Duration::from_secs(5);
/// 终态任务的清理周期（保留期本身由 `JobQueue::with_retention_days` 配，默认 7 天）。
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// 出错后的重试退避（任务本身已标记失败，这里只是别把日志刷爆）。
const ERROR_BACKOFF: Duration = Duration::from_secs(1);
/// 任务失败原因入库上限（防止上游错误链把 payload 撑爆）。
const MAX_ERROR_DETAIL: usize = 4 * 1024;

/// 把多行错误折成单行并限制长度（日志 / 任务视图都不该被换行与无界文本撑爆）。
fn one_line(value: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if out.len() >= max {
            out.push('…');
            break;
        }
        match ch {
            '\n' | '\r' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
}

/// 任务进度：`completed / total` + 一句可读说明（前端显示「取包 2/3」靠它）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JobProgress {
    #[serde(default)]
    pub completed: u32,
    #[serde(default)]
    pub total: u32,
    #[serde(default)]
    pub message: Option<String>,
}

/// 一条持久化任务。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    pub job_id: String,
    /// handler 类型（如 `release-download`）；worker 按它找执行器。
    pub kind: String,
    /// 队列名（同一队列串行执行；不同队列可各起一个 worker）。
    pub queue: String,
    /// 业务主体（如 release 的 `component`）；供通用读面按它过滤，避免
    /// 「先取最近 N 条再在内存里筛」把目标任务筛没。
    #[serde(default)]
    pub subject: Option<String>,
    /// `queued` | `running` | `succeeded` | `failed`。
    pub state: String,
    /// 同队列内认领顺序：大者优先，再按 `created_at` 从早到晚。
    #[serde(default)]
    pub priority: i32,
    /// 业务载荷（JSON）。
    pub payload: serde_json::Value,
    /// 成功结果（JSON）。
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub progress: JobProgress,
    /// 失败码（`api::codes` 里的稳定字符串）。
    #[serde(default)]
    pub error_code: Option<String>,
    /// 失败对应的 HTTP 状态（同步兼容模式折回同一状态码）。
    #[serde(default)]
    pub error_status: Option<u16>,
    /// 可暴露的失败原因。
    #[serde(default)]
    pub error_detail: Option<String>,
    pub created_at: DateTime,
    #[serde(default)]
    pub started_at: Option<DateTime>,
    #[serde(default)]
    pub finished_at: Option<DateTime>,
}

impl JobRecord {
    /// 新建一条排队任务。
    pub fn queued(
        queue: impl Into<String>,
        kind: impl Into<String>,
        payload: serde_json::Value,
        priority: i32,
    ) -> Self {
        let kind = kind.into();
        Self {
            job_id: new_job_id(&kind),
            queue: queue.into(),
            kind,
            subject: None,
            state: JOB_QUEUED.to_string(),
            priority,
            payload,
            result: None,
            progress: JobProgress::default(),
            error_code: None,
            error_status: None,
            error_detail: None,
            created_at: DateTime::now(),
            started_at: None,
            finished_at: None,
        }
    }

    /// 任务是否已到明确终态（成功 / 失败 / 已取消）。
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state.as_str(),
            JOB_SUCCEEDED | JOB_FAILED | JOB_CANCELED
        )
    }

    /// 标业务主体（如 release 的组件名），供通用读面按主体过滤。
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        let subject = subject.into();
        self.subject = (!subject.trim().is_empty()).then_some(subject);
        self
    }
}

/// 任务 id：`job-<kind>-<unix millis>-<seq>`。
fn new_job_id(kind: &str) -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("job-{kind}-{millis}-{seq}")
}

/// 执行失败（带 HTTP 语义，供任务视图 / 同步兼容端点使用）。
#[derive(Debug, Clone)]
pub struct JobFailure {
    pub status: u16,
    pub code: &'static str,
    pub detail: String,
}

impl JobFailure {
    pub fn new(status: u16, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            code,
            detail: detail.into(),
        }
    }
}

/// 取消结果：区分「取消成功」「不是排队中」「任务不存在」。
#[derive(Debug, Clone)]
pub enum CancelOutcome {
    Canceled(JobRecord),
    /// 任务在跑 / 已终结：不能取消。带回当前快照供调用方报状态。
    NotCancelable(JobRecord),
    NotFound,
}

/// 执行上下文：handler 通过它回报进度，不必自己碰存储。
#[derive(Clone)]
pub struct JobContext {
    store: Arc<dyn Store>,
    job_id: String,
    progress: Arc<Mutex<JobProgress>>,
}

impl JobContext {
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// 更新并持久化进度（同一把锁里改内存快照，再异步落库）。
    ///
    /// 回写失败只告警：进度落后不影响业务执行本身。
    pub async fn report(&self, update: impl FnOnce(&mut JobProgress)) {
        let snapshot = {
            let mut progress = self
                .progress
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            update(&mut progress);
            progress.clone()
        };
        if let Err(err) = self
            .store
            .update_job_progress(&self.job_id, &snapshot)
            .await
        {
            log::warn!(
                "event=JobProgressSaveFailed job_id={} error={err}",
                self.job_id
            );
        }
    }

    pub fn progress(&self) -> JobProgress {
        self.progress
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// 业务执行器：一个 `kind` 一个实现。
#[async_trait::async_trait]
pub trait JobHandler: Send + Sync {
    fn kind(&self) -> &'static str;
    /// 执行任务；成功返回业务结果（JSON），失败返回可暴露的失败。
    async fn run(&self, ctx: &JobContext, job: &JobRecord)
    -> Result<serde_json::Value, JobFailure>;
}

/// 通用任务队列（一个实例对应一个 `queue`；不同队列可各起一个 worker）。
#[derive(Clone)]
pub struct JobQueue {
    inner: Arc<Inner>,
}

struct Inner {
    store: Arc<dyn Store>,
    queue: String,
    handlers: HashMap<String, Arc<dyn JobHandler>>,
    notify: tokio::sync::Notify,
    started: AtomicBool,
    /// 终态任务保留天数；超过后由清理循环删除。
    retention_days: i64,
}

impl std::fmt::Debug for JobQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobQueue")
            .field("queue", &self.inner.queue)
            .field("handlers", &self.inner.handlers.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl JobQueue {
    pub fn new(
        store: Arc<dyn Store>,
        queue: impl Into<String>,
        handlers: HashMap<String, Arc<dyn JobHandler>>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                queue: queue.into(),
                handlers,
                notify: tokio::sync::Notify::new(),
                started: AtomicBool::new(false),
                retention_days: DEFAULT_JOB_RETENTION_DAYS,
            }),
        }
    }

    /// 覆盖终态任务的保留天数（`<= 0` 视为不清理）。需在 [`Self::start`] 前调用。
    pub fn with_retention_days(self, days: i64) -> Self {
        // `Arc` 已经构造：直接替换 inner 的字段不现实，重新包一层。
        let inner = Inner {
            store: self.inner.store.clone(),
            queue: self.inner.queue.clone(),
            handlers: self.inner.handlers.clone(),
            notify: tokio::sync::Notify::new(),
            started: AtomicBool::new(false),
            retention_days: days,
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// 启动后台 worker（进程内只启一次）。
    ///
    /// 先把上次退出时残留的 `running` 任务排回 `queued`：业务执行需要幂等，重跑比永远
    /// 「执行中」更诚实。
    pub fn start(&self) {
        if self.inner.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let queue = self.clone();
        tokio::spawn(async move { queue.worker_loop().await });
        let cleanup = self.clone();
        tokio::spawn(async move { cleanup.cleanup_loop().await });
    }

    /// 入队一条任务并唤醒 worker。
    pub async fn enqueue(&self, job: JobRecord) -> Result<JobRecord, StoreError> {
        // 懒启动：生产在 `state_of` 已启；测试 / 手动构造的 `ApiState` 在这里补一次。
        self.start();
        self.inner.store.create_job(&job).await?;
        self.inner.notify.notify_one();
        Ok(job)
    }

    /// 处理一条排队任务（测试直接驱动用；生产由 [`Self::start`] 的循环调用）。
    pub async fn run_next(&self) -> Result<Option<JobRecord>, StoreError> {
        let Some(mut job) = self.inner.store.claim_next_job(&self.inner.queue).await? else {
            return Ok(None);
        };
        log::info!(
            "event=JobStarted job_id={} kind={} queue={}",
            job.job_id,
            job.kind,
            job.queue
        );
        let Some(handler) = self.inner.handlers.get(&job.kind).cloned() else {
            job.state = JOB_FAILED.to_string();
            job.error_code = Some(crate::api::codes::JOB_KIND_UNKNOWN.to_string());
            job.error_status = Some(500);
            job.error_detail = Some(format!("no handler registered for job kind `{}`", job.kind));
            job.finished_at = Some(DateTime::now());
            self.inner.store.save_job(&job).await?;
            log::error!(
                "event=JobHandlerMissing job_id={} kind={}",
                job.job_id,
                job.kind
            );
            return Ok(Some(job));
        };

        let progress = Arc::new(Mutex::new(job.progress.clone()));
        let ctx = JobContext {
            store: self.inner.store.clone(),
            job_id: job.job_id.clone(),
            progress: progress.clone(),
        };
        // handler 在独立 task 里执行：panic 只让这一条任务失败，不会带走 worker 循环。
        let handler_task = handler.clone();
        let ctx_task = ctx.clone();
        let job_task = job.clone();
        let outcome =
            tokio::spawn(async move { handler_task.run(&ctx_task, &job_task).await }).await;
        match outcome {
            Ok(Ok(result)) => {
                job.state = JOB_SUCCEEDED.to_string();
                job.result = Some(result);
                job.error_code = None;
                job.error_status = None;
                job.error_detail = None;
                log::info!("event=JobSucceeded job_id={}", job.job_id);
            }
            Ok(Err(failure)) => {
                let detail = one_line(&failure.detail, MAX_ERROR_DETAIL);
                job.state = JOB_FAILED.to_string();
                job.result = None;
                job.error_code = Some(failure.code.to_string());
                job.error_status = Some(failure.status);
                job.error_detail = Some(detail.clone());
                log::warn!(
                    "event=JobFailed job_id={} code={} detail={}",
                    job.job_id,
                    failure.code,
                    one_line(&detail, 512)
                );
            }
            Err(join) => {
                job.state = JOB_FAILED.to_string();
                job.result = None;
                job.error_code = Some(crate::api::codes::JOB_PANICKED.to_string());
                job.error_status = Some(500);
                job.error_detail = Some(if join.is_panic() {
                    "job handler panicked".to_string()
                } else {
                    "job handler task was aborted".to_string()
                });
                log::error!(
                    "event=JobHandlerPanicked job_id={} error={}",
                    job.job_id,
                    one_line(&join.to_string(), 512)
                );
            }
        }
        job.progress = ctx.progress();
        job.finished_at = Some(DateTime::now());
        // 写终态失败时任务会停在 `running`：worker 继续处理下一条，只能靠重启时的
        // `requeue_running_jobs` 恢复。日志记下 job_id / 目标状态，运维才查得到是哪一条。
        if let Err(err) = self.inner.store.save_job(&job).await {
            log::error!(
                "event=JobSaveFailed job_id={} state={} error={err}",
                job.job_id,
                job.state
            );
            return Err(err);
        }
        Ok(Some(job))
    }

    /// 等一条任务到终态（同步兼容端点的兼容桥）。超时返回 `None`。
    pub async fn wait_for_terminal(
        &self,
        job_id: &str,
        timeout: Duration,
    ) -> Result<Option<JobRecord>, StoreError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(job) = self.inner.store.get_job(job_id).await?
                && job.is_terminal()
            {
                return Ok(Some(job));
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(None);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    pub async fn get(&self, job_id: &str) -> Result<Option<JobRecord>, StoreError> {
        self.inner.store.get_job(job_id).await
    }

    /// 本队列最近的 `limit` 条任务（新→旧）。
    pub async fn list(&self, limit: usize) -> Result<Vec<JobRecord>, StoreError> {
        self.inner.store.list_jobs(&self.inner.queue, limit).await
    }

    /// 取消一条**排队中**的任务。已开始执行 / 已终结的任务不会被取消。
    pub async fn cancel(&self, job_id: &str) -> Result<CancelOutcome, StoreError> {
        self.inner.store.cancel_queued_job(job_id).await
    }

    /// 清理本队列超过保留期的终态任务；返回删除条数。
    pub async fn cleanup(&self) -> Result<u64, StoreError> {
        if self.inner.retention_days <= 0 {
            return Ok(0);
        }
        let cutoff = DateTime::in_days(-self.inner.retention_days);
        self.inner
            .store
            .delete_terminal_jobs_before(&self.inner.queue, &cutoff)
            .await
    }

    async fn cleanup_loop(&self) {
        loop {
            match self.cleanup().await {
                Ok(0) => {}
                Ok(deleted) => log::info!(
                    "event=JobCleanup queue={} deleted={deleted} retention_days={}",
                    self.inner.queue,
                    self.inner.retention_days
                ),
                Err(err) => log::warn!(
                    "event=JobCleanupFailed queue={} error={err}",
                    self.inner.queue
                ),
            }
            tokio::time::sleep(CLEANUP_INTERVAL).await;
        }
    }

    async fn worker_loop(&self) {
        if let Err(err) = self
            .inner
            .store
            .requeue_running_jobs(&self.inner.queue)
            .await
        {
            log::warn!(
                "event=JobRequeueFailed queue={} error={err}",
                self.inner.queue
            );
        }
        loop {
            match self.run_next().await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    // 兜底超时：别的中心实例写库时本实例收不到 notify。
                    let _ = tokio::time::timeout(IDLE_WAIT, self.inner.notify.notified()).await;
                }
                Err(err) => {
                    log::error!("event=JobQueueError queue={} error={err}", self.inner.queue);
                    tokio::time::sleep(ERROR_BACKOFF).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::infra::{FileStore, Store};

    use super::*;

    struct PanicHandler;

    #[async_trait::async_trait]
    impl JobHandler for PanicHandler {
        fn kind(&self) -> &'static str {
            "panic"
        }

        async fn run(
            &self,
            _ctx: &JobContext,
            _job: &JobRecord,
        ) -> Result<serde_json::Value, JobFailure> {
            panic!("boom");
        }
    }

    struct OkHandler;

    #[async_trait::async_trait]
    impl JobHandler for OkHandler {
        fn kind(&self) -> &'static str {
            "ok"
        }

        async fn run(
            &self,
            _ctx: &JobContext,
            _job: &JobRecord,
        ) -> Result<serde_json::Value, JobFailure> {
            Ok(serde_json::json!({ "ok": true }))
        }
    }

    fn queue_with(
        handlers: Vec<Arc<dyn JobHandler>>,
    ) -> (Arc<dyn Store>, JobQueue, std::path::PathBuf) {
        // 纳秒 + 进程内原子序号：光靠纳秒在并行跑测试时会撞同一路径，撞上就变成随机失败
        // （与 `store::tests::test_store_path` 同一个理由）。
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
        let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "wist-jobs-{}-{nanos}-{sequence}.json",
            std::process::id()
        ));
        let store: Arc<dyn Store> = Arc::new(FileStore::new(&path));
        let mut map: HashMap<String, Arc<dyn JobHandler>> = HashMap::new();
        for handler in handlers {
            map.insert(handler.kind().to_string(), handler);
        }
        let queue = JobQueue::new(store.clone(), "test", map);
        (store, queue, path)
    }

    #[test]
    fn job_ids_are_unique_and_kind_scoped() {
        let first = new_job_id("release-download");
        let second = new_job_id("release-download");
        assert!(first.starts_with("job-release-download-"), "{first}");
        assert_ne!(first, second);
    }

    #[test]
    fn queued_jobs_are_not_terminal() {
        let job = JobRecord::queued("q", "k", serde_json::json!({}), 0);
        assert!(!job.is_terminal());
        assert_eq!(job.state, JOB_QUEUED);
    }

    #[test]
    fn canceled_jobs_are_terminal() {
        let mut job = JobRecord::queued("q", "k", serde_json::json!({}), 0);
        job.state = JOB_CANCELED.to_string();
        assert!(job.is_terminal());
    }

    #[test]
    fn one_line_collapses_newlines_and_truncates() {
        assert_eq!(one_line("a\nb\r\nc", 100), "a b  c");
        assert_eq!(one_line("abcdef", 3), "abc…");
        let cut = one_line(&"你".repeat(10), 4);
        assert!(cut.ends_with('…'));
    }

    /// handler panic 只把这一条任务标成 `job_panicked`，worker 还能继续处理下一条。
    #[tokio::test]
    async fn a_panicking_handler_fails_only_that_job() {
        let (store, queue, path) = queue_with(vec![
            Arc::new(PanicHandler) as Arc<dyn JobHandler>,
            Arc::new(OkHandler),
        ]);
        store
            .create_job(&JobRecord::queued(
                "test",
                "panic",
                serde_json::json!({}),
                0,
            ))
            .await
            .expect("create panic job");
        let failed = queue.run_next().await.expect("run").expect("job");
        assert_eq!(failed.state, JOB_FAILED);
        assert_eq!(
            failed.error_code.as_deref(),
            Some(crate::api::codes::JOB_PANICKED)
        );

        store
            .create_job(&JobRecord::queued("test", "ok", serde_json::json!({}), 0))
            .await
            .expect("create ok job");
        let ok = queue.run_next().await.expect("run").expect("job");
        assert_eq!(ok.state, JOB_SUCCEEDED);
        assert_eq!(ok.result, Some(serde_json::json!({ "ok": true })));
        let _ = std::fs::remove_file(path);
    }

    /// 队列级清理：只删超期的终态任务；排队中（没有 finished_at）永不清理。
    #[tokio::test]
    async fn cleanup_deletes_only_expired_terminal_jobs() {
        let (store, queue, path) = queue_with(vec![]);
        let mut old = JobRecord::queued("test", "ok", serde_json::json!({}), 0);
        old.job_id = "job-old".to_string();
        old.state = JOB_SUCCEEDED.to_string();
        old.finished_at = Some(DateTime::in_days(-8));
        store.create_job(&old).await.expect("create old");

        let mut recent = JobRecord::queued("test", "ok", serde_json::json!({}), 0);
        recent.job_id = "job-recent".to_string();
        recent.state = JOB_FAILED.to_string();
        recent.finished_at = Some(DateTime::now());
        store.create_job(&recent).await.expect("create recent");

        let mut queued = JobRecord::queued("test", "ok", serde_json::json!({}), 0);
        queued.job_id = "job-queued".to_string();
        store.create_job(&queued).await.expect("create queued");

        assert_eq!(queue.cleanup().await.expect("cleanup"), 1);
        assert!(store.get_job("job-old").await.expect("get").is_none());
        assert!(store.get_job("job-recent").await.expect("get").is_some());
        assert!(
            store.get_job("job-queued").await.expect("get").is_some(),
            "排队中的任务即使很旧也不能清理"
        );

        // retention <= 0 = 不清理。
        let no_cleanup = queue.with_retention_days(0);
        assert_eq!(no_cleanup.cleanup().await.expect("cleanup"), 0);
        let _ = std::fs::remove_file(path);
    }

    /// 没有 handler 的 kind：任务直接判 `job_kind_unknown`，不能把 worker 卡死。
    ///
    /// 这是「多实例读到别的版本写的任务」和「handler 名字写错」时的兜底路径，
    /// 所以任务必须自己终结掉，后面的任务才能被继续认领。
    #[tokio::test]
    async fn an_unknown_kind_fails_the_job_and_keeps_the_worker_alive() {
        let (store, queue, path) = queue_with(vec![Arc::new(OkHandler) as Arc<dyn JobHandler>]);
        store
            .create_job(&JobRecord::queued(
                "test",
                "mystery",
                serde_json::json!({}),
                0,
            ))
            .await
            .expect("create unknown job");

        let failed = queue.run_next().await.expect("run").expect("job");
        assert_eq!(failed.state, JOB_FAILED);
        assert_eq!(
            failed.error_code.as_deref(),
            Some(crate::api::codes::JOB_KIND_UNKNOWN)
        );
        // 错误信息要能看出是哪个 kind 没人接，方便定位是版本不一致还是拼写错误。
        assert!(
            failed
                .error_detail
                .as_deref()
                .is_some_and(|detail| detail.contains("mystery")),
            "{failed:?}"
        );

        store
            .create_job(&JobRecord::queued("test", "ok", serde_json::json!({}), 0))
            .await
            .expect("create ok job");
        let ok = queue.run_next().await.expect("run").expect("job");
        assert_eq!(ok.state, JOB_SUCCEEDED);
        let _ = std::fs::remove_file(path);
    }

    /// 重启重排：`running` 回到 `queued`，并且**清掉旧进度**。
    ///
    /// 不清的话，排队中的任务会带着上一轮的「镜像 2/5」停在列表里，看起来像卡住。
    #[tokio::test]
    async fn requeueing_running_jobs_clears_stale_progress() {
        let (store, _queue, path) = queue_with(vec![]);
        let mut job = JobRecord::queued("test", "ok", serde_json::json!({}), 0);
        job.job_id = "job-stale".to_string();
        job.state = JOB_RUNNING.to_string();
        job.started_at = Some(DateTime::now());
        job.progress = JobProgress {
            message: Some("镜像 2/5".to_string()),
            ..JobProgress::default()
        };
        store.create_job(&job).await.expect("create running job");

        assert_eq!(
            store.requeue_running_jobs("test").await.expect("requeue"),
            1
        );
        let requeued = store.get_job("job-stale").await.expect("get").expect("job");
        assert_eq!(requeued.state, JOB_QUEUED);
        assert!(requeued.started_at.is_none(), "{requeued:?}");
        assert_eq!(requeued.progress.message.as_deref(), Some("重新排队中"));
        assert_eq!(
            requeued.progress.completed, 0,
            "旧进度（完成数）不能留在重新排队的任务上"
        );
        let _ = std::fs::remove_file(path);
    }

    /// 取消只对 `queued` 生效：`running` 的任务拒绝取消，且**不改变**它的状态。
    #[tokio::test]
    async fn a_running_job_cannot_be_canceled() {
        let (store, _queue, path) = queue_with(vec![]);
        let mut job = JobRecord::queued("test", "ok", serde_json::json!({}), 0);
        job.job_id = "job-running".to_string();
        job.state = JOB_RUNNING.to_string();
        store.create_job(&job).await.expect("create running job");

        match store
            .cancel_queued_job("job-running")
            .await
            .expect("cancel")
        {
            CancelOutcome::NotCancelable(current) => {
                assert_eq!(current.state, JOB_RUNNING);
            }
            other => panic!("unexpected: {other:?}"),
        }
        let untouched = store
            .get_job("job-running")
            .await
            .expect("get")
            .expect("job");
        assert_eq!(untouched.state, JOB_RUNNING);

        match store.cancel_queued_job("job-absent").await.expect("cancel") {
            CancelOutcome::NotFound => {}
            other => panic!("unexpected: {other:?}"),
        }
        let _ = std::fs::remove_file(path);
    }
}
