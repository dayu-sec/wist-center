//! 包一层 **ApiError** 的请求体 / 查询提取器：axum 默认的 `Json` / `Query` 拒绝是纯文本正文，
//! 绕过了本仓统一的 `{ "error": { code, message } }` 信封（且不落日志）。这里把拒绝折成
//! [`ApiError`]（通用话术 + 内部因由进日志），让**所有**错误都同一形状。

use axum::extract::Request;
use axum::{
    Json,
    extract::{
        FromRequest, FromRequestParts, Query,
        rejection::{JsonRejection, QueryRejection},
    },
    http::request::Parts,
};

use super::{codes, error::ApiError};

/// 同 [`axum::Json`]，但反序列化失败时返回 [`ApiError`]（信封）而不是 axum 的纯文本 400。
#[derive(Debug, Clone, Copy)]
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(ApiJson(value)),
            // `body_text()`（含字段名 / 期望类型）只进日志；对外只出通用话术 + 状态码。
            Err(rejection) => Err(ApiError::internal_with(
                rejection.status(),
                codes::INVALID_REQUEST_BODY,
                "invalid request body",
                rejection.body_text(),
            )),
        }
    }
}

/// 同 [`axum::Query`]，但解析失败时返回 [`ApiError`]（信封）而不是 axum 的纯文本 400。
#[derive(Debug, Clone, Copy)]
pub struct ApiQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for ApiQuery<T>
where
    Query<T>: FromRequestParts<S, Rejection = QueryRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(ApiQuery(value)),
            Err(rejection) => Err(ApiError::internal_with(
                rejection.status(),
                codes::INVALID_QUERY,
                "invalid query parameters",
                rejection.body_text(),
            )),
        }
    }
}
