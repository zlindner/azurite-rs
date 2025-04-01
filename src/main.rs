use axum::{
    Router,
    body::Body,
    extract::{Path, Query, Request},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const EMULATOR_STORAGE_ACCOUNT_KIND: &'static str = "StorageV2";
const EMULATOR_STORAGE_SKU: &'static str = "Standard_RAGRS";
const EMULATOR_STORAGE_VERSION: &'static str = "2025-05-05";
const EMULATOR_HNS_ENABLED: bool = false;

fn error_response(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap()
}

async fn auth(headers: HeaderMap, request: Request, next: Next) -> Response {
    // The request must have either the `x-ms-date` or `Date` header. If both are provided the
    // value of the `x-ms-date` header is used.
    let date_header = match headers.get("x-ms-date").or(headers.get("Date")) {
        Some(date_header) => date_header,
        None => {
            return error_response(StatusCode::FORBIDDEN);
        }
    };

    let utc_date: DateTime<Utc> = match date_header
        .to_str()
        .map_err(|_| ())
        .and_then(|s| s.parse().map_err(|_| ()))
    {
        Ok(date) => date,
        Err(_) => return error_response(StatusCode::FORBIDDEN),
    };

    // Ensure the date header is no older than 15 minutes to prevent replay attacks.
    if Utc::now().signed_duration_since(utc_date) > Duration::minutes(15) {
        return error_response(StatusCode::FORBIDDEN);
    }

    next.run(request).await
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("azurite_rs=debug,tower_http=debug"))
                .unwrap(),
        )
        .init();

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/{account_name}", get(account))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(middleware::from_fn(auth)),
        );

    let listener = TcpListener::bind("0.0.0.0:10000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct Params {
    #[serde(rename = "restype")]
    resource_type: Option<String>,
    #[serde(rename = "comp")]
    component: String,
}

async fn account(
    Path(account_name): Path<String>,
    Query(params): Query<Params>,
    headers: HeaderMap,
) -> Response {
    tracing::info!(
        "account: {}, resource_type: {:?}, component: {}",
        account_name,
        params.resource_type,
        params.component
    );

    // TODO: route based on query params

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header("Date", Utc::now().to_string())
        .header("x-ms-account-kind", EMULATOR_STORAGE_ACCOUNT_KIND)
        .header("x-ms-is-hns-enabled", EMULATOR_HNS_ENABLED.to_string())
        .header("x-ms-request-id", Uuid::new_v4().to_string())
        .header("x-ms-sku-name", EMULATOR_STORAGE_SKU)
        .header("x-ms-version", EMULATOR_STORAGE_VERSION);

    // Add the `x-ms-client-request-id` header if it's present and the value is at most 1024
    // visible ASCII characters.
    // TODO: could add check that storage version >= 2019-07-07
    if let Some(client_request_id_header) = headers.get("x-ms-client-request-id") {
        if client_request_id_header.len() <= 1024 {
            if let Ok(client_request_id) = client_request_id_header.to_str() {
                response = response.header("x-ms-client-request-id", client_request_id);
            }
        }
    }

    response.body(Body::empty()).unwrap()
}
