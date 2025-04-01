use axum::{
    Router,
    body::Body,
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::get,
};
use chrono::Utc;
use serde::Deserialize;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

const EMULATOR_STORAGE_ACCOUNT_KIND: &'static str = "StorageV2";

const EMULATOR_STORAGE_SKU: &'static str = "Standard_RAGRS";

const EMULATOR_STORAGE_VERSION: &'static str = "2025-05-05";

const EMULATOR_HNS_ENABLED: bool = false;

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
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind("0.0.0.0:10000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct Params {
    restype: String,
    comp: String,
}

async fn account(
    Path(account_name): Path<String>,
    Query(params): Query<Params>,
    headers: HeaderMap,
) -> Response {
    tracing::info!(
        "account: {}, restype: {:?}, comp: {:?}",
        account_name,
        params.restype,
        params.comp
    );

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header("Date", Utc::now().to_string())
        .header("x-ms-account-kind", EMULATOR_STORAGE_ACCOUNT_KIND)
        .header("x-ms-is-hns-enabled", EMULATOR_HNS_ENABLED.to_string())
        .header("x-ms-request-id", "")
        .header("x-ms-sku-name", EMULATOR_STORAGE_SKU)
        .header("x-ms-version", EMULATOR_STORAGE_VERSION);

    // Add the `x-ms-client-request-id` header if it's present and the value is at most 1024
    // visible ASCII characters.
    // TODO: could add check that storage version >= 2019-07-07
    if let Some(client_request_id) = headers.get("x-ms-client-request-id") {
        if client_request_id.len() <= 1024 {
            if let Ok(client_request_id) = client_request_id.to_str() {
                response = response.header("x-ms-client-request-id", client_request_id);
            }
        }
    }

    response.body(Body::empty()).unwrap()
}
