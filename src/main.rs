use std::collections::BTreeMap;

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
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const EMULATOR_STORAGE_ACCOUNT_KIND: &str = "StorageV2";
const EMULATOR_STORAGE_SKU: &str = "Standard_RAGRS";
const EMULATOR_STORAGE_VERSION: &str = "2025-05-05";
const EMULATOR_HNS_ENABLED: bool = false;
const EMULATOR_DEFAULT_ACCOUNT_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

/// Middleware that adds default response headers for every response.
async fn default_response_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    // Add the `Date` header if it's not already present.
    if !response.headers().contains_key("Date") {
        response
            .headers_mut()
            .insert("Date", Utc::now().to_string().parse().unwrap());
    }

    // Add the `x-ms-request-id` header if it's not already present.
    if !response.headers().contains_key("x-ms-request-id") {
        response.headers_mut().insert(
            "x-ms-request-id",
            Uuid::new_v4().to_string().parse().unwrap(),
        );
    }

    response
}

/// Middleware that authenticates the request.
/// TODO: we should eventually extract this into an `Authenticator` trait, the request should only
/// need to satisfy one authenticator to be considered valid.
async fn auth_middleware(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // TODO: move date header validation to a separate middleware?
    // The request must have either the `x-ms-date` or `Date` header. If both are provided the
    // value of the `x-ms-date` header is used.
    let date_header = headers
        .get("x-ms-date")
        .or(headers.get("Date"))
        .ok_or(StatusCode::FORBIDDEN)?
        .to_str()
        .map_err(|_| StatusCode::FORBIDDEN)?;

    let utc_date: DateTime<Utc> = date_header.parse().map_err(|_| StatusCode::FORBIDDEN)?;

    // Ensure the date header is no older than 15 minutes to prevent replay attacks.
    if Utc::now().signed_duration_since(utc_date) > Duration::minutes(15) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Get the auth header, if it is invalid or doesn't exist return a 403.
    let auth_header = headers
        .get("Authorization")
        .ok_or(StatusCode::FORBIDDEN)?
        .to_str()
        .map_err(|_| StatusCode::FORBIDDEN)?;

    // Parse the auth header to extract the authentication scheme, account name, and signature
    // Format: "[SharedKey|SharedKeyLite] <AccountName>:<Signature>"
    let (auth_scheme, account_and_signature) = match auth_header.split_once(' ') {
        Some(parts) => parts,
        None => return Err(StatusCode::FORBIDDEN),
    };

    // Ensure the auth scheme is either "SharedKey" or "SharedKeyLite"
    if auth_scheme != "SharedKey" && auth_scheme != "SharedKeyLite" {
        return Err(StatusCode::FORBIDDEN);
    }

    // Extract the account name and signature
    let (account_name, signature) = match account_and_signature.split_once(':') {
        Some(parts) => parts,
        None => return Err(StatusCode::FORBIDDEN),
    };

    // TODO: check if account exists - 404?
    if account_name.is_empty() {
        return Err(StatusCode::FORBIDDEN);
    }

    let headers = request.headers();
    let canonicalized_headers = canonicalize_ms_headers(headers);
    let canonicalized_resource = canonicalize_resource(&request.uri().to_string(), account_name);

    // TODO: possibly use + to append string instead of format.
    // TODO: we need to use x-ms-date val if it exists.
    let generated_signature = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}{}",
        request.method(),
        get_header_string_allow_empty(headers, "Content-Encoding"),
        get_header_string_allow_empty(headers, "Content-Language"),
        get_header_string_allow_empty(headers, "Content-Length"),
        get_header_string_allow_empty(headers, "Content-MD5"),
        get_header_string_allow_empty(headers, "Content-Type"),
        get_header_string_allow_empty(headers, "Date"),
        get_header_string_allow_empty(headers, "If-Modified-Since"),
        get_header_string_allow_empty(headers, "If-Match"),
        get_header_string_allow_empty(headers, "If-None-Match"),
        get_header_string_allow_empty(headers, "If-Unmodified-Since"),
        get_header_string_allow_empty(headers, "Range"),
        canonicalized_headers,
        canonicalized_resource
    );

    tracing::debug!("Generated signature: {}", generated_signature);

    if !verify_signature(&generated_signature, signature, account_name) {
        tracing::debug!("Signature verification failed");
        return Err(StatusCode::FORBIDDEN);
    } else {
        tracing::debug!("Signature verification succeeded");
    }

    Ok(next.run(request).await)
}

/// Canonicalizes x-ms headers (prefixed with x-ms-).
fn canonicalize_ms_headers(headers: &HeaderMap) -> String {
    // Use a BTreeMap to sort headers lexicographically by name
    let mut ms_headers = BTreeMap::new();

    for (key, value) in headers.iter() {
        let key_str = key.as_str().to_lowercase();
        if key_str.starts_with("x-ms-") {
            if let Ok(val) = value.to_str() {
                ms_headers.insert(key_str, val.to_string());
            }
        }
    }

    let mut result = String::new();
    for (key, value) in ms_headers.iter() {
        result.push_str(&format!("{}:{}\n", key, value));
    }

    result
}

/// Canonicalizes the resource string.
fn canonicalize_resource(uri: &str, account_name: &str) -> String {
    // Parse the URI to extract path and query
    let uri_parts: Vec<&str> = uri.split('?').collect();
    let path = uri_parts[0];

    let mut result = format!("/{}/{}", account_name, path.trim_start_matches('/'));

    // If there are query parameters, canonicalize them
    if uri_parts.len() > 1 {
        let query = uri_parts[1];
        let mut params = BTreeMap::new();

        for param in query.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                params.insert(key.to_lowercase(), value);
            } else {
                params.insert(param.to_lowercase(), "");
            }
        }

        for (key, value) in params {
            if !value.is_empty() {
                result.push_str(&format!("\n{}:{}", key, value));
            } else {
                result.push_str(&format!("\n{}", key));
            }
        }
    }

    result
}

// Function to validate the signature
fn verify_signature(string_to_sign: &str, provided_signature: &str, account_name: &str) -> bool {
    // For the emulator, we use the default key
    let decoded_key = base64::decode(EMULATOR_DEFAULT_ACCOUNT_KEY).unwrap_or_default();

    // Create HMAC-SHA256 instance
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&decoded_key).expect("HMAC can take key of any size");

    // Update with string to sign
    mac.update(string_to_sign.as_bytes());

    // Get the result and compare
    let computed_signature = base64::encode(mac.finalize().into_bytes());

    // Compare signatures (timing-attack safe comparison would be better)
    provided_signature == computed_signature
}

/// Gets a header value as a string, or an empty string if the header is not present.
fn get_header_string_allow_empty(headers: &HeaderMap, key: &str) -> String {
    if let Some(header) = headers.get(key) {
        if let Ok(header_value) = header.to_str() {
            return header_value.to_string();
        }
    }

    String::new()
}

fn log_request(req: &Request<axum::body::Body>, _span: &tracing::Span) {
    let method = req.method();
    let uri = req.uri();

    tracing::trace!(method = %method, uri = %uri, "Incoming request");

    for (key, value) in req.headers().iter() {
        tracing::trace!(header = %key, value = ?value, "Request header");
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .compact()
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
                .layer(TraceLayer::new_for_http().on_request(log_request))
                .layer(middleware::from_fn(default_response_headers_middleware))
                .layer(middleware::from_fn(auth_middleware)),
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
        .header("x-ms-account-kind", EMULATOR_STORAGE_ACCOUNT_KIND)
        .header("x-ms-is-hns-enabled", EMULATOR_HNS_ENABLED.to_string())
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
