use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// Middleware that logs the incoming request and its headers.
/// This is the first middleware that is executed before any validations.
pub fn log_request(request: &Request, _span: &tracing::Span) {
    let method = request.method();
    let uri = request.uri();

    tracing::trace!(method = %method, uri = %uri, "Incoming request");

    for (key, value) in request.headers().iter() {
        tracing::trace!(header = %key, value = ?value, "Request header");
    }
}

/// Middleware that adds default response headers for every response.
pub async fn set_default_response_headers(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
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

    Ok(response)
}

/// Middleware that validates the incoming request headers.
pub async fn validate_request_headers(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers();

    let date_header = headers
        .get("x-ms-date")
        .or(headers.get("Date"))
        .ok_or({
            tracing::debug!("The x-ms-date or Date headers must be present");
            StatusCode::FORBIDDEN
        })?
        .to_str()
        .map_err(|err| {
            tracing::error!("Date header is not valid UTF-8: {}", err);
            StatusCode::FORBIDDEN
        })?;

    let utc_date: DateTime<Utc> = DateTime::parse_from_rfc2822(date_header)
        .map_err(|err| {
            tracing::error!("Error parsing date header value: {}", err);
            StatusCode::FORBIDDEN
        })?
        .to_utc();

    // Ensure the date header is no older than 15 minutes to prevent replay attacks.
    if Utc::now().signed_duration_since(utc_date) > Duration::minutes(15) {
        tracing::debug!("Date header is older than 15 mins");
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

/// Middleware that authorizes the request.
pub async fn authorize_request(request: Request, next: Next) -> Result<Response, StatusCode> {
    // TODO: we should probably check all possible auth schemes and accept if any are valid.
    // ex. if an invalid auth header is passed, but we are able to authorize with public access,
    // we should allow the request to go through.
    let headers = request.headers();

    // Get the auth header, if it is invalid or doesn't exist return a 403.
    let auth_header = headers
        .get("Authorization")
        .ok_or(StatusCode::FORBIDDEN)?
        .to_str()
        .map_err(|_| StatusCode::FORBIDDEN)?;

    // Parse the auth header to extract the authentication scheme, account name, and signature.
    // Format: "[SharedKey|SharedKeyLite] <AccountName>:<Signature>"
    let (auth_scheme, account_and_signature) = match auth_header.split_once(' ') {
        Some(parts) => parts,
        None => return Err(StatusCode::FORBIDDEN),
    };

    // Extract the account name and signature.
    let (account_name, signature) = match account_and_signature.split_once(':') {
        Some(parts) => parts,
        None => return Err(StatusCode::FORBIDDEN),
    };

    // TODO: allow case insensitive?
    match auth_scheme {
        "SharedKey" => authorize_shared_key(&request, account_name, signature).await?,
        "SharedKeyLite" => authorize_shared_key_lite(&request, account_name, signature).await?,
        _ => {
            tracing::debug!("Unsupported auth scheme: {}", auth_scheme);
            return Err(StatusCode::FORBIDDEN);
        }
    };

    Ok(next.run(request).await)
}
