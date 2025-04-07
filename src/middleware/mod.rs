use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

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
    Ok(next.run(request).await)
}
