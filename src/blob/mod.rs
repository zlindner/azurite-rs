use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{Response, StatusCode},
    routing::get,
};

use crate::emulator::EmulatorState;

pub fn router(state: EmulatorState) -> Router {
    Router::new()
        .route("/{account_name}", get(account_get))
        .with_state(state)
}

async fn account_get(
    State(_state): State<EmulatorState>,
    _request: Request,
) -> Result<Response<Body>, StatusCode> {
    Ok(Response::builder().body(Body::empty()).unwrap())
}
