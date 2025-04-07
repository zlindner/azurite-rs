use axum::Router;

use crate::emulator::EmulatorState;

pub fn router(state: EmulatorState) -> Router {
    Router::new().with_state(state)
}
