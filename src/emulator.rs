use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use crate::{blob, config::Config, queue, table};

/// The core emulator state struct that is passed to all handlers.
#[derive(Clone)]
pub struct EmulatorState {
    config: Arc<Config>,
}

/// Starts the emulator.
pub async fn start(config: Config) -> anyhow::Result<()> {
    let state = EmulatorState {
        config: Arc::new(config),
    };

    let blob_task = tokio::spawn(start_blob_server(state.clone()));
    let queue_task = tokio::spawn(start_queue_server(state.clone()));
    let table_task = tokio::spawn(start_table_server(state.clone()));

    let _ = tokio::join!(blob_task, queue_task, table_task);

    Ok(())
}

/// Starts the blob http server.
async fn start_blob_server(state: EmulatorState) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", state.config.blob_server_port);
    let listener = TcpListener::bind(&addr)
        .await
        .context("error binding to blob server port")?;

    let app = blob::router(state).layer(
        ServiceBuilder::new()
            // Enables logging of http requests and responses.
            .layer(TraceLayer::new_for_http()),
    );

    tracing::info!("Blob server running @ {}", addr);

    axum::serve(listener, app)
        .await
        .context("error starting blob server")?;

    Ok(())
}

/// Starts the queue http server.
async fn start_queue_server(state: EmulatorState) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", state.config.queue_server_port);
    let listener = TcpListener::bind(&addr)
        .await
        .context("error binding to queue server port")?;

    let app = queue::router(state).layer(
        ServiceBuilder::new()
            // Enables logging of http requests and responses.
            .layer(TraceLayer::new_for_http()),
    );

    tracing::info!("Queue server running @ {}", addr);

    axum::serve(listener, app)
        .await
        .context("error starting queue server")?;

    Ok(())
}

/// Starts the table http server.
async fn start_table_server(state: EmulatorState) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", state.config.table_server_port);
    let listener = TcpListener::bind(&addr)
        .await
        .context("error binding to table server port")?;

    let app = table::router(state).layer(
        ServiceBuilder::new()
            // Enables logging of http requests and responses.
            .layer(TraceLayer::new_for_http()),
    );

    tracing::info!("Table server running @ {}", addr);

    axum::serve(listener, app)
        .await
        .context("error starting table server")?;

    Ok(())
}
