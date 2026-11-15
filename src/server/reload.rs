//! The settings a reload cannot change, and the reload itself.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::config::{Config, ConnectionConfig};
use crate::error::ConfigError;

use super::state::AppState;

/// The settings that a reload cannot change. A reload that changes one logs a warning.
pub(crate) struct Startup {
    pid_file: std::path::PathBuf,
    listen: String,
    worker_threads: Option<usize>,
    max_connections: usize,
    worker_shutdown_timeout: Option<Duration>,
    connection: ConnectionConfig,
}

impl Startup {
    pub(crate) fn of(config: &Config) -> Self {
        Self {
            pid_file: config.pid_file.clone(),
            listen: config.listen.clone(),
            worker_threads: config.worker_threads,
            max_connections: config.max_connections,
            worker_shutdown_timeout: config.worker_shutdown_timeout,
            connection: config.connection.clone(),
        }
    }

    /// Warns about each setting of `config` that differs from the startup value.
    fn report_changes(&self, config: &Config) {
        if config.pid_file != self.pid_file {
            tracing::warn!(path = %config.pid_file.display(), "pid changed; a restart is needed for it to take effect");
        }
        if config.listen != self.listen {
            tracing::warn!(listen = %config.listen, "listen changed; a restart is needed for it to take effect");
        }
        if config.worker_threads != self.worker_threads {
            tracing::warn!("worker_threads changed; a restart is needed for it to take effect");
        }
        if config.max_connections != self.max_connections {
            tracing::warn!("max_connections changed; a restart is needed for it to take effect");
        }
        if config.worker_shutdown_timeout != self.worker_shutdown_timeout {
            tracing::warn!(
                "worker_shutdown_timeout changed; a restart is needed for it to take effect"
            );
        }
        if config.connection != self.connection {
            tracing::warn!(
                "connection timers and header limits changed; a restart is needed for them to take effect"
            );
        }
    }
}

/// Waits for the next reload request. Without a reload source it never completes,
/// and a closed source ends the wait for good.
pub(crate) async fn next_reload(requests: &mut Option<mpsc::Receiver<()>>) -> Option<()> {
    match requests {
        Some(requests) => requests.recv().await,
        None => std::future::pending().await,
    }
}

/// Builds the state of a new configuration and publishes it to new requests. A
/// failure is logged and leaves the current state in place.
pub(crate) fn reload(
    load: &dyn Fn() -> Result<Config, ConfigError>,
    applied: &dyn Fn(&Config),
    startup: &Startup,
    current: &watch::Sender<Arc<AppState>>,
) {
    let config = match load() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(%error, "configuration reload failed; keeping the previous configuration");
            return;
        }
    };
    startup.report_changes(&config);
    let previous = current.borrow().clone();
    match AppState::from_config(config.clone(), Some(previous.as_ref())) {
        Ok(state) => {
            current.send_replace(Arc::new(state));
            applied(&config);
            tracing::info!("configuration reloaded");
        }
        Err(error) => {
            tracing::error!(%error, "configuration reload failed; keeping the previous configuration");
        }
    }
}
