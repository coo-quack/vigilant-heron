//! Command-line entry point for the vigilant-heron proxy.

use std::path::PathBuf;

use anyhow::{Context, bail};
use tokio::signal::unix::{SignalKind, signal};
use vigilant_heron::{Config, ErrorLogHandle, install_error_log, serve};

const DEFAULT_CONFIG_PATH: &str = "/etc/vigilant-heron/vigilant-heron.conf";
const CONFIG_ENV: &str = "VIGILANT_HERON_CONFIG";

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config_path = config_path(&args, std::env::var_os(CONFIG_ENV).map(PathBuf::from))?;
    // The configuration is loaded before the runtime exists, because `worker_threads` sizes the runtime.
    let config =
        Config::load(&config_path).with_context(|| format!("loading {}", config_path.display()))?;
    let error_log = install_error_log(&config.error_log);
    let runtime = build_runtime(config.worker_threads)?;
    runtime.block_on(run(config, error_log))
}

/// Chooses the config path: `--config` wins, then the environment, then the default.
fn config_path(args: &[String], from_env: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match args {
        [] => Ok(from_env.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))),
        [flag, value] if flag.as_str() == "--config" => Ok(PathBuf::from(value)),
        [flag] if flag.as_str() == "--config" => bail!("--config needs a path"),
        [single] => match single.strip_prefix("--config=") {
            Some(value) => Ok(PathBuf::from(value)),
            None => bail!("unknown argument: {single}"),
        },
        [other, ..] => bail!("unknown argument: {other}"),
    }
}

/// Builds the multi-thread runtime. Without `worker_threads`, tokio uses one worker per CPU core.
fn build_runtime(worker_threads: Option<usize>) -> anyhow::Result<tokio::runtime::Runtime> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if let Some(threads) = worker_threads {
        builder.worker_threads(threads);
    }
    builder
        .enable_all()
        .build()
        .context("starting the async runtime")
}

async fn run(config: Config, error_log: ErrorLogHandle) -> anyhow::Result<()> {
    // Reopen the error log on SIGUSR1, so logrotate can move the file away.
    match signal(SignalKind::user_defined1()) {
        Ok(mut usr1) => {
            tokio::spawn(async move {
                while usr1.recv().await.is_some() {
                    error_log.reopen();
                }
            });
        }
        Err(error) => {
            tracing::warn!(%error, "cannot listen for SIGUSR1; the error log cannot be reopened");
        }
    }
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    tracing::info!(listen = %config.listen, "vigilant-heron is listening");
    serve(listener, config, shutdown_signal()).await?;
    tracing::info!("vigilant-heron stopped");
    Ok(())
}

/// Resolves when SIGINT or SIGTERM arrives.
async fn shutdown_signal() {
    let interrupt = async {
        // A failed signal registration leaves the server running until SIGTERM.
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                tracing::warn!(%error, "cannot listen for SIGTERM; only SIGINT stops the server");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_path_prefers_flag_then_env_then_default() -> anyhow::Result<()> {
        let flag = config_path(
            &["--config".into(), "/flag.conf".into()],
            Some("/env.conf".into()),
        )?;
        assert_eq!(flag, PathBuf::from("/flag.conf"));
        let env = config_path(&[], Some("/env.conf".into()))?;
        assert_eq!(env, PathBuf::from("/env.conf"));
        let default = config_path(&[], None)?;
        assert_eq!(default, PathBuf::from(DEFAULT_CONFIG_PATH));
        let equals = config_path(&["--config=/eq.conf".into()], None)?;
        assert_eq!(equals, PathBuf::from("/eq.conf"));
        Ok(())
    }

    #[test]
    fn config_path_rejects_bad_arguments() {
        assert!(config_path(&["--config".into()], None).is_err());
        assert!(config_path(&["--verbose".into()], None).is_err());
    }
}
