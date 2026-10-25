//! Command-line entry point for the vigilant-heron proxy.

use std::path::PathBuf;

use anyhow::{Context, bail};
use tokio::signal::unix::SignalKind;
use tracing_subscriber::EnvFilter;
use vigilant_heron::{Config, LogFormat, serve};

const DEFAULT_CONFIG_PATH: &str = "/etc/vigilant-heron/config.toml";
const CONFIG_ENV: &str = "VIGILANT_HERON_CONFIG";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config_path = config_path(&args, std::env::var_os(CONFIG_ENV).map(PathBuf::from))?;
    let config =
        Config::load(&config_path).with_context(|| format!("loading {}", config_path.display()))?;
    init_tracing(config.log_format);
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    tracing::info!(listen = %config.listen, "vigilant-heron is listening");
    serve(listener, config, shutdown_signal()).await?;
    tracing::info!("vigilant-heron stopped");
    Ok(())
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

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match format {
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
        LogFormat::Pretty => tracing_subscriber::fmt()
            .pretty()
            .with_env_filter(filter)
            .init(),
    }
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
    use rstest::rstest;

    #[rstest]
    #[case::default_path(&[], None, DEFAULT_CONFIG_PATH)]
    #[case::env_overrides_default(&[], Some("/env.toml"), "/env.toml")]
    #[case::flag_overrides_env(&["--config", "/flag.toml"], Some("/env.toml"), "/flag.toml")]
    #[case::equals_form(&["--config=/eq.toml"], None, "/eq.toml")]
    fn config_path_prefers_flag_then_env_then_default(
        #[case] args: &[&str],
        #[case] env: Option<&str>,
        #[case] expected: &str,
    ) {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        let path = config_path(&args, env.map(PathBuf::from));
        assert_eq!(path.ok(), Some(PathBuf::from(expected)));
    }

    #[rstest]
    #[case::missing_value(&["--config"])]
    #[case::unknown_flag(&["--verbose"])]
    fn config_path_rejects_bad_arguments(#[case] args: &[&str]) {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        assert!(config_path(&args, None).is_err());
    }
}
