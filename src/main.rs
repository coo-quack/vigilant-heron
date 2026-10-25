//! Command-line entry point for the vigilant-heron proxy.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use tokio::signal::unix::{SignalKind, signal};
use vigilant_heron::{Config, ErrorLogHandle, install_error_log, serve};

const DEFAULT_CONFIG_PATH: &str = "/etc/vigilant-heron/vigilant-heron.conf";
const CONFIG_ENV: &str = "VIGILANT_HERON_CONFIG";

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    /// The `--config` path, when one is given.
    config: Option<PathBuf>,
    /// `-t`: check the configuration and exit, without binding or serving.
    test_only: bool,
}

fn main() -> ExitCode {
    match run_cli() {
        Ok(code) => code,
        Err(error) => {
            // Errors go to stderr as nginx writes them, and the process exits with 1.
            let _ = writeln!(std::io::stderr(), "vigilant-heron: {error:?}");
            ExitCode::FAILURE
        }
    }
}

fn run_cli() -> anyhow::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = parse_args(&args)?;
    let config_path = config_path(
        options.config,
        std::env::var_os(CONFIG_ENV).map(PathBuf::from),
    );
    if options.test_only {
        return Ok(test_configuration(&config_path));
    }
    // The configuration is loaded before the runtime exists, because `worker_threads` sizes the runtime.
    let config =
        Config::load(&config_path).with_context(|| format!("loading {}", config_path.display()))?;
    let error_log = install_error_log(&config.error_log);
    let runtime = build_runtime(config.worker_threads)?;
    runtime.block_on(run(config, error_log))?;
    Ok(ExitCode::SUCCESS)
}

/// Checks the configuration as `nginx -t` does: it is read and validated, and
/// nothing is bound or started. The result is written to stderr, as nginx does.
fn test_configuration(path: &std::path::Path) -> ExitCode {
    let mut stderr = std::io::stderr();
    match Config::load(path) {
        Ok(_) => {
            let _ = writeln!(
                stderr,
                "configuration file {} test is successful",
                path.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(stderr, "vigilant-heron: {error}");
            let _ = writeln!(stderr, "configuration file {} test failed", path.display());
            ExitCode::FAILURE
        }
    }
}

/// Reads the command line: `-t`, and `--config <path>` or `--config=<path>`.
fn parse_args(args: &[String]) -> anyhow::Result<Options> {
    let mut options = Options {
        config: None,
        test_only: false,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "-t" => options.test_only = true,
            "--config" => match rest.next() {
                Some(value) => options.config = Some(PathBuf::from(value)),
                None => bail!("--config needs a path"),
            },
            other => match other.strip_prefix("--config=") {
                Some(value) => options.config = Some(PathBuf::from(value)),
                None => bail!("unknown argument: {other}"),
            },
        }
    }
    Ok(options)
}

/// Chooses the config path: `--config` wins, then the environment, then the default.
fn config_path(flag: Option<PathBuf>, from_env: Option<PathBuf>) -> PathBuf {
    flag.or(from_env)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
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

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn config_path_prefers_flag_then_env_then_default() {
        let flag = config_path(Some("/flag.conf".into()), Some("/env.conf".into()));
        assert_eq!(flag, PathBuf::from("/flag.conf"));
        let env = config_path(None, Some("/env.conf".into()));
        assert_eq!(env, PathBuf::from("/env.conf"));
        let default = config_path(None, None);
        assert_eq!(default, PathBuf::from(DEFAULT_CONFIG_PATH));
    }

    #[test]
    fn the_config_flag_takes_a_separate_value_or_an_equals_sign() -> anyhow::Result<()> {
        let separate = parse_args(&args(&["--config", "/a.conf"]))?;
        assert_eq!(separate.config, Some(PathBuf::from("/a.conf")));
        let equals = parse_args(&args(&["--config=/b.conf"]))?;
        assert_eq!(equals.config, Some(PathBuf::from("/b.conf")));
        Ok(())
    }

    #[test]
    fn t_selects_the_test_mode_in_any_order() -> anyhow::Result<()> {
        let first = parse_args(&args(&["-t", "--config", "/c.conf"]))?;
        assert!(first.test_only);
        assert_eq!(first.config, Some(PathBuf::from("/c.conf")));
        let last = parse_args(&args(&["--config=/c.conf", "-t"]))?;
        assert!(last.test_only);
        assert!(!parse_args(&[])?.test_only);
        Ok(())
    }

    #[test]
    fn bad_arguments_are_rejected() {
        assert!(parse_args(&args(&["--config"])).is_err());
        assert!(parse_args(&args(&["--verbose"])).is_err());
    }
}
