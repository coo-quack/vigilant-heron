//! Command-line entry point for the vigilant-heron proxy.

mod cli;
mod lifecycle;
mod pidfile;

use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use cli::{Command, Options, USAGE, config_path, parse_args, send_signal};
use pidfile::PidFile;
use tokio::signal::unix::{SignalKind, signal};
use vigilant_heron::{Config, ErrorLogHandle, install_error_log, serve_reloadable};

const CONFIG_ENV: &str = "VIGILANT_HERON_CONFIG";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match parse_args(&args) {
        Ok(options) => options,
        Err(message) => {
            // A bad command line prints the reason and the usage to stderr, and exits with 1.
            let mut stderr = std::io::stderr();
            let _ = writeln!(stderr, "vigilant-heron: {message}");
            let _ = write!(stderr, "{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    match run_cli(options) {
        Ok(code) => code,
        Err(error) => {
            // Errors go to stderr as nginx writes them, and the process exits with 1.
            let _ = writeln!(std::io::stderr(), "vigilant-heron: {error:?}");
            ExitCode::FAILURE
        }
    }
}

fn run_cli(options: Options) -> anyhow::Result<ExitCode> {
    let Options { config, command } = options;
    match command {
        Command::Help => {
            let _ = write!(std::io::stdout(), "{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Version => {
            let _ = writeln!(
                std::io::stdout(),
                "vigilant-heron version {}",
                env!("CARGO_PKG_VERSION")
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Signal(signal) => {
            send_signal(&resolve_config(config), signal)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Test { dump } => Ok(test_configuration(&resolve_config(config), dump)),
        Command::Start => lifecycle::start(&resolve_config(config)),
        Command::Stop => lifecycle::stop(&resolve_config(config)),
        Command::Restart => lifecycle::restart(&resolve_config(config)),
        Command::Serve => {
            let config_path = resolve_config(config);
            // The configuration is loaded before the runtime exists, because `worker_threads` sizes the runtime.
            let loaded = Config::load(&config_path)
                .with_context(|| format!("loading {}", config_path.display()))?;
            let error_log = install_error_log(&loaded.error_log)?;
            let runtime = build_runtime(loaded.worker_threads)?;
            runtime.block_on(run(loaded, error_log, config_path))?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// The configuration path from `-c`, the environment, or the default.
fn resolve_config(flag: Option<PathBuf>) -> PathBuf {
    config_path(flag, std::env::var_os(CONFIG_ENV).map(PathBuf::from))
}

/// Checks the configuration as `nginx -t` does: it is read and validated, and
/// nothing is bound or started. The result is written to stderr, as nginx does.
/// With `dump` (`-T`), a valid configuration is then printed to stdout, with its
/// includes expanded.
fn test_configuration(path: &Path, dump: bool) -> ExitCode {
    let mut stderr = std::io::stderr();
    if let Err(error) = Config::load(path) {
        let _ = writeln!(stderr, "vigilant-heron: {error}");
        let _ = writeln!(stderr, "configuration file {} test failed", path.display());
        return ExitCode::FAILURE;
    }
    let _ = writeln!(
        stderr,
        "configuration file {} test is successful",
        path.display()
    );
    if !dump {
        return ExitCode::SUCCESS;
    }
    match vigilant_heron::dump_configuration(path) {
        Ok(text) => {
            let mut stdout = std::io::stdout();
            if stdout
                .write_all(text.as_bytes())
                .and_then(|()| stdout.flush())
                .is_err()
            {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(stderr, "vigilant-heron: {error}");
            ExitCode::FAILURE
        }
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

async fn run(
    config: Config,
    error_log: ErrorLogHandle,
    config_path: PathBuf,
) -> anyhow::Result<()> {
    // SIGHUP reloads the configuration, as `nginx -s reload` does. The reload
    // opens the error log destination of the new file, so it also reopens the file.
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel::<()>(1);
    match signal(SignalKind::hangup()) {
        Ok(mut hangup) => {
            tokio::spawn(async move {
                while hangup.recv().await.is_some() {
                    // A reload already waiting covers this signal too.
                    let _ = reload_tx.try_send(());
                }
            });
        }
        Err(error) => {
            tracing::warn!(%error, "cannot listen for SIGHUP; the configuration cannot be reloaded");
        }
    }
    // Reopen the error log on SIGUSR1, so logrotate can move the file away.
    match signal(SignalKind::user_defined1()) {
        Ok(mut usr1) => {
            let error_log = error_log.clone();
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
    // Registered before the listener is bound, so a stop sent once the pid file exists is handled.
    let shutdown = shutdown_signal();
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    // The PID file is written once the listener is bound, so its presence means the router
    // accepts connections. A failure to write it is logged and the router still runs, so an
    // existing deployment whose directory is not writable keeps working; `-s` then reports the
    // missing file.
    let _pid_file = match PidFile::create(&config.pid_file) {
        Ok(file) => Some(file),
        Err(error) => {
            tracing::warn!(
                %error,
                path = %config.pid_file.display(),
                "cannot write the pid file; `-s` will not find this process"
            );
            None
        }
    };
    tracing::info!(listen = %config.listen, "vigilant-heron is listening");
    // A reload stages the new error log destination before the configuration is
    // put into service, and the staged destination is committed only after that.
    let staging = error_log.clone();
    let committing = error_log;
    serve_reloadable(
        listener,
        config,
        shutdown,
        reload_rx,
        move || {
            let config = Config::load(&config_path)?;
            staging.stage(&config.error_log)?;
            Ok(config)
        },
        move |_| committing.commit(),
    )
    .await?;
    tracing::info!("vigilant-heron stopped");
    Ok(())
}

/// Registers the signals that stop the router, and returns the future that resolves on
/// the first of them. Registration happens here, before the pid file is written: a
/// signal that arrives before the handlers exist would end the process without the
/// cleanup that removes the pid file.
///
/// SIGINT, SIGTERM and SIGQUIT all shut down gracefully in this version.
fn shutdown_signal() -> impl Future<Output = ()> {
    let interrupt = signal(SignalKind::interrupt());
    let terminate = signal(SignalKind::terminate());
    let quit = signal(SignalKind::quit());
    async move {
        tokio::select! {
            () = wait_for(interrupt, "SIGINT") => {}
            () = wait_for(terminate, "SIGTERM") => {}
            () = wait_for(quit, "SIGQUIT") => {}
        }
    }
}

/// Resolves when the registered signal arrives. A failed registration never resolves, so the
/// other signals still stop the router.
async fn wait_for(registered: std::io::Result<tokio::signal::unix::Signal>, name: &str) {
    match registered {
        Ok(mut stream) => {
            stream.recv().await;
        }
        Err(error) => {
            tracing::warn!(%error, signal = name, "cannot listen for this signal");
            std::future::pending::<()>().await;
        }
    }
}
