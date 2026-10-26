//! The command line: option parsing, the usage text, and `-s` signals to a running router.
//!
//! Options are read by hand, as nginx reads its own. `-s` sends a signal through
//! `rustix`, which is already in the dependency tree and makes the call without
//! `unsafe` code and without running a `kill` binary, which the distroless image lacks.

use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::{Context, anyhow, bail};
use rustix::io::Errno;
use rustix::process::{Pid, Signal, kill_process};

use crate::pidfile;

/// What `-s` asks the running router to do, as nginx's `-s` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalCommand {
    /// `reload`: re-read the configuration (SIGHUP).
    Reload,
    /// `reopen`: reopen the log files (SIGUSR1).
    Reopen,
    /// `stop`: shut down, graceful in this version (SIGTERM).
    Stop,
    /// `quit`: shut down gracefully (SIGQUIT).
    Quit,
}

impl SignalCommand {
    /// Reads the word after `-s`.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text {
            "reload" => Some(Self::Reload),
            "reopen" => Some(Self::Reopen),
            "stop" => Some(Self::Stop),
            "quit" => Some(Self::Quit),
            _ => None,
        }
    }

    /// The Unix signal this command sends.
    pub(crate) fn signal(self) -> Signal {
        match self {
            Self::Reload => Signal::HUP,
            Self::Reopen => Signal::USR1,
            Self::Stop => Signal::TERM,
            Self::Quit => Signal::QUIT,
        }
    }
}

/// The one action a command line asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    /// No action option: run the router.
    Serve,
    /// `-t` (and `-T` with `dump`): check the configuration and exit.
    Test {
        /// `-T`: print the configuration with its includes expanded.
        dump: bool,
    },
    /// `-s`: signal the running router.
    Signal(SignalCommand),
    /// `start`: check the configuration, then run the router in the background.
    Start,
    /// `stop`: stop the background router gracefully and wait for it to exit.
    Stop,
    /// `restart`: check the configuration, stop the background router, then start it.
    Restart,
    /// `-h`, `--help`.
    Help,
    /// `-v`, `--version`.
    Version,
}

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Options {
    /// The `-c` or `--config` path, when one is given.
    pub(crate) config: Option<PathBuf>,
    /// The action.
    pub(crate) command: Command,
}

/// The usage text, printed for `-h` and after a bad command line.
pub(crate) const USAGE: &str = "\
Usage: vigilant-heron [-h] [-v] [-t] [-T] [-c <path>] [-s <signal>]
       vigilant-heron start|stop|restart [-c <path>]

Options:
  -h, --help            show this help and exit
  -v, --version         show the version and exit
  -c, --config <path>   configuration file (also --config=<path>); default
                        $VIGILANT_HERON_CONFIG, then /etc/vigilant-heron/vigilant-heron.conf
  -t                    check the configuration and exit
  -T                    check the configuration, print it with includes expanded, and exit
  -s <signal>           signal the running router: reload, reopen, stop or quit
                        (the pid comes from the `pid` directive)
  start                 run the router in the background (checks the file first)
  stop                  stop the background router and wait for it to exit
  restart               stop, then start, after checking the file
                        use -s reload for configuration changes: it keeps connections
";

/// Reads the command line. The first error is returned as text for the usage message.
pub(crate) fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut help = false;
    let mut version = false;
    let mut test = false;
    let mut dump = false;
    let mut signal: Option<SignalCommand> = None;
    let mut lifecycle: Option<&str> = None;
    let mut config = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "start" | "stop" | "restart" => {
                if lifecycle.is_some() {
                    return Err("give only one of start, stop and restart".to_owned());
                }
                lifecycle = Some(arg.as_str());
            }
            "-h" | "--help" => help = true,
            "-v" | "--version" => version = true,
            "-t" => test = true,
            "-T" => {
                test = true;
                dump = true;
            }
            "-c" | "--config" => config = Some(path_value(arg, rest.next())?),
            "-s" => {
                if signal.is_some() {
                    return Err("-s is given more than once".to_owned());
                }
                let word = rest.next().ok_or("-s needs a signal")?;
                let parsed = SignalCommand::parse(word).ok_or_else(|| {
                    format!("invalid signal \"{word}\": use reload, reopen, stop or quit")
                })?;
                signal = Some(parsed);
            }
            other => match other.strip_prefix("--config=") {
                Some(value) => config = Some(path_value("--config", Some(&value.to_owned()))?),
                None => return Err(format!("unknown option \"{other}\"")),
            },
        }
    }
    let command = if help {
        Command::Help
    } else if version {
        Command::Version
    } else if let Some(word) = lifecycle {
        if test {
            return Err(format!("{word} cannot be combined with -t or -T"));
        }
        if signal.is_some() {
            return Err(format!("{word} cannot be combined with -s"));
        }
        match word {
            "start" => Command::Start,
            "stop" => Command::Stop,
            _ => Command::Restart,
        }
    } else if let Some(command) = signal {
        if test {
            return Err("-s cannot be combined with -t or -T".to_owned());
        }
        Command::Signal(command)
    } else if test {
        Command::Test { dump }
    } else {
        Command::Serve
    };
    Ok(Options { config, command })
}

/// Reads the value of an option that takes a path.
fn path_value(option: &str, value: Option<&String>) -> Result<PathBuf, String> {
    match value {
        Some(path) if !path.is_empty() => Ok(PathBuf::from(path)),
        _ => Err(format!("{option} needs a path")),
    }
}

/// Chooses the config path: `--config` wins, then the environment, then the default.
pub(crate) fn config_path(flag: Option<PathBuf>, from_env: Option<PathBuf>) -> PathBuf {
    flag.or(from_env)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

/// The configuration file read when no `-c` or environment variable names one.
pub(crate) const DEFAULT_CONFIG_PATH: &str = "/etc/vigilant-heron/vigilant-heron.conf";

/// Sends `command` to the router whose pid is in the file named by its `pid` directive.
///
/// # Errors
///
/// Returns an error when the configuration cannot be read, the pid file is missing
/// or does not hold a process id, no router holds the pid file's lock (a stale pid file,
/// in which case nothing is signalled), or no process has that id.
pub(crate) fn send_signal(
    config_path: &std::path::Path,
    command: SignalCommand,
) -> anyhow::Result<()> {
    let pid_path = vigilant_heron::process_settings(config_path)
        .with_context(|| format!("loading {}", config_path.display()))?
        .pid_file;
    // The file is checked by `pidfile::read_pid`, which refuses one that another user
    // owns in a shared directory, so the signal never goes to a pid it did not trust.
    let raw = pidfile::read_pid(&pid_path).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            anyhow!(
                "cannot read the pid file {}; is the router running with this configuration?",
                pid_path.display()
            )
        } else {
            anyhow!("the pid file {}: {error}", pid_path.display())
        }
    })?;
    // A router holds the lock of the pid file for its whole life. Without the lock the pid
    // may belong to an unrelated process that reused it, so nothing is signalled.
    let locked = pidfile::lock_held(&pid_path)
        .map_err(|error| anyhow!("the lock of the pid file {}: {error}", pid_path.display()))?;
    if !locked {
        bail!(
            "the pid file {} is stale: no router holds its lock, so no signal was sent (process {raw} may be unrelated); delete the file if no router runs",
            pid_path.display()
        );
    }
    let pid = Pid::from_raw(raw).ok_or_else(|| anyhow!("invalid process id {raw}"))?;
    match kill_process(pid, command.signal()) {
        Ok(()) => Ok(()),
        Err(Errno::SRCH) => bail!(
            "no process {raw} is running: the pid file {} is stale",
            pid_path.display()
        ),
        Err(error) => Err(anyhow!("sending the signal to process {raw}: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| (*item).to_owned()).collect()
    }

    #[rstest]
    #[case::no_arguments(&[], Options { config: None, command: Command::Serve })]
    #[case::help_short(&["-h"], Options { config: None, command: Command::Help })]
    #[case::help_long(&["--help"], Options { config: None, command: Command::Help })]
    #[case::version_short(&["-v"], Options { config: None, command: Command::Version })]
    #[case::version_long(&["--version"], Options { config: None, command: Command::Version })]
    #[case::config_short(&["-c", "/a.conf"], Options { config: Some(PathBuf::from("/a.conf")), command: Command::Serve })]
    #[case::config_long(&["--config", "/a.conf"], Options { config: Some(PathBuf::from("/a.conf")), command: Command::Serve })]
    #[case::config_equals(&["--config=/a.conf"], Options { config: Some(PathBuf::from("/a.conf")), command: Command::Serve })]
    #[case::test(&["-t"], Options { config: None, command: Command::Test { dump: false } })]
    #[case::test_with_config(&["-t", "-c", "/a.conf"], Options { config: Some(PathBuf::from("/a.conf")), command: Command::Test { dump: false } })]
    #[case::dump(&["-T"], Options { config: None, command: Command::Test { dump: true } })]
    #[case::dump_and_test(&["-t", "-T"], Options { config: None, command: Command::Test { dump: true } })]
    #[case::dump_with_config(&["-c", "/a.conf", "-T"], Options { config: Some(PathBuf::from("/a.conf")), command: Command::Test { dump: true } })]
    #[case::signal_reload(&["-s", "reload"], Options { config: None, command: Command::Signal(SignalCommand::Reload) })]
    #[case::signal_reopen(&["-s", "reopen"], Options { config: None, command: Command::Signal(SignalCommand::Reopen) })]
    #[case::signal_stop(&["-s", "stop"], Options { config: None, command: Command::Signal(SignalCommand::Stop) })]
    #[case::signal_quit(&["-s", "quit"], Options { config: None, command: Command::Signal(SignalCommand::Quit) })]
    #[case::signal_with_config(&["-c", "/a.conf", "-s", "reload"], Options { config: Some(PathBuf::from("/a.conf")), command: Command::Signal(SignalCommand::Reload) })]
    #[case::start_plain(&["start"], Options { config: None, command: Command::Start })]
    #[case::start_with_config(&["start", "-c", "/a.conf"], Options { config: Some(PathBuf::from("/a.conf")), command: Command::Start })]
    #[case::config_before_start(&["-c", "/a.conf", "start"], Options { config: Some(PathBuf::from("/a.conf")), command: Command::Start })]
    #[case::stop_with_config_equals(&["stop", "--config=/a.conf"], Options { config: Some(PathBuf::from("/a.conf")), command: Command::Stop })]
    #[case::restart_with_config(&["restart", "-c", "/a.conf"], Options { config: Some(PathBuf::from("/a.conf")), command: Command::Restart })]
    #[case::help_wins_over_start(&["start", "-h"], Options { config: None, command: Command::Help })]
    #[case::help_wins_over_version(&["-v", "-h"], Options { config: None, command: Command::Help })]
    #[case::help_wins_over_test(&["-t", "-h"], Options { config: None, command: Command::Help })]
    #[case::version_wins_over_signal(&["-s", "stop", "-v"], Options { config: None, command: Command::Version })]
    fn a_valid_command_line_parses(#[case] input: &[&str], #[case] expected: Options) {
        assert_eq!(parse_args(&args(input)), Ok(expected));
    }

    #[rstest]
    #[case::unknown_option(&["--verbose"], "unknown option \"--verbose\"")]
    #[case::unknown_short(&["-x"], "unknown option \"-x\"")]
    #[case::config_without_path(&["-c"], "-c needs a path")]
    #[case::config_long_without_path(&["--config"], "--config needs a path")]
    #[case::config_empty_path(&["-c", ""], "-c needs a path")]
    #[case::config_equals_empty(&["--config="], "--config needs a path")]
    #[case::signal_without_word(&["-s"], "-s needs a signal")]
    #[case::signal_unknown_word(&["-s", "kill"], "invalid signal \"kill\": use reload, reopen, stop or quit")]
    #[case::signal_twice(&["-s", "reload", "-s", "stop"], "-s is given more than once")]
    #[case::signal_with_test(&["-s", "reload", "-t"], "-s cannot be combined with -t or -T")]
    #[case::signal_with_dump(&["-T", "-s", "stop"], "-s cannot be combined with -t or -T")]
    #[case::start_with_test(&["start", "-t"], "start cannot be combined with -t or -T")]
    #[case::stop_with_dump(&["stop", "-T"], "stop cannot be combined with -t or -T")]
    #[case::restart_with_signal(&["restart", "-s", "reload"], "restart cannot be combined with -s")]
    #[case::start_with_stop(&["start", "stop"], "give only one of start, stop and restart")]
    #[case::restart_twice(&["restart", "restart"], "give only one of start, stop and restart")]
    fn a_bad_command_line_is_rejected(#[case] input: &[&str], #[case] message: &str) {
        assert_eq!(parse_args(&args(input)), Err(message.to_owned()));
    }

    #[test]
    fn the_config_flag_wins_over_the_environment_which_wins_over_the_default() {
        let flag = config_path(Some("/flag.conf".into()), Some("/env.conf".into()));
        assert_eq!(flag, PathBuf::from("/flag.conf"));
        let env = config_path(None, Some("/env.conf".into()));
        assert_eq!(env, PathBuf::from("/env.conf"));
        assert_eq!(config_path(None, None), PathBuf::from(DEFAULT_CONFIG_PATH));
    }

    #[rstest]
    #[case("reload", SignalCommand::Reload, Signal::HUP)]
    #[case("reopen", SignalCommand::Reopen, Signal::USR1)]
    #[case("stop", SignalCommand::Stop, Signal::TERM)]
    #[case("quit", SignalCommand::Quit, Signal::QUIT)]
    fn each_signal_word_maps_to_its_signal(
        #[case] word: &str,
        #[case] command: SignalCommand,
        #[case] signal: Signal,
    ) {
        assert_eq!(SignalCommand::parse(word), Some(command));
        assert_eq!(command.signal(), signal);
    }

    #[test]
    fn the_usage_text_lists_every_option() {
        for option in ["-h", "-v", "-c", "-t", "-T", "-s"] {
            assert!(USAGE.contains(option), "usage does not mention {option}");
        }
        for long in ["--help", "--version", "--config"] {
            assert!(USAGE.contains(long), "usage does not mention {long}");
        }
    }
}
