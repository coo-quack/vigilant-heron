//! The command line: option parsing, the usage text, and `-s` signals to a running router.
//!
//! Options are read by hand, as nginx reads its own. `-s` sends a signal through
//! `rustix`, which is already in the dependency tree and makes the call without
//! `unsafe` code and without running a `kill` binary, which the distroless image lacks.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use anyhow::{Context, anyhow, bail};
use rustix::io::Errno;
use rustix::process::{Pid, Signal, kill_process};

use vigilant_heron::SuggestOptions;

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
///
/// Not `Eq`: the suggestion thresholds are scores, which are floating-point numbers.
#[derive(Debug, Clone, PartialEq)]
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
    /// `test-request <file>`: screen one sample request and print the report, without calling the backend.
    TestRequest {
        /// The raw request file, or `-` for standard input.
        file: PathBuf,
        /// The client address the access list sees.
        client: IpAddr,
    },
    /// `suggest-skip-rules <file>`: suggest skip rules from a `json` access log and print them.
    /// Nothing is applied, and the configuration is not read.
    SuggestSkipRules {
        /// The access log, or `-` for standard input.
        file: PathBuf,
        /// The site filter and the learning thresholds.
        options: SuggestOptions,
    },
    /// `-h`, `--help`.
    Help,
    /// `-v`, `--version`.
    Version,
}

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq)]
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
       vigilant-heron test-request <file> [-c <path>] [--client <address>]
       vigilant-heron suggest-skip-rules <file> [--site <name>] [--min-judged <n>] [--min-clients <n>]
                             [--min-days <n>] [--max-attack <x>] [--max-ai-instruction <x>]

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
  test-request <file>   report what the router would do with a raw HTTP/1.1 request
                        in <file> (- reads stdin), without calling the decision backend
  --client <address>    client address for the access list with test-request
                        (default 127.0.0.1; real_ip settings are not applied)
  suggest-skip-rules <file>
                        suggest skip rules from a json access log (- reads stdin);
                        prints them for review and never reads the configuration
  --site <name>         suggest-skip-rules: keep only the groups of this site
  --min-judged <n>      suggest-skip-rules: judged requests a shape needs (default 50)
  --min-clients <n>     suggest-skip-rules: distinct clients needed (default 10)
  --min-days <n>        suggest-skip-rules: distinct UTC days needed (default 3)
  --max-attack <x>      suggest-skip-rules: highest attack score allowed, 0 to 1 (default 0.3)
  --max-ai-instruction <x>
                        suggest-skip-rules: highest ai_instruction score allowed,
                        0 to 1 (default 0.3)
";

/// The options of `suggest-skip-rules`, with their names as the command line writes them.
const SUGGEST_FLAGS: [&str; 6] = [
    "--site",
    "--min-judged",
    "--min-clients",
    "--min-days",
    "--max-attack",
    "--max-ai-instruction",
];

/// The words and options of a command line, read before the action is chosen.
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one command-line word, and the action is chosen from them together"
)]
struct Words<'a> {
    help: bool,
    version: bool,
    test: bool,
    dump: bool,
    request_check: bool,
    suggest: bool,
    signal: Option<SignalCommand>,
    lifecycle: Option<&'a str>,
    config: Option<PathBuf>,
    client: Option<IpAddr>,
    /// Bare arguments: the request file of test-request or suggest-skip-rules. Any other use is an error.
    operands: Vec<&'a str>,
    /// The `suggest-skip-rules` options, as written, with the value of each.
    suggest_values: Vec<(&'a str, String)>,
}

/// Reads the command line. The first error is returned as text for the usage message.
pub(crate) fn parse_args(args: &[String]) -> Result<Options, String> {
    choose_command(read_words(args)?)
}

/// Reads every word and option of the command line, without choosing the action.
fn read_words(args: &[String]) -> Result<Words<'_>, String> {
    let mut words = Words::default();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "start" | "stop" | "restart" => {
                if words.lifecycle.is_some() {
                    return Err("give only one of start, stop and restart".to_owned());
                }
                words.lifecycle = Some(arg.as_str());
            }
            "test-request" => {
                if words.request_check {
                    return Err("test-request is given more than once".to_owned());
                }
                words.request_check = true;
            }
            "suggest-skip-rules" => {
                if words.suggest {
                    return Err("suggest-skip-rules is given more than once".to_owned());
                }
                words.suggest = true;
            }
            "-h" | "--help" => words.help = true,
            "-v" | "--version" => words.version = true,
            "-t" => words.test = true,
            "-T" => {
                words.test = true;
                words.dump = true;
            }
            "-c" | "--config" => words.config = Some(path_value(arg, rest.next())?),
            "--client" => words.client = Some(address_value(arg, rest.next())?),
            "-s" => {
                if words.signal.is_some() {
                    return Err("-s is given more than once".to_owned());
                }
                let word = rest.next().ok_or("-s needs a signal")?;
                let parsed = SignalCommand::parse(word).ok_or_else(|| {
                    format!("invalid signal \"{word}\": use reload, reopen, stop or quit")
                })?;
                words.signal = Some(parsed);
            }
            flag if SUGGEST_FLAGS.contains(&flag) => {
                let value = rest.next().ok_or_else(|| format!("{flag} needs a value"))?;
                words.suggest_values.push((flag, value.clone()));
            }
            "-" => words.operands.push("-"),
            other => match (
                other.strip_prefix("--config="),
                other.strip_prefix("--client="),
                suggest_flag_value(other),
            ) {
                (Some(value), _, _) => {
                    words.config = Some(path_value("--config", Some(&value.to_owned()))?);
                }
                (_, Some(value), _) => {
                    words.client = Some(address_value("--client", Some(&value.to_owned()))?);
                }
                (_, _, Some((flag, value))) => words.suggest_values.push((flag, value.to_owned())),
                _ if other.starts_with('-') => return Err(format!("unknown option \"{other}\"")),
                _ => words.operands.push(other),
            },
        }
    }
    Ok(words)
}

/// Checks how the words combine, then chooses the one action.
fn choose_command(words: Words<'_>) -> Result<Options, String> {
    let Words {
        help,
        version,
        test,
        dump,
        request_check,
        suggest,
        signal,
        lifecycle,
        config,
        client,
        operands,
        suggest_values,
    } = words;
    if !help && !version && !request_check {
        if !suggest && let Some(operand) = operands.first() {
            return Err(format!("unknown option \"{operand}\""));
        }
        if client.is_some() {
            return Err("--client can only be used with test-request".to_owned());
        }
    }
    if !help
        && !version
        && !suggest
        && let Some((flag, _)) = suggest_values.first()
    {
        return Err(format!("{flag} can only be used with suggest-skip-rules"));
    }
    if request_check && suggest {
        return Err("suggest-skip-rules cannot be combined with test-request".to_owned());
    }
    let command = if help {
        Command::Help
    } else if version {
        Command::Version
    } else if request_check {
        test_request_command(&operands, client, lifecycle, test, signal.is_some())?
    } else if suggest {
        suggest_command(
            &operands,
            config.is_some(),
            lifecycle,
            test,
            signal.is_some(),
            &suggest_values,
        )?
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

/// The command of `test-request <file>`. The file is the one bare operand, and the
/// word may not be combined with the other actions.
fn test_request_command(
    operands: &[&str],
    client: Option<IpAddr>,
    lifecycle: Option<&str>,
    test: bool,
    signal: bool,
) -> Result<Command, String> {
    if let Some(word) = lifecycle {
        return Err(format!("test-request cannot be combined with {word}"));
    }
    if test {
        return Err("test-request cannot be combined with -t or -T".to_owned());
    }
    if signal {
        return Err("test-request cannot be combined with -s".to_owned());
    }
    let file = match operands {
        [only] => PathBuf::from(only),
        [] => return Err("test-request needs a request file (or - for stdin)".to_owned()),
        _ => return Err("give only one request file".to_owned()),
    };
    Ok(Command::TestRequest {
        file,
        client: client.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    })
}

/// The command of `suggest-skip-rules <file>`. The file is the one bare operand. The word
/// reads only the access log, so `-c` and the other actions are errors.
fn suggest_command(
    operands: &[&str],
    config_given: bool,
    lifecycle: Option<&str>,
    test: bool,
    signal: bool,
    values: &[(&str, String)],
) -> Result<Command, String> {
    if config_given {
        return Err("suggest-skip-rules reads only the access log; -c is not used".to_owned());
    }
    if let Some(word) = lifecycle {
        return Err(format!("suggest-skip-rules cannot be combined with {word}"));
    }
    if test {
        return Err("suggest-skip-rules cannot be combined with -t or -T".to_owned());
    }
    if signal {
        return Err("suggest-skip-rules cannot be combined with -s".to_owned());
    }
    let file = match operands {
        [only] => PathBuf::from(only),
        [] => {
            return Err("suggest-skip-rules needs an access log file (or - for stdin)".to_owned());
        }
        _ => return Err("give only one access log file".to_owned()),
    };
    Ok(Command::SuggestSkipRules {
        file,
        options: suggest_options(values)?,
    })
}

/// The site filter and thresholds from the `suggest-skip-rules` options. Each option may
/// be given once. The defaults are the thresholds of the documentation.
fn suggest_options(values: &[(&str, String)]) -> Result<SuggestOptions, String> {
    let mut options = SuggestOptions::default();
    let mut seen: Vec<&str> = Vec::new();
    for (flag, value) in values {
        if seen.contains(flag) {
            return Err(format!("{flag} is given more than once"));
        }
        seen.push(flag);
        match *flag {
            "--site" => {
                if value.is_empty() {
                    return Err("--site needs a site name".to_owned());
                }
                options.site = Some(value.clone());
            }
            "--min-judged" => options.min_judged = count_value(flag, value)?,
            "--min-clients" => options.min_clients = count_value(flag, value)?,
            "--min-days" => options.min_days = count_value(flag, value)?,
            "--max-attack" => options.max_attack = score_value(flag, value)?,
            "--max-ai-instruction" => options.max_ai_instruction = score_value(flag, value)?,
            other => return Err(format!("unknown option \"{other}\"")),
        }
    }
    Ok(options)
}

/// Reads a count, which must be a whole number of at least 1.
fn count_value(option: &str, value: &str) -> Result<usize, String> {
    match value.parse::<usize>() {
        Ok(count) if count > 0 => Ok(count),
        _ => Err(format!(
            "{option} must be a whole number of at least 1, not \"{value}\""
        )),
    }
}

/// Reads a score, which must be a number from 0 to 1.
fn score_value(option: &str, value: &str) -> Result<f64, String> {
    match value.parse::<f64>() {
        Ok(score) if (0.0..=1.0).contains(&score) => Ok(score),
        _ => Err(format!(
            "{option} must be a number from 0 to 1, not \"{value}\""
        )),
    }
}

/// Splits `--name=value` for a `suggest-skip-rules` option. The name is one of [`SUGGEST_FLAGS`].
fn suggest_flag_value(arg: &str) -> Option<(&'static str, &str)> {
    let (name, value) = arg.split_once('=')?;
    let flag = SUGGEST_FLAGS.into_iter().find(|flag| *flag == name)?;
    Some((flag, value))
}

/// Reads the value of an option that takes a path.
fn path_value(option: &str, value: Option<&String>) -> Result<PathBuf, String> {
    match value {
        Some(path) if !path.is_empty() => Ok(PathBuf::from(path)),
        _ => Err(format!("{option} needs a path")),
    }
}

/// Reads the value of `--client`, an IPv4 or IPv6 address.
fn address_value(option: &str, value: Option<&String>) -> Result<IpAddr, String> {
    let text = value.ok_or_else(|| format!("{option} needs an address"))?;
    text.parse::<IpAddr>()
        .map_err(|_| format!("invalid address \"{text}\" for {option}"))
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
    #[case::test_request_with_file(&["test-request", "req.txt"], Options { config: None, command: test_request("req.txt", LOCALHOST) })]
    #[case::test_request_file_before_word(&["req.txt", "test-request"], Options { config: None, command: test_request("req.txt", LOCALHOST) })]
    #[case::test_request_with_config(&["-c", "/a.conf", "test-request", "req.txt"], Options { config: Some(PathBuf::from("/a.conf")), command: test_request("req.txt", LOCALHOST) })]
    #[case::test_request_with_client(&["test-request", "req.txt", "--client", "203.0.113.7"], Options { config: None, command: test_request("req.txt", "203.0.113.7".parse().unwrap_or(LOCALHOST)) })]
    #[case::test_request_with_client_equals(&["test-request", "--client=2001:db8::1", "req.txt"], Options { config: None, command: test_request("req.txt", "2001:db8::1".parse().unwrap_or(LOCALHOST)) })]
    #[case::test_request_from_stdin(&["test-request", "-"], Options { config: None, command: test_request("-", LOCALHOST) })]
    #[case::suggest_with_file(&["suggest-skip-rules", "log.json"], Options { config: None, command: Command::SuggestSkipRules { file: PathBuf::from("log.json"), options: SuggestOptions::default() } })]
    #[case::suggest_from_stdin(&["suggest-skip-rules", "-"], Options { config: None, command: Command::SuggestSkipRules { file: PathBuf::from("-"), options: SuggestOptions::default() } })]
    #[case::suggest_file_before_word(&["log.json", "suggest-skip-rules"], Options { config: None, command: Command::SuggestSkipRules { file: PathBuf::from("log.json"), options: SuggestOptions::default() } })]
    #[case::suggest_with_site(&["suggest-skip-rules", "log.json", "--site", "example.test"], Options { config: None, command: Command::SuggestSkipRules { file: PathBuf::from("log.json"), options: SuggestOptions { site: Some("example.test".to_owned()), ..SuggestOptions::default() } } })]
    #[case::suggest_with_thresholds(&["suggest-skip-rules", "log.json", "--min-judged", "60", "--min-clients=12", "--min-days", "4", "--max-attack", "0.2", "--max-ai-instruction=0.25"], Options { config: None, command: Command::SuggestSkipRules { file: PathBuf::from("log.json"), options: SuggestOptions { min_judged: 60, min_clients: 12, min_days: 4, max_attack: 0.2, max_ai_instruction: 0.25, ..SuggestOptions::default() } } })]
    #[case::suggest_score_one(&["suggest-skip-rules", "log.json", "--max-attack", "1"], Options { config: None, command: Command::SuggestSkipRules { file: PathBuf::from("log.json"), options: SuggestOptions { max_attack: 1.0, ..SuggestOptions::default() } } })]
    #[case::suggest_help_wins(&["suggest-skip-rules", "-h"], Options { config: None, command: Command::Help })]
    #[case::help_wins_over_test_request(&["test-request", "-h"], Options { config: None, command: Command::Help })]
    fn a_valid_command_line_parses(#[case] input: &[&str], #[case] expected: Options) {
        assert_eq!(parse_args(&args(input)), Ok(expected));
    }

    #[rstest]
    #[case::long_option(&["--bogus"], "unknown option \"--bogus\"")]
    #[case::short_option(&["-x"], "unknown option \"-x\"")]
    #[case::option_after_a_command(&["start", "--bogus"], "unknown option \"--bogus\"")]
    fn a_dashed_word_that_is_no_option_is_refused(#[case] input: &[&str], #[case] message: &str) {
        assert_eq!(parse_args(&args(input)), Err(message.to_owned()));
    }

    #[rstest]
    #[case::before_help(&["-h", "--bogus"])]
    #[case::inside_suggest_skip_rules(&["suggest-skip-rules", "--bogus", "log.json"])]
    #[case::inside_test_request(&["test-request", "--bogus", "req.txt"])]
    fn an_unknown_option_is_refused_wherever_it_appears(#[case] input: &[&str]) {
        assert_eq!(
            parse_args(&args(input)),
            Err("unknown option \"--bogus\"".to_owned())
        );
    }

    #[test]
    fn positive_suggest_thresholds_are_read_as_given() -> Result<(), String> {
        let command = parse_args(&args(&[
            "suggest-skip-rules",
            "log.json",
            "--min-judged",
            "60",
            "--min-clients",
            "12",
            "--min-days",
            "4",
            "--max-attack",
            "0.2",
            "--max-ai-instruction",
            "0.25",
        ]))?
        .command;
        let Command::SuggestSkipRules { options, .. } = command else {
            return Err("not a suggest-skip-rules command".to_owned());
        };
        assert_eq!(options.min_judged, 60);
        assert_eq!(options.min_clients, 12);
        assert_eq!(options.min_days, 4);
        assert!((options.max_attack - 0.2).abs() < f64::EPSILON);
        assert!((options.max_ai_instruction - 0.25).abs() < f64::EPSILON);
        Ok(())
    }

    fn test_request(file: &str, client: IpAddr) -> Command {
        Command::TestRequest {
            file: PathBuf::from(file),
            client,
        }
    }

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[test]
    fn test_request_defaults_the_client_to_the_loopback_address() {
        assert_eq!(
            parse_args(&args(&["test-request", "req.txt"])).map(|options| options.command),
            Ok(test_request("req.txt", LOCALHOST))
        );
    }

    #[rstest]
    #[case::without_a_file(&["test-request"], "test-request needs a request file (or - for stdin)")]
    #[case::two_files(&["test-request", "a.txt", "b.txt"], "give only one request file")]
    #[case::with_test(&["test-request", "req.txt", "-t"], "test-request cannot be combined with -t or -T")]
    #[case::with_dump(&["-T", "test-request", "req.txt"], "test-request cannot be combined with -t or -T")]
    #[case::with_signal(&["test-request", "req.txt", "-s", "reload"], "test-request cannot be combined with -s")]
    #[case::with_start(&["start", "test-request", "req.txt"], "test-request cannot be combined with start")]
    #[case::with_stop(&["test-request", "req.txt", "stop"], "test-request cannot be combined with stop")]
    #[case::with_restart(&["restart", "test-request", "req.txt"], "test-request cannot be combined with restart")]
    #[case::word_twice(&["test-request", "test-request", "req.txt"], "test-request is given more than once")]
    #[case::bare_file_without_the_word(&["req.txt"], "unknown option \"req.txt\"")]
    #[case::client_without_the_word(&["--client", "127.0.0.1"], "--client can only be used with test-request")]
    #[case::client_with_start(&["start", "--client=127.0.0.1"], "--client can only be used with test-request")]
    #[case::client_without_address(&["test-request", "req.txt", "--client"], "--client needs an address")]
    #[case::client_not_an_address(&["test-request", "req.txt", "--client", "example.com"], "invalid address \"example.com\" for --client")]
    #[case::suggest_with_config(&["suggest-skip-rules", "log.json", "-c", "/a.conf"], "suggest-skip-rules reads only the access log; -c is not used")]
    #[case::suggest_with_config_equals(&["--config=/a.conf", "suggest-skip-rules", "log.json"], "suggest-skip-rules reads only the access log; -c is not used")]
    #[case::suggest_with_test(&["suggest-skip-rules", "log.json", "-t"], "suggest-skip-rules cannot be combined with -t or -T")]
    #[case::suggest_with_signal(&["suggest-skip-rules", "log.json", "-s", "reload"], "suggest-skip-rules cannot be combined with -s")]
    #[case::suggest_with_start(&["start", "suggest-skip-rules", "log.json"], "suggest-skip-rules cannot be combined with start")]
    #[case::suggest_with_test_request(&["suggest-skip-rules", "log.json", "test-request", "req.txt"], "suggest-skip-rules cannot be combined with test-request")]
    #[case::suggest_without_file(&["suggest-skip-rules"], "suggest-skip-rules needs an access log file (or - for stdin)")]
    #[case::suggest_two_files(&["suggest-skip-rules", "a.json", "b.json"], "give only one access log file")]
    #[case::suggest_word_twice(&["suggest-skip-rules", "suggest-skip-rules", "a.json"], "suggest-skip-rules is given more than once")]
    #[case::suggest_site_without_name(&["suggest-skip-rules", "a.json", "--site"], "--site needs a value")]
    #[case::suggest_site_empty(&["suggest-skip-rules", "a.json", "--site="], "--site needs a site name")]
    #[case::suggest_site_twice(&["suggest-skip-rules", "a.json", "--site", "x", "--site=y"], "--site is given more than once")]
    #[case::suggest_zero_count(&["suggest-skip-rules", "a.json", "--min-judged", "0"], "--min-judged must be a whole number of at least 1, not \"0\"")]
    #[case::suggest_count_not_a_number(&["suggest-skip-rules", "a.json", "--min-days=three"], "--min-days must be a whole number of at least 1, not \"three\"")]
    #[case::suggest_score_above_one(&["suggest-skip-rules", "a.json", "--max-attack", "1.5"], "--max-attack must be a number from 0 to 1, not \"1.5\"")]
    #[case::suggest_score_nan(&["suggest-skip-rules", "a.json", "--max-ai-instruction", "NaN"], "--max-ai-instruction must be a number from 0 to 1, not \"NaN\"")]
    #[case::suggest_option_without_word(&["--min-judged", "60"], "--min-judged can only be used with suggest-skip-rules")]
    #[case::site_with_test_request(&["test-request", "req.txt", "--site", "example.test"], "--site can only be used with suggest-skip-rules")]
    fn test_request_rejects_combinations_and_bad_operands(
        #[case] input: &[&str],
        #[case] message: &str,
    ) {
        assert_eq!(parse_args(&args(input)), Err(message.to_owned()));
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
