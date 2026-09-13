//! Local launcher for remote commands.
//!
//! A remote operation stays `target` + remote command string. This module owns
//! the one point where that pair becomes a local process: the built-in SSH
//! launcher, or the program and argv template from `[remote.command]`. Both
//! spawn an executable with an argv vector, so no local shell is ever involved
//! and a remote command keeps its own quoting, `$`, and `;` intact.
//!
//! The remote command string itself keeps SSH semantics: the launched program
//! hands it to the remote side, which runs it the way `ssh target "<command>"`
//! would.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

const TARGET_PLACEHOLDER: &str = "target";
const COMMAND_PLACEHOLDER: &str = "command";

/// Stdin disposition the caller needs from the launched process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RemoteStdin {
    /// The caller writes the remote command's stdin: setup scripts, binary
    /// installs, and the long-running client bridge.
    Piped,
    /// The caller never writes stdin.
    Null,
}

/// Private SSH config and control socket Herdr generates for one attach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ManagedSshOptions {
    pub(super) config_path: PathBuf,
    pub(super) control_path: Option<PathBuf>,
}

/// How Herdr launches `remote_command` on `target` locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RemoteLauncher {
    /// Built-in OpenSSH launcher. The default, and the only launcher that owns
    /// generated SSH config and connection reuse.
    Ssh {
        options: Option<ManagedSshOptions>,
        noninteractive: bool,
    },
    /// Configured executable plus argv template from `[remote.command]`.
    Program(RemoteProgram),
}

impl RemoteLauncher {
    pub(super) fn ssh(options: Option<ManagedSshOptions>, noninteractive: bool) -> Self {
        Self::Ssh {
            options,
            noninteractive,
        }
    }

    /// Local process that runs `remote_command` on `target`.
    ///
    /// Callers still choose the stdio handles they need; `stdin` only tells the
    /// launcher whether the remote command reads stdin.
    pub(super) fn command(
        &self,
        target: &str,
        remote_command: &str,
        stdin: RemoteStdin,
    ) -> Command {
        match self {
            Self::Ssh {
                options,
                noninteractive,
            } => {
                let mut command = Command::new("ssh");
                apply_managed_ssh_options(&mut command, options.as_ref());
                if *noninteractive {
                    apply_noninteractive_ssh_options(&mut command);
                }
                command.arg("-T").arg(target);
                if matches!(stdin, RemoteStdin::Null) {
                    // Windows OpenSSH can still read the console with stdin redirected to NUL.
                    command.arg("-n");
                }
                command.arg(remote_command);
                command
            }
            Self::Program(program) => program.command(target, remote_command),
        }
    }

    /// Launcher for a metadata-only probe: SSH drops the shared control socket
    /// and refuses prompts, a configured program is used unchanged.
    pub(super) fn probe(&self) -> Self {
        match self {
            Self::Ssh { .. } => Self::ssh(None, true),
            Self::Program(program) => Self::Program(program.clone()),
        }
    }

    /// Shutdown for a connection-reuse master, when the launcher owns one.
    pub(super) fn control_exit_command(&self, target: &str) -> Option<Command> {
        let Self::Ssh { options, .. } = self else {
            return None;
        };
        let options = options
            .as_ref()
            .filter(|options| options.control_path.is_some())?;
        let mut command = Command::new("ssh");
        apply_managed_ssh_options(&mut command, Some(options));
        command
            .arg("-O")
            .arg("exit")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg(target);
        Some(command)
    }

    /// Program name for spawn diagnostics.
    pub(super) fn program_name(&self) -> String {
        match self {
            Self::Ssh { .. } => "ssh".to_string(),
            Self::Program(program) => program.program.to_string_lossy().into_owned(),
        }
    }
}

/// Launcher selected by `[remote]`, before Herdr generates the SSH config that
/// only the SSH launcher uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ConfiguredLauncher {
    Ssh { manage_config: bool },
    Program(RemoteProgram),
}

/// Launcher for `[remote]` configuration.
///
/// An invalid `[remote.command]` is an error rather than a silent fall back to
/// `ssh`: the launcher is how the operator chose to reach the target.
/// `noninteractive` callers never get the generated SSH config, because they
/// cannot answer a prompt or clean up a shared control socket interactively.
pub(super) fn configured_launcher(
    config: &crate::config::RemoteConfig,
    noninteractive: bool,
) -> std::io::Result<ConfiguredLauncher> {
    match config.command.as_ref() {
        Some(command) => RemoteProgram::from_config(command)
            .map(ConfiguredLauncher::Program)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error)),
        None => Ok(ConfiguredLauncher::Ssh {
            manage_config: config.manage_ssh_config && !noninteractive,
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RemoteProgram {
    program: OsString,
    args: Vec<ArgTemplate>,
}

impl RemoteProgram {
    fn from_config(config: &crate::config::RemoteCommandConfig) -> Result<Self, String> {
        let program = config.program.trim();
        if program.is_empty() {
            return Err("remote.command.program must name an executable".to_string());
        }
        if ArgTemplate::parse(program).is_ok_and(|template| !template.is_literal()) {
            return Err(
                "remote.command.program is spawned directly and does not expand placeholders; \
                 put {target} and {command} in remote.command.args"
                    .to_string(),
            );
        }

        let mut args = Vec::with_capacity(config.args.len());
        for (index, arg) in config.args.iter().enumerate() {
            args.push(
                ArgTemplate::parse(arg)
                    .map_err(|error| format!("remote.command.args[{index}]: {error}"))?,
            );
        }
        for (placeholder, present) in [
            (
                TARGET_PLACEHOLDER,
                args.iter().any(|arg| arg.contains(&Segment::Target)),
            ),
            (
                COMMAND_PLACEHOLDER,
                args.iter().any(|arg| arg.contains(&Segment::Command)),
            ),
        ] {
            if !present {
                return Err(format!(
                    "remote.command.args must include the {{{placeholder}}} placeholder so \
                     `{program}` receives the remote {placeholder}"
                ));
            }
        }

        Ok(Self {
            program: OsString::from(program),
            args,
        })
    }

    fn command(&self, target: &str, remote_command: &str) -> Command {
        let mut command = Command::new(&self.program);
        for arg in &self.args {
            command.arg(arg.expand(target, remote_command));
        }
        command
    }
}

/// One configured argument. Expansion never splits it into more than one argv
/// element, whatever the target or the remote command contain.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ArgTemplate(Vec<Segment>);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Target,
    Command,
}

impl ArgTemplate {
    fn parse(raw: &str) -> Result<Self, String> {
        let mut segments = Vec::new();
        let mut literal = String::new();
        let mut rest = raw;

        while let Some(open) = rest.find(['{', '}']) {
            let (head, tail) = rest.split_at(open);
            literal.push_str(head);
            let doubled = tail[..1].repeat(2);
            if let Some(after) = tail.strip_prefix(&doubled) {
                literal.push_str(&tail[..1]);
                rest = after;
                continue;
            }
            if let Some(after) = tail.strip_prefix('}') {
                literal.push('}');
                rest = after;
                continue;
            }
            let Some(end) = tail.find('}') else {
                return Err(format!(
                    "unterminated placeholder in {raw:?}; write {{{{ for a literal brace"
                ));
            };
            let name = &tail[1..end];
            let segment = match name {
                TARGET_PLACEHOLDER => Segment::Target,
                COMMAND_PLACEHOLDER => Segment::Command,
                _ => {
                    return Err(format!(
                        "unknown placeholder {{{name}}}; supported placeholders are \
                         {{{TARGET_PLACEHOLDER}}} and {{{COMMAND_PLACEHOLDER}}} \
                         (write {{{{ for a literal brace)"
                    ))
                }
            };
            if !literal.is_empty() {
                segments.push(Segment::Literal(std::mem::take(&mut literal)));
            }
            segments.push(segment);
            rest = &tail[end + 1..];
        }

        literal.push_str(rest);
        if !literal.is_empty() || segments.is_empty() {
            segments.push(Segment::Literal(literal));
        }
        Ok(Self(segments))
    }

    fn is_literal(&self) -> bool {
        self.0
            .iter()
            .all(|segment| matches!(segment, Segment::Literal(_)))
    }

    fn contains(&self, needle: &Segment) -> bool {
        self.0.iter().any(|segment| segment == needle)
    }

    fn expand(&self, target: &str, remote_command: &str) -> OsString {
        let mut expanded = String::new();
        for segment in &self.0 {
            match segment {
                Segment::Literal(literal) => expanded.push_str(literal),
                Segment::Target => expanded.push_str(target),
                Segment::Command => expanded.push_str(remote_command),
            }
        }
        OsString::from(expanded)
    }
}

fn apply_noninteractive_ssh_options(command: &mut Command) {
    command
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("NumberOfPasswordPrompts=0")
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("ConnectionAttempts=1")
        .arg("-o")
        .arg("ServerAliveInterval=15")
        .arg("-o")
        .arg("ServerAliveCountMax=4");
}

fn apply_managed_ssh_options(command: &mut Command, options: Option<&ManagedSshOptions>) {
    let Some(options) = options else {
        return;
    };

    command.arg("-F").arg(&options.config_path);
    if let Some(control_path) = &options.control_path {
        command
            .arg("-S")
            .arg(control_path)
            .arg("-o")
            .arg("ControlMaster=auto")
            .arg("-o")
            .arg("ControlPersist=yes");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program_config(program: &str, args: &[&str]) -> crate::config::RemoteCommandConfig {
        crate::config::RemoteCommandConfig {
            program: program.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
        }
    }

    fn openshell_config() -> crate::config::RemoteCommandConfig {
        program_config(
            "openshell",
            &[
                "sandbox",
                "exec",
                "-n",
                "{target}",
                "--no-tty",
                "--no-login-shell",
                "--",
                "{command}",
            ],
        )
    }

    fn argv(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn launcher(config: &crate::config::RemoteCommandConfig) -> RemoteLauncher {
        RemoteLauncher::Program(RemoteProgram::from_config(config).expect("valid launcher"))
    }

    #[test]
    fn ssh_stays_the_default_launcher_shape() {
        let command = RemoteLauncher::ssh(None, false).command(
            "host",
            "herdr remote-client-bridge",
            RemoteStdin::Piped,
        );

        assert_eq!(command.get_program(), "ssh");
        assert_eq!(
            argv(&command),
            vec!["-T", "host", "herdr remote-client-bridge"]
        );
    }

    #[test]
    fn ssh_refuses_stdin_for_commands_that_never_write_it() {
        let command =
            RemoteLauncher::ssh(None, false).command("host", "uname -s", RemoteStdin::Null);

        assert_eq!(argv(&command), vec!["-T", "host", "-n", "uname -s"]);
    }

    #[test]
    fn ssh_keeps_managed_and_noninteractive_options_before_the_target() {
        let options = ManagedSshOptions {
            config_path: PathBuf::from("/tmp/herdr/config"),
            control_path: Some(PathBuf::from("/tmp/herdr/ctl")),
        };
        let command =
            RemoteLauncher::ssh(Some(options), true).command("host", "true", RemoteStdin::Piped);
        let args = argv(&command);

        assert_eq!(&args[..2], ["-F", "/tmp/herdr/config"]);
        assert!(args.iter().any(|arg| arg == "BatchMode=yes"));
        assert_eq!(&args[args.len() - 3..], ["-T", "host", "true"]);
    }

    #[test]
    fn configured_launcher_spawns_the_executable_directly() {
        let launcher = launcher(&openshell_config());
        let command = launcher.command(
            "sandbox-1",
            "herdr remote-client-bridge",
            RemoteStdin::Piped,
        );

        assert_eq!(command.get_program(), "openshell");
        assert_eq!(
            argv(&command),
            vec![
                "sandbox",
                "exec",
                "-n",
                "sandbox-1",
                "--no-tty",
                "--no-login-shell",
                "--",
                "herdr remote-client-bridge",
            ]
        );
        assert_eq!(launcher.program_name(), "openshell");
        assert!(launcher.control_exit_command("sandbox-1").is_none());
    }

    #[test]
    fn placeholders_expand_into_exactly_one_argv_element() {
        let command = launcher(&openshell_config()).command(
            "two words",
            "sh -c 'echo $HOME; echo \"done\"' && true",
            RemoteStdin::Piped,
        );
        let args = argv(&command);

        assert_eq!(args.iter().filter(|arg| *arg == "two words").count(), 1);
        assert_eq!(
            args.last().expect("remote command argument"),
            "sh -c 'echo $HOME; echo \"done\"' && true"
        );
        assert_eq!(args.len(), 8);
    }

    #[test]
    fn placeholders_expand_inside_a_larger_argument_without_splitting_it() {
        let command = launcher(&program_config(
            "wrapper",
            &["--target={target}", "--run={command}", "{{literal}}"],
        ))
        .command("host", "a b", RemoteStdin::Piped);

        assert_eq!(
            argv(&command),
            vec!["--target=host", "--run=a b", "{literal}"]
        );
    }

    #[test]
    fn expansion_never_re_expands_substituted_text() {
        let command =
            launcher(&openshell_config()).command("{command}", "{target}", RemoteStdin::Piped);
        let args = argv(&command);

        assert_eq!(args[3], "{command}");
        assert_eq!(args[7], "{target}");
    }

    #[test]
    fn probe_launcher_drops_ssh_reuse_but_keeps_a_configured_program() {
        let options = ManagedSshOptions {
            config_path: PathBuf::from("/tmp/herdr/config"),
            control_path: Some(PathBuf::from("/tmp/herdr/ctl")),
        };
        let ssh = RemoteLauncher::ssh(Some(options), false).probe();
        assert_eq!(ssh, RemoteLauncher::ssh(None, true));

        let program = launcher(&openshell_config());
        assert_eq!(program.probe(), program);
    }

    #[test]
    fn managed_ssh_control_socket_has_a_shutdown_command() {
        let options = ManagedSshOptions {
            config_path: PathBuf::from("/tmp/herdr/config"),
            control_path: Some(PathBuf::from("/tmp/herdr/ctl")),
        };
        let command = RemoteLauncher::ssh(Some(options), false)
            .control_exit_command("host")
            .expect("managed control socket exits");

        assert_eq!(
            argv(&command),
            vec![
                "-F",
                "/tmp/herdr/config",
                "-S",
                "/tmp/herdr/ctl",
                "-o",
                "ControlMaster=auto",
                "-o",
                "ControlPersist=yes",
                "-O",
                "exit",
                "-o",
                "BatchMode=yes",
                "host",
            ]
        );
        assert!(RemoteLauncher::ssh(None, false)
            .control_exit_command("host")
            .is_none());
    }

    #[test]
    fn invalid_launcher_configuration_names_the_problem() {
        for (config, expected) in [
            (
                program_config("", &["{target}", "{command}"]),
                "must name an executable",
            ),
            (
                program_config("openshell {target}", &["{target}", "{command}"]),
                "does not expand placeholders",
            ),
            (
                program_config("openshell", &["{command}"]),
                "must include the {target} placeholder",
            ),
            (
                program_config("openshell", &["{target}"]),
                "must include the {command} placeholder",
            ),
            (
                program_config("openshell", &["-n", "{host}", "{command}"]),
                "unknown placeholder {host}",
            ),
            (
                program_config("openshell", &["{target}", "{command"]),
                "unterminated placeholder",
            ),
        ] {
            let error = RemoteProgram::from_config(&config).expect_err("rejected configuration");
            assert!(
                error.contains(expected),
                "expected {expected:?} in {error:?}"
            );
        }
    }

    #[test]
    fn unknown_placeholder_error_points_at_the_offending_argument() {
        let error = RemoteProgram::from_config(&program_config(
            "openshell",
            &["{target}", "{oops}", "{command}"],
        ))
        .expect_err("rejected configuration");

        assert!(error.starts_with("remote.command.args[1]:"), "{error}");
    }

    #[test]
    fn unset_remote_command_keeps_the_ssh_default() {
        let config = crate::config::RemoteConfig::default();

        assert_eq!(
            configured_launcher(&config, false).expect("default config is valid"),
            ConfiguredLauncher::Ssh {
                manage_config: true
            }
        );
        assert_eq!(
            configured_launcher(&config, true).expect("default config is valid"),
            ConfiguredLauncher::Ssh {
                manage_config: false
            }
        );
    }

    #[test]
    fn configured_remote_command_replaces_ssh_for_every_caller() {
        let config = crate::config::RemoteConfig {
            manage_ssh_config: true,
            command: Some(openshell_config()),
        };
        let expected =
            ConfiguredLauncher::Program(RemoteProgram::from_config(&openshell_config()).unwrap());

        for noninteractive in [false, true] {
            assert_eq!(
                configured_launcher(&config, noninteractive).expect("valid launcher"),
                expected
            );
        }
    }

    #[test]
    fn invalid_remote_command_configuration_is_rejected_instead_of_falling_back_to_ssh() {
        let config = crate::config::RemoteConfig {
            manage_ssh_config: true,
            command: Some(program_config("openshell", &["{target}"])),
        };

        let error = configured_launcher(&config, false).expect_err("rejected configuration");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("{command}"), "{error}");
    }
}

/// The configured launcher is only useful if a real process receives the argv
/// Herdr built and keeps the bridge's stdio usable, so these spawn one.
#[cfg(all(test, unix))]
mod process_tests {
    use super::*;
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Stdio;

    struct FakeLauncher {
        dir: std::path::PathBuf,
    }

    impl Drop for FakeLauncher {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl FakeLauncher {
        /// Writes a launcher that records its own argv, echoes stdin back on
        /// stdout, and exits with the status named by its first argument.
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "herdr-launcher-test-{}-{name}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).expect("create launcher directory");
            let program = dir.join("fake launcher");
            std::fs::write(
                &program,
                "#!/bin/sh\nstatus=\"$1\"\nshift\nfor arg in \"$@\"; do\n  printf '%s\\n' \"$arg\" >> \"$0.argv\"\ndone\nwhile IFS= read -r line; do\n  printf 'echo:%s\\n' \"$line\"\ndone\nexit \"$status\"\n",
            )
            .expect("write launcher");
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
                .expect("make launcher executable");
            Self { dir }
        }

        fn program(&self) -> String {
            self.dir
                .join("fake launcher")
                .to_string_lossy()
                .into_owned()
        }

        fn recorded_argv(&self) -> Vec<String> {
            let path = self.dir.join("fake launcher.argv");
            std::fs::read_to_string(path)
                .expect("launcher recorded its argv")
                .lines()
                .map(str::to_owned)
                .collect()
        }

        fn launcher(&self, status: &str) -> RemoteLauncher {
            RemoteLauncher::Program(
                RemoteProgram::from_config(&crate::config::RemoteCommandConfig {
                    program: self.program(),
                    args: [status, "exec", "-n", "{target}", "--", "{command}"]
                        .iter()
                        .map(|arg| (*arg).to_string())
                        .collect(),
                })
                .expect("valid launcher"),
            )
        }
    }

    #[test]
    fn configured_launcher_execs_the_program_without_a_local_shell() {
        let fake = FakeLauncher::new("argv");
        let canary = fake.dir.join("canary");
        let remote_command = format!(
            "herdr --session 'a b' server; touch {}; echo \"$HOME\" && true",
            canary.display()
        );

        let mut child = fake
            .launcher("0")
            .command("host name", &remote_command, RemoteStdin::Piped)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn configured launcher");
        assert!(child.wait().expect("launcher exits").success());

        // One argv element each, byte for byte, and no shell ran the remote
        // command locally.
        assert_eq!(
            fake.recorded_argv(),
            vec![
                "exec".to_string(),
                "-n".to_string(),
                "host name".to_string(),
                "--".to_string(),
                remote_command,
            ]
        );
        assert!(
            !canary.exists(),
            "the remote command ran through a local shell"
        );
    }

    #[test]
    fn configured_launcher_keeps_stdin_and_stdout_usable_for_the_bridge() {
        let fake = FakeLauncher::new("bridge");
        let mut child = fake
            .launcher("0")
            .command("host", "herdr remote-client-bridge", RemoteStdin::Piped)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn configured launcher");
        let mut stdin = child.stdin.take().expect("bridge stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("bridge stdout"));

        // Round trip before EOF: the bridge stays open across messages.
        for message in ["first", "second"] {
            writeln!(stdin, "{message}").expect("write to the launcher");
            stdin.flush().expect("flush launcher stdin");
            let mut line = String::new();
            stdout.read_line(&mut line).expect("read from the launcher");
            assert_eq!(line, format!("echo:{message}\n"));
        }

        drop(stdin);
        let mut rest = String::new();
        stdout
            .read_to_string(&mut rest)
            .expect("drain launcher stdout");
        assert!(rest.is_empty(), "unexpected trailing output {rest:?}");
        assert!(child.wait().expect("launcher exits").success());
    }

    #[test]
    fn configured_launcher_reports_the_programs_exit_status() {
        let fake = FakeLauncher::new("status");
        let status = fake
            .launcher("7")
            .command("host", "herdr remote-client-bridge", RemoteStdin::Piped)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .expect("run configured launcher");

        assert_eq!(status.code(), Some(7));
    }

    #[test]
    fn missing_launcher_program_fails_at_spawn_like_a_missing_ssh() {
        let launcher = RemoteLauncher::Program(
            RemoteProgram::from_config(&crate::config::RemoteCommandConfig {
                program: "/nonexistent/herdr-remote-launcher".to_string(),
                args: vec!["{target}".to_string(), "{command}".to_string()],
            })
            .expect("valid launcher"),
        );

        let error = launcher
            .command("host", "true", RemoteStdin::Piped)
            .spawn()
            .expect_err("missing program");

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }
}
