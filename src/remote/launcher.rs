//! Local launcher for remote commands.
//!
//! A remote operation stays `target` + remote command string. `[remote.command]`
//! says which local program runs that pair, and `ssh` is the default value of
//! that setting rather than a separate path: Herdr always expands one argv
//! template and spawns the program directly, so no local shell is involved and a
//! remote command keeps its own quoting, `$`, and `;` intact.
//!
//! The launched program must run the remote command on the target the way
//! `ssh target "<command>"` does, with stdin and stdout connected.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::Command;

const TARGET_PLACEHOLDER: &str = "target";
const COMMAND_PLACEHOLDER: &str = "command";
const SSH_OPTIONS_PLACEHOLDER: &str = "ssh_options";

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

impl ManagedSshOptions {
    fn apply(&self, command: &mut Command) {
        command.arg("-F").arg(&self.config_path);
        if let Some(control_path) = &self.control_path {
            command
                .arg("-S")
                .arg(control_path)
                .arg("-o")
                .arg("ControlMaster=auto")
                .arg("-o")
                .arg("ControlPersist=yes");
        }
    }

    /// Shutdown for the connection-reuse master, when this config opened one.
    pub(super) fn control_exit_command(&self, target: &str) -> Option<Command> {
        self.control_path.as_ref()?;
        let mut command = Command::new("ssh");
        self.apply(&mut command);
        command
            .arg("-O")
            .arg("exit")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg(target);
        Some(command)
    }
}

/// The local program Herdr runs to execute one remote command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RemoteLauncher {
    program: OsString,
    args: Vec<Arg>,
    ssh: SshOptions,
}

/// Values `{ssh_options}` expands to. Only a template that asks for them is
/// given Herdr's OpenSSH options, so a program that is not ssh gets none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SshOptions {
    managed: Option<ManagedSshOptions>,
    noninteractive: bool,
}

impl RemoteLauncher {
    /// Launcher for `[remote.command]`, whose default is Herdr's `ssh` command.
    ///
    /// An unusable template is an error rather than a fall back to some other
    /// program: the launcher is how the operator chose to reach the target.
    pub(super) fn new(config: &crate::config::RemoteCommandConfig) -> io::Result<Self> {
        Self::parse(config).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }

    fn parse(config: &crate::config::RemoteCommandConfig) -> Result<Self, String> {
        let program = config.program.trim();
        if program.is_empty() {
            return Err("remote.command.program must name an executable".to_string());
        }
        if ArgTemplate::parse(program).is_ok_and(|template| !template.is_literal()) {
            return Err(
                "remote.command.program is spawned directly and does not expand placeholders; \
                 put the placeholders in remote.command.args"
                    .to_string(),
            );
        }

        let mut args = Vec::with_capacity(config.args.len());
        for (index, arg) in config.args.iter().enumerate() {
            args.push(
                Arg::parse(arg)
                    .map_err(|error| format!("remote.command.args[{index}]: {error}"))?,
            );
        }
        for (placeholder, segment) in [
            (TARGET_PLACEHOLDER, Segment::Target),
            (COMMAND_PLACEHOLDER, Segment::Command),
        ] {
            if !args.iter().any(|arg| arg.contains(&segment)) {
                return Err(format!(
                    "remote.command.args must include the {{{placeholder}}} placeholder so \
                     `{program}` receives the remote {placeholder}"
                ));
            }
        }

        Ok(Self {
            program: OsString::from(program),
            args,
            ssh: SshOptions::default(),
        })
    }

    /// Whether the template asks for the OpenSSH options Herdr manages, and so
    /// whether generating a private SSH config for it is worth anything.
    pub(super) fn uses_ssh_options(&self) -> bool {
        self.args.iter().any(|arg| matches!(arg, Arg::SshOptions))
    }

    pub(super) fn with_ssh_options(
        mut self,
        managed: Option<ManagedSshOptions>,
        noninteractive: bool,
    ) -> Self {
        self.ssh = SshOptions {
            managed,
            noninteractive,
        };
        self
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
        let mut command = Command::new(&self.program);
        for arg in &self.args {
            match arg {
                Arg::Template(template) => {
                    command.arg(template.expand(target, remote_command));
                }
                Arg::SshOptions => self.ssh.apply(&mut command, stdin),
            }
        }
        command
    }

    /// Launcher for a metadata-only probe: it never reuses the shared
    /// connection and never waits on a prompt.
    pub(super) fn probe(&self) -> Self {
        self.clone().with_ssh_options(None, true)
    }

    /// Program name for spawn diagnostics.
    pub(super) fn program_name(&self) -> String {
        self.program.to_string_lossy().into_owned()
    }
}

impl SshOptions {
    fn apply(&self, command: &mut Command, stdin: RemoteStdin) {
        if let Some(managed) = &self.managed {
            managed.apply(command);
        }
        if self.noninteractive {
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
        if matches!(stdin, RemoteStdin::Null) {
            // Windows OpenSSH can still read the console with stdin redirected to NUL.
            command.arg("-n");
        }
    }
}

/// One configured argument.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Arg {
    /// Text and placeholders that always expand to exactly one argv element.
    Template(ArgTemplate),
    /// Herdr's OpenSSH options for this call: zero or more argv elements.
    SshOptions,
}

impl Arg {
    fn parse(raw: &str) -> Result<Self, String> {
        let template = ArgTemplate::parse(raw)?;
        if template.contains(&Segment::SshOptions) {
            if template.0.len() == 1 {
                return Ok(Self::SshOptions);
            }
            return Err(format!(
                "{{{SSH_OPTIONS_PLACEHOLDER}}} expands to a list of options, \
                 so it must be an argument of its own"
            ));
        }
        Ok(Self::Template(template))
    }

    fn contains(&self, needle: &Segment) -> bool {
        match self {
            Self::Template(template) => template.contains(needle),
            Self::SshOptions => matches!(needle, Segment::SshOptions),
        }
    }
}

/// Text and placeholders for one argv element. Expansion never splits it into
/// more than one element, whatever the target or the remote command contain.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ArgTemplate(Vec<Segment>);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Target,
    Command,
    SshOptions,
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
                SSH_OPTIONS_PLACEHOLDER => Segment::SshOptions,
                _ => {
                    return Err(format!(
                        "unknown placeholder {{{name}}}; supported placeholders are \
                         {{{TARGET_PLACEHOLDER}}}, {{{COMMAND_PLACEHOLDER}}}, and \
                         {{{SSH_OPTIONS_PLACEHOLDER}}} (write {{{{ for a literal brace)"
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
                // Parsing turns a lone {ssh_options} into Arg::SshOptions and
                // rejects it anywhere else.
                Segment::SshOptions => {}
            }
        }
        OsString::from(expanded)
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
        RemoteLauncher::new(config).expect("valid launcher")
    }

    fn default_launcher() -> RemoteLauncher {
        launcher(&crate::config::RemoteCommandConfig::default())
    }

    fn managed_options() -> ManagedSshOptions {
        ManagedSshOptions {
            config_path: PathBuf::from("/tmp/herdr/config"),
            control_path: Some(PathBuf::from("/tmp/herdr/ctl")),
        }
    }

    #[test]
    fn the_default_launcher_is_plain_ssh() {
        let command =
            default_launcher().command("host", "herdr remote-client-bridge", RemoteStdin::Piped);

        assert_eq!(command.get_program(), "ssh");
        assert_eq!(
            argv(&command),
            vec!["-T", "host", "herdr remote-client-bridge"]
        );
    }

    #[test]
    fn ssh_refuses_stdin_for_commands_that_never_write_it() {
        let command = default_launcher().command("host", "uname -s", RemoteStdin::Null);

        assert_eq!(argv(&command), vec!["-n", "-T", "host", "uname -s"]);
    }

    #[test]
    fn ssh_options_expand_where_the_template_asks_for_them() {
        let command = default_launcher()
            .with_ssh_options(Some(managed_options()), true)
            .command("host", "true", RemoteStdin::Piped);
        let args = argv(&command);

        assert_eq!(
            &args[..8],
            [
                "-F",
                "/tmp/herdr/config",
                "-S",
                "/tmp/herdr/ctl",
                "-o",
                "ControlMaster=auto",
                "-o",
                "ControlPersist=yes",
            ]
        );
        for required in [
            "BatchMode=yes",
            "NumberOfPasswordPrompts=0",
            "StrictHostKeyChecking=yes",
            "ConnectTimeout=10",
            "ConnectionAttempts=1",
            "ServerAliveInterval=15",
            "ServerAliveCountMax=4",
        ] {
            assert!(args.iter().any(|arg| arg == required), "missing {required}");
        }
        assert_eq!(&args[args.len() - 3..], ["-T", "host", "true"]);
    }

    #[test]
    fn a_configured_program_asks_for_no_ssh_options() {
        let launcher = launcher(&openshell_config());
        assert!(!launcher.uses_ssh_options());

        // Even handed Herdr's OpenSSH options, a template that never asks for
        // them cannot receive them.
        let command = launcher
            .with_ssh_options(Some(managed_options()), true)
            .command("sandbox-1", "herdr remote-client-bridge", RemoteStdin::Null);

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
    }

    #[test]
    fn the_default_launcher_asks_for_ssh_options() {
        assert!(default_launcher().uses_ssh_options());
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
    fn probe_launcher_drops_connection_reuse_and_prompts() {
        let probe = default_launcher()
            .with_ssh_options(Some(managed_options()), false)
            .probe();

        let args = argv(&probe.command("host", "true", RemoteStdin::Piped));
        assert!(!args.iter().any(|arg| arg == "-F"));
        assert!(args.iter().any(|arg| arg == "BatchMode=yes"));

        // A template that never asks for ssh options probes unchanged.
        let program = launcher(&openshell_config());
        assert_eq!(
            argv(&program.probe().command("host", "true", RemoteStdin::Piped)),
            argv(&program.command("host", "true", RemoteStdin::Piped))
        );
    }

    #[test]
    fn managed_ssh_control_socket_has_a_shutdown_command() {
        let command = managed_options()
            .control_exit_command("host")
            .expect("managed control socket exits");

        assert_eq!(command.get_program(), "ssh");
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
        assert!(ManagedSshOptions {
            config_path: PathBuf::from("/tmp/herdr/config"),
            control_path: None,
        }
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
            (
                program_config("ssh", &["-o{ssh_options}", "{target}", "{command}"]),
                "must be an argument of its own",
            ),
        ] {
            let error = RemoteLauncher::new(&config).expect_err("rejected configuration");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(
                error.to_string().contains(expected),
                "expected {expected:?} in {error}"
            );
        }
    }

    #[test]
    fn unknown_placeholder_error_points_at_the_offending_argument() {
        let error = RemoteLauncher::new(&program_config(
            "openshell",
            &["{target}", "{oops}", "{command}"],
        ))
        .expect_err("rejected configuration");

        assert!(
            error.to_string().starts_with("remote.command.args[1]:"),
            "{error}"
        );
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

    /// Exec'ing a file this test just wrote races with any other test's fork:
    /// between fork and exec the child holds an inherited write handle and the
    /// exec fails with ETXTBSY. `cargo nextest` runs one test per process, so
    /// this only bites plain `cargo test`.
    fn spawn(command: &mut Command) -> std::process::Child {
        for _ in 0..50 {
            match command.spawn() {
                Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                result => return result.expect("spawn configured launcher"),
            }
        }
        panic!("the fake launcher stayed busy");
    }

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
            RemoteLauncher::new(&crate::config::RemoteCommandConfig {
                program: self.program(),
                args: [status, "exec", "-n", "{target}", "--", "{command}"]
                    .iter()
                    .map(|arg| (*arg).to_string())
                    .collect(),
            })
            .expect("valid launcher")
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

        let mut child = spawn(
            fake.launcher("0")
                .command("host name", &remote_command, RemoteStdin::Piped)
                .stdin(Stdio::null())
                .stdout(Stdio::null()),
        );
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
        let mut child = spawn(
            fake.launcher("0")
                .command("host", "herdr remote-client-bridge", RemoteStdin::Piped)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped()),
        );
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
        let status = spawn(
            fake.launcher("7")
                .command("host", "herdr remote-client-bridge", RemoteStdin::Piped)
                .stdin(Stdio::null())
                .stdout(Stdio::null()),
        )
        .wait()
        .expect("run configured launcher");

        assert_eq!(status.code(), Some(7));
    }

    #[test]
    fn missing_launcher_program_fails_at_spawn_like_a_missing_ssh() {
        let launcher = RemoteLauncher::new(&crate::config::RemoteCommandConfig {
            program: "/nonexistent/herdr-remote-launcher".to_string(),
            args: vec!["{target}".to_string(), "{command}".to_string()],
        })
        .expect("valid launcher");

        let error = launcher
            .command("host", "true", RemoteStdin::Piped)
            .spawn()
            .expect_err("missing program");

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
