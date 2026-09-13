#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CHECK_NOTICE: &str = "# Tailscale SSH requires an additional check.";
const CHECK_URL: &str = "# To authenticate, visit: https://login.tailscale.com/a/test";
const LATER_FAILURE: &str = "ssh: later setup probe failed";

struct TestCleanup {
    temp_dir: PathBuf,
    child: Option<Child>,
    reader: Option<thread::JoinHandle<()>>,
}

impl Drop for TestCleanup {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // The child leads a private process group and has not been reaped.
            // Kill its fake SSH descendants too, not just the Herdr launcher.
            // SAFETY: the negative PID targets only this test's process group.
            unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
            let _ = child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

fn wait_for_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for fake ssh");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn ssh_check_message_is_visible_while_authentication_waits() {
    check_authentication_output(false);
    check_authentication_output(true);
}

fn check_authentication_output(framed_shell: bool) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let temp_dir = std::env::temp_dir().join(format!(
        "herdr-remote-auth-test-{}-{nonce}",
        std::process::id()
    ));
    let mut cleanup = TestCleanup {
        temp_dir: temp_dir.clone(),
        child: None,
        reader: None,
    };
    fs::create_dir_all(&temp_dir).expect("create test directory");

    let started_path = temp_dir.join("ssh-started");
    let approval_path = temp_dir.join("ssh-approved");
    let advanced_path = temp_dir.join("ssh-advanced");
    let first_done_path = temp_dir.join("ssh-first-done");
    let ssh_path = temp_dir.join("ssh");
    fs::write(
        &ssh_path,
        format!(
            r#"#!/bin/sh
authenticate() {{
    : > "$FAKE_SSH_STARTED"
    printf '%s\n%s\n' '{CHECK_NOTICE}' '{CHECK_URL}' >&2
    while [ ! -e "$FAKE_SSH_APPROVED" ]; do
        /bin/sleep 0.01
    done
}}
if [ ! -e "$FAKE_SSH_FIRST_DONE" ]; then
    : > "$FAKE_SSH_FIRST_DONE"
    if [ "$FAKE_SSH_FRAMED" = 0 ]; then authenticate; fi
    /bin/cat >/dev/null
    printf 'login banner\nherdr-remote-output-ready:1\nLinux\nx86_64\n'
    exit 0
fi
if [ "$FAKE_SSH_FRAMED" = 1 ] && [ ! -e "$FAKE_SSH_STARTED" ]; then
    authenticate
fi
/bin/cat >/dev/null
: > "$FAKE_SSH_ADVANCED"
printf '%s\n' '{LATER_FAILURE}' >&2
exit 255
"#
        ),
    )
    .expect("write fake ssh");
    fs::set_permissions(&ssh_path, fs::Permissions::from_mode(0o755))
        .expect("make fake ssh executable");

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{inherited_path}", temp_dir.display());
    let child = Command::new(env!("CARGO_BIN_EXE_herdr"))
        .args(["--remote", "check-host"])
        .env("PATH", path)
        .env("FAKE_SSH_FRAMED", if framed_shell { "1" } else { "0" })
        .env("FAKE_SSH_STARTED", &started_path)
        .env("FAKE_SSH_APPROVED", &approval_path)
        .env("FAKE_SSH_ADVANCED", &advanced_path)
        .env("FAKE_SSH_FIRST_DONE", &first_done_path)
        .env("HERDR_CONFIG_PATH", temp_dir.join("config.toml"))
        .env_remove("HERDR_ENV")
        .env_remove("HERDR_SESSION")
        .env_remove("HERDR_SOCKET_PATH")
        .env_remove("HERDR_CLIENT_SOCKET_PATH")
        .env_remove("HERDR_REMOTE_BINARY")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("start remote attach");

    cleanup.child = Some(child);
    let child = cleanup.child.as_mut().expect("registered child");
    let stderr = child.stderr.take().expect("remote attach stderr");
    let (line_tx, line_rx) = mpsc::channel();
    cleanup.reader = Some(thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            if line_tx
                .send(line.expect("read remote attach stderr"))
                .is_err()
            {
                break;
            }
        }
    }));

    wait_for_file(&started_path, Duration::from_secs(2));
    let notice = line_rx.recv_timeout(Duration::from_secs(2));
    let url = line_rx.recv_timeout(Duration::from_secs(2));
    fs::write(&approval_path, b"approved").expect("release fake ssh approval");
    wait_for_file(&advanced_path, Duration::from_secs(2));

    let status = child.wait().expect("wait for remote attach");
    cleanup.child = None;
    cleanup
        .reader
        .take()
        .expect("registered stderr reader")
        .join()
        .expect("join stderr reader");
    let later_lines = line_rx.try_iter().collect::<Vec<_>>();

    assert_eq!(notice.as_deref(), Ok(CHECK_NOTICE));
    assert_eq!(url.as_deref(), Ok(CHECK_URL));
    assert!(
        later_lines.iter().any(|line| line == LATER_FAILURE),
        "later SSH stderr should also be visible: {later_lines:?}"
    );
    assert!(
        later_lines.iter().any(|line| {
            line.contains("error: remote binary discovery failed") && line.contains(LATER_FAILURE)
        }),
        "failed SSH stderr should remain in the contextual error: {later_lines:?}"
    );
    assert!(!status.success());
}

const LAUNCHER_FAILURE: &str = "fake-launcher: later setup probe failed";

#[test]
fn configured_remote_command_launches_the_program_instead_of_ssh() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let temp_dir = std::env::temp_dir().join(format!(
        "herdr-remote-launcher-test-{}-{nonce}",
        std::process::id()
    ));
    let mut cleanup = TestCleanup {
        temp_dir: temp_dir.clone(),
        child: None,
        reader: None,
    };
    fs::create_dir_all(&temp_dir).expect("create test directory");

    let argv_path = temp_dir.join("launcher-argv");
    let stdin_path = temp_dir.join("launcher-stdin");
    let ssh_ran_path = temp_dir.join("ssh-ran");
    let first_done_path = temp_dir.join("launcher-first-done");

    // A launcher that records the argv Herdr built, keeps stdin usable, and then
    // fails so the attach stops at the first setup probe.
    let launcher_path = temp_dir.join("fake-launcher");
    fs::write(
        &launcher_path,
        r#"#!/bin/sh
if [ ! -e "$FAKE_LAUNCHER_FIRST_DONE" ]; then
    : > "$FAKE_LAUNCHER_FIRST_DONE"
    for arg in "$@"; do
        printf '%s\n' "$arg" >> "$FAKE_LAUNCHER_ARGV"
    done
    /bin/cat > "$FAKE_LAUNCHER_STDIN"
    printf 'herdr-remote-output-ready:1\nLinux\nx86_64\n'
    exit 0
fi
/bin/cat >/dev/null
printf '%s\n' 'fake-launcher: later setup probe failed' >&2
exit 255
"#,
    )
    .expect("write fake launcher");
    fs::set_permissions(&launcher_path, fs::Permissions::from_mode(0o755))
        .expect("make fake launcher executable");

    // Any use of ssh at all is a failure for this configuration.
    let ssh_path = temp_dir.join("ssh");
    fs::write(&ssh_path, "#!/bin/sh\n: > \"$FAKE_SSH_RAN\"\nexit 255\n").expect("write fake ssh");
    fs::set_permissions(&ssh_path, fs::Permissions::from_mode(0o755))
        .expect("make fake ssh executable");

    let config_path = temp_dir.join("config.toml");
    fs::write(
        &config_path,
        format!(
            "onboarding = false\n\n[remote.command]\nprogram = {program:?}\nargs = [\"exec\", \"-n\", \"{{target}}\", \"--\", \"{{command}}\"]\n",
            program = launcher_path.display().to_string()
        ),
    )
    .expect("write herdr config");

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{inherited_path}", temp_dir.display());
    let child = Command::new(env!("CARGO_BIN_EXE_herdr"))
        .args(["--remote", "sandbox-target"])
        .env("PATH", path)
        .env("FAKE_LAUNCHER_ARGV", &argv_path)
        .env("FAKE_LAUNCHER_STDIN", &stdin_path)
        .env("FAKE_LAUNCHER_FIRST_DONE", &first_done_path)
        .env("FAKE_SSH_RAN", &ssh_ran_path)
        .env("HERDR_CONFIG_PATH", &config_path)
        .env_remove("HERDR_ENV")
        .env_remove("HERDR_SESSION")
        .env_remove("HERDR_SOCKET_PATH")
        .env_remove("HERDR_CLIENT_SOCKET_PATH")
        .env_remove("HERDR_REMOTE_BINARY")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("start remote attach");

    cleanup.child = Some(child);
    let child = cleanup.child.as_mut().expect("registered child");
    let stderr = child.stderr.take().expect("remote attach stderr");
    let (line_tx, line_rx) = mpsc::channel();
    cleanup.reader = Some(thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            if line_tx
                .send(line.expect("read remote attach stderr"))
                .is_err()
            {
                break;
            }
        }
    }));

    let status = child.wait().expect("wait for remote attach");
    cleanup.child = None;
    cleanup
        .reader
        .take()
        .expect("registered stderr reader")
        .join()
        .expect("join stderr reader");
    let lines = line_rx.try_iter().collect::<Vec<_>>();

    let argv = fs::read_to_string(&argv_path).expect("launcher recorded its argv");
    let argv = argv.lines().collect::<Vec<_>>();
    assert_eq!(
        argv,
        vec!["exec", "-n", "sandbox-target", "--", "/bin/sh -s"],
        "target and remote command must each stay one argv element"
    );
    let stdin = fs::read_to_string(&stdin_path).expect("launcher received stdin");
    assert!(
        stdin.contains("uname -s"),
        "setup commands still write the remote command's stdin: {stdin:?}"
    );
    assert!(
        !ssh_ran_path.exists(),
        "a configured remote command must replace ssh entirely"
    );
    assert!(
        lines.iter().any(|line| line.contains(LAUNCHER_FAILURE)),
        "launcher stderr should stay visible: {lines:?}"
    );
    assert!(!status.success());
}

#[test]
fn invalid_remote_command_configuration_fails_without_falling_back_to_ssh() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let temp_dir = std::env::temp_dir().join(format!(
        "herdr-remote-launcher-invalid-test-{}-{nonce}",
        std::process::id()
    ));
    let _cleanup = TestCleanup {
        temp_dir: temp_dir.clone(),
        child: None,
        reader: None,
    };
    fs::create_dir_all(&temp_dir).expect("create test directory");

    let ssh_ran_path = temp_dir.join("ssh-ran");
    let ssh_path = temp_dir.join("ssh");
    fs::write(&ssh_path, "#!/bin/sh\n: > \"$FAKE_SSH_RAN\"\nexit 255\n").expect("write fake ssh");
    fs::set_permissions(&ssh_path, fs::Permissions::from_mode(0o755))
        .expect("make fake ssh executable");

    let config_path = temp_dir.join("config.toml");
    fs::write(
        &config_path,
        "onboarding = false\n\n[remote.command]\nprogram = \"openshell\"\nargs = [\"sandbox\", \"exec\", \"-n\", \"{target}\"]\n",
    )
    .expect("write herdr config");

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{inherited_path}", temp_dir.display());
    let output = Command::new(env!("CARGO_BIN_EXE_herdr"))
        .args(["--remote", "sandbox-target"])
        .env("PATH", path)
        .env("FAKE_SSH_RAN", &ssh_ran_path)
        .env("HERDR_CONFIG_PATH", &config_path)
        .env_remove("HERDR_ENV")
        .env_remove("HERDR_SESSION")
        .env_remove("HERDR_SOCKET_PATH")
        .env_remove("HERDR_CLIENT_SOCKET_PATH")
        .env_remove("HERDR_REMOTE_BINARY")
        .stdin(Stdio::null())
        .process_group(0)
        .output()
        .expect("run remote attach");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("remote.command.args") && stderr.contains("{command}"),
        "invalid launcher configuration should name the missing placeholder: {stderr}"
    );
    assert!(
        !ssh_ran_path.exists(),
        "an invalid launcher must not silently fall back to ssh"
    );
}
