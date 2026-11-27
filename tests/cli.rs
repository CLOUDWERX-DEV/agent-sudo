//! The command line, end to end, with the real binary. Nothing here runs sudo for real: blocked commands stop before it, and installs go to a staging folder.
use std::path::PathBuf;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agent-sudo")).args(args).output().unwrap()
}

fn out(o: &Output) -> String { String::from_utf8_lossy(&o.stdout).into_owned() }
fn err(o: &Output) -> String { String::from_utf8_lossy(&o.stderr).into_owned() }

fn sandbox(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("agent-sudo-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn version_help_and_no_arguments() {
    assert_eq!(out(&run(&["--version"])).trim(), format!("agent-sudo {}", env!("CARGO_PKG_VERSION")));
    let h = run(&["--help"]);
    assert!(h.status.success());
    for word in ["--check", "--explain", "--rules", "--status", "--logs", "--install", "--uninstall", "asudo", "exit codes"] {
        assert!(out(&h).contains(word), "help lacks {word}");
    }
    let none = run(&[]);
    assert_eq!(none.status.code(), Some(1), "no arguments shows the help and exits 1");
    assert!(out(&none).contains("usage:"));
}

#[test]
fn check_and_explain() {
    let ok = run(&["--check", "pacman", "-S", "--noconfirm", "ripgrep"]);
    assert_eq!(ok.status.code(), Some(0));
    assert!(out(&ok).contains("ALLOWED"));
    let bad = run(&["--check", "rm", "-rf", "/"]);
    assert_eq!(bad.status.code(), Some(126));
    assert!(out(&bad).contains("BLOCKED"));
    let why = out(&run(&["--explain", "rm", "-rf", "/usr"]));
    assert!(why.contains("root-delete") && why.contains("disable_rules"), "{why}");
    assert_eq!(run(&["--check", "bash", "-c", "echo x > /etc/shadow"]).status.code(), Some(126));
    assert_eq!(run(&["--check"]).status.code(), Some(1), "--check needs a command");
}

#[test]
fn a_blocked_command_is_refused_before_sudo_is_ever_started() {
    for argv in [&["rm", "-rf", "/"][..], &["mkfs.ext4", "/dev/sda1"], &["dd", "if=/dev/zero", "of=/dev/nvme0n1"], &["--", "rm", "-rf", "/etc"], &["env", "x=1", "rm", "-rf", "/usr"]] {
        let o = run(argv);
        assert_eq!(o.status.code(), Some(126), "{argv:?}: {}", err(&o));
        assert!(err(&o).contains("BLOCKED"));
    }
}

#[test]
fn unknown_options_are_an_error_and_dash_dash_runs_a_dashed_command() {
    let o = run(&["--frobnicate"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("put -- before"));
}

#[test]
fn rules_lists_every_rule() {
    let r = out(&run(&["--rules"]));
    for name in ["root-delete", "disk-format", "disk-write", "auth-files", "recursive-perms", "move-critical", "find-delete", "fork-bomb", "unverifiable-delete", "power"] {
        assert!(r.contains(name), "{name}");
    }
}

#[test]
fn logs_shows_the_tail_and_a_missing_log_is_not_an_error() {
    let d = sandbox("logs");
    let log = d.join("a.log");
    std::fs::write(&log, (1..=30).map(|i| format!("line {i}\n")).collect::<String>()).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_agent-sudo")).args(["--logs", "3"]).env("AGENT_SUDO_LOG", &log).output().unwrap();
    assert_eq!(out(&o), "line 28\nline 29\nline 30\n");
    let d20 = Command::new(env!("CARGO_BIN_EXE_agent-sudo")).arg("--logs").env("AGENT_SUDO_LOG", &log).output().unwrap();
    assert_eq!(out(&d20).lines().count(), 20, "20 by default");
    let none = Command::new(env!("CARGO_BIN_EXE_agent-sudo")).arg("--logs").env("AGENT_SUDO_LOG", d.join("missing.log")).output().unwrap();
    assert_eq!(none.status.code(), Some(0));
    assert!(err(&none).contains("No log file"));
}

#[test]
fn completions() {
    for shell in ["fish", "bash", "zsh"] {
        let o = run(&["--completions", shell]);
        assert!(o.status.success() && out(&o).contains("agent-sudo"), "{shell}");
    }
    assert_eq!(run(&["--completions", "tcsh"]).status.code(), Some(2));
}

#[test]
fn install_and_uninstall_into_a_staging_folder() {
    let d = sandbox("stage");
    let root = d.to_str().unwrap();
    let o = run(&["--install", "--user", "ty", "--root", root]);
    assert!(o.status.success(), "{}", err(&o));
    let sudoers = std::fs::read_to_string(d.join("etc/sudoers.d/99-agent-sudo")).unwrap();
    assert!(sudoers.contains("ty ALL=(root) NOPASSWD: /usr/local/libexec/agent-sudo-backend"));
    assert!(d.join("usr/local/libexec/agent-sudo-backend").is_file());
    // the copy is the program itself, and acts as the root side when it is named agent-sudo-backend
    let be = Command::new(d.join("usr/local/libexec/agent-sudo-backend")).output().unwrap();
    assert_eq!(be.status.code(), Some(1), "as a non-root user the backend refuses: {}", err(&be));
    assert!(err(&be).contains("must run as root"));
    assert!(run(&["--uninstall", "--root", root]).status.success());
    assert!(!d.join("etc/sudoers.d/99-agent-sudo").exists());
    assert_eq!(run(&["--install", "--user", "root", "--root", root]).status.code(), Some(1), "never root");
    assert_eq!(run(&["--install", "--bogus"]).status.code(), Some(2));
}

#[test]
fn install_without_root_says_so() {
    if unsafe { libc::geteuid() } != 0 {
        let o = run(&["--install", "--user", "ty"]);
        assert_eq!(o.status.code(), Some(1));
        assert!(err(&o).contains("needs root"));
    }
}

#[test]
fn status_never_panics_and_always_names_the_version() {
    let o = run(&["--status"]);
    assert!(matches!(o.status.code(), Some(0) | Some(1)));
    assert!(out(&o).contains("agent-sudo "));
    assert!(out(&o).contains("health check"));
}
