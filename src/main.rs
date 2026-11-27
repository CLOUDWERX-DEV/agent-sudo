//! agent-sudo: run a command as root with no password prompt, behind guardrails and an audit log.
//!
//! It is one binary that plays two parts. Run as `agent-sudo` it checks your command and hands it to sudo. Installed as
//! `agent-sudo-backend` (root-owned, the only thing sudoers lets you run without a password) it checks again, logs, and runs it as root.
mod audit;
mod backend;
mod completions;
mod config;
mod guard;
mod install;
mod notify;

use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use config::CONFIG_PATH;
use install::BACKEND;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn help() -> String {
    format!(r#"agent-sudo {VERSION}: run commands as root without a password prompt, behind guardrails and an audit log.

usage:
  agent-sudo COMMAND [ARGS...]      run a command as root (also: asudo COMMAND ...)
  agent-sudo -- COMMAND [ARGS...]   the same, for a command that starts with a dash

  -c, --check COMMAND...    would the guardrails allow it? (runs nothing; exit 126 if not)
  -e, --explain COMMAND...  the same, and say which rule and why
  -r, --rules               list the guardrail rules
  -s, --status              check the installation (exit 0 only if the root runner works)
  -l, --logs [N]            show the last N audit log entries (default 20)
  -v, --version             show the version
  -h, --help                show this help

  --install [--user NAME]   install it (needs root): sudo agent-sudo --install --user NAME
  --uninstall [--purge]     remove it again (--purge deletes the audit log too)
  --completions SHELL       print completions for fish, bash or zsh

examples:
  agent-sudo pacman -S --noconfirm ripgrep
  agent-sudo systemctl restart NetworkManager
  agent-sudo tee /etc/systemd/system/app.service < app.service
  agent-sudo --explain rm -rf /usr

Commands that would wreck a machine (rm -rf /, mkfs on a disk, writing /etc/shadow...) are refused. Every run is written to {log}
and shows a desktop notification. exit codes: the command's own, 126 blocked, 127 not found or not installed.
It is a seatbelt, not a security boundary: read SECURITY.md.
"#, log = backend::LOG_PATH)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prog = Path::new(&args[0]).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let code = if prog == "agent-sudo-backend" { backend::main(&args[1..]) } else { frontend(&args[1..]) };
    std::process::exit(code);
}

fn cwd() -> std::path::PathBuf {
    std::env::current_dir().unwrap_or_else(|_| "/".into())
}

/// The policy to give early feedback with. The root side makes the real decision; this is only so a blocked command fails fast.
fn local_policy() -> guard::Policy {
    config::load_checked(Path::new(CONFIG_PATH)).map(|c| c.policy).unwrap_or_default()
}

fn frontend(args: &[String]) -> i32 {
    let Some(first) = args.first() else {
        print!("{}", help());
        return 1;
    };
    let rest = &args[1..];
    match first.as_str() {
        "-h" | "--help" => { print!("{}", help()); 0 }
        "-v" | "--version" => { println!("agent-sudo {VERSION}"); 0 }
        "-s" | "--status" => status(),
        "-l" | "--logs" => logs(rest.first().map(String::as_str)),
        "-r" | "--rules" => {
            for (name, what) in guard::RULES {
                println!("{name:<20} {what}");
            }
            0
        }
        "-c" | "--check" | "-e" | "--explain" => {
            if rest.is_empty() {
                eprintln!("[agent-sudo] ERROR: {first} needs a command to test.");
                return 1;
            }
            match guard::check(rest, &cwd(), &local_policy()) {
                Ok(()) => { println!("[agent-sudo] ALLOWED: Command passes all guardrail checks."); 0 }
                Err(v) => {
                    println!("[agent-sudo] BLOCKED by rule '{}': {}", v.rule, v.reason);
                    if matches!(first.as_str(), "-e" | "--explain") {
                        println!("[agent-sudo] To allow this kind of command, add \"{}\" to disable_rules in {CONFIG_PATH} (see SECURITY.md first).", v.rule);
                    }
                    126
                }
            }
        }
        "--install" | "--uninstall" => admin(first == "--install", rest),
        "--completions" => match rest.first().and_then(|s| completions::for_shell(s)) {
            Some(text) => { print!("{text}"); 0 }
            None => { eprintln!("usage: agent-sudo --completions fish|bash|zsh"); 2 }
        },
        "--" => run_command(rest),
        s if s.starts_with('-') && s.len() > 1 => {
            eprintln!("[agent-sudo] unknown option '{s}'. To run a command that starts with a dash, put -- before it.");
            2
        }
        _ => run_command(args),
    }
}

fn admin(installing: bool, rest: &[String]) -> i32 {
    let mut o = install::Opts::default();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--user" => o.user = it.next().cloned(),
            "--root" => o.root = it.next().map(Into::into),
            "--purge" => o.purge = true,
            other => { eprintln!("[agent-sudo] unknown option '{other}'"); return 2; }
        }
    }
    let result = if installing { install::install(&o) } else { install::uninstall(&o) };
    match result {
        Ok(lines) => {
            for l in lines {
                println!("  {l}");
            }
            if installing && o.root.is_none() {
                println!("\nDone. Try: agent-sudo --status");
            }
            0
        }
        Err(e) => { eprintln!("[agent-sudo] {e}"); 1 }
    }
}

fn run_command(argv: &[String]) -> i32 {
    if argv.is_empty() {
        eprintln!("[agent-sudo] ERROR: no command given.");
        return 1;
    }
    let dir = cwd();
    if let Err(v) = guard::check(argv, &dir, &local_policy()) {
        eprintln!("[agent-sudo] BLOCKED ({}): {}", v.rule, v.reason);
        eprintln!("[agent-sudo] Command: {}", audit::command_line(argv));
        return 126;
    }
    if !Path::new(BACKEND).is_file() {
        eprintln!("[agent-sudo] ERROR: the root runner {BACKEND} isn't installed. Run: sudo agent-sudo --install --user $USER");
        return 127;
    }
    // sudo -n never asks for a password: it either works or says so. exec keeps the terminal, the signals and the exit code exactly as they are.
    let err = Command::new("sudo").arg("-n").arg(BACKEND).arg(&dir).args(argv).exec();
    eprintln!("[agent-sudo] can't run sudo: {err}");
    127
}

fn logs(count: Option<&str>) -> i32 {
    let n: usize = count.and_then(|c| c.parse().ok()).unwrap_or(20);
    let path = std::env::var("AGENT_SUDO_LOG").unwrap_or_else(|_| backend::LOG_PATH.to_string()); // the log path can only be changed here, never on the root side
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let lines: Vec<&str> = text.lines().collect();
            for l in &lines[lines.len().saturating_sub(n)..] {
                println!("{l}");
            }
            0
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => { eprintln!("No log file found at {path}"); 0 }
        Err(e) => { eprintln!("can't read {path}: {e} (it's readable by root and your account's group)"); 1 }
    }
}

/// One line of the status report.
fn line(ok: bool, label: &str, detail: &str) {
    println!("  {} {label}{}", if ok { "ok " } else { "NO " }, if detail.is_empty() { String::new() } else { format!("   {detail}") });
}

fn status() -> i32 {
    println!("agent-sudo {VERSION}");
    // the root runner must be root's and nobody else's to change, or the whole thing is a hole
    let backend_ok = match std::fs::metadata(BACKEND) {
        Ok(m) if m.uid() == 0 && m.mode() & 0o022 == 0 => { line(true, "root runner", BACKEND); true }
        Ok(m) if m.uid() != 0 => { line(false, "root runner", &format!("{BACKEND} isn't owned by root: anyone who owns it could run anything as root")); false }
        Ok(_) => { line(false, "root runner", &format!("{BACKEND} is writable by someone other than root")); false }
        Err(_) => { line(false, "root runner", &format!("{BACKEND} is missing: sudo agent-sudo --install --user $USER")); false }
    };
    let listed = Command::new("sudo").args(["-n", "-l", BACKEND]).output().map(|o| o.status.success()).unwrap_or(false);
    let sudoers = std::fs::read_to_string(install::SUDOERS).ok().filter(|s| s.contains(BACKEND));
    // the rule's file is mode 0440 (root only), so an ordinary account usually can't read it: sudo saying yes is the real test
    match (&sudoers, listed) {
        (Some(_), _) => line(true, "sudoers rule", install::SUDOERS),
        (None, true) => line(true, "sudoers rule", &format!("{} (readable only by root; sudo allows it)", install::SUDOERS)),
        (None, false) => line(false, "sudoers rule", "not found: sudo agent-sudo --install --user $USER"),
    }
    line(listed, "sudo allows it without a password", "");
    let healthy = Command::new("sudo").args(["-n", BACKEND, "/", "--healthcheck"]).output().map(|o| o.status.success()).unwrap_or(false);
    line(healthy, "health check", if healthy { "the elevated runner works" } else { "can't run the backend without a password" });
    match std::fs::metadata(backend::LOG_PATH) {
        Ok(m) => line(true, "audit log", &format!("{} ({} bytes)", backend::LOG_PATH, m.len())),
        Err(_) => line(true, "audit log", "not created yet"),
    }
    match config::load_checked(Path::new(CONFIG_PATH)) {
        Ok(_) => line(true, "policy file", if Path::new(CONFIG_PATH).exists() { CONFIG_PATH } else { "none (the guardrails only)" }),
        Err(e) => line(false, "policy file", &e),
    }
    if healthy && backend_ok { 0 } else { 1 }
}
