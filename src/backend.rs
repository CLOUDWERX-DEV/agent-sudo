//! The root side: check the command again, write the audit log, run it, and write down how it ended.
//!
//! This is `agent-sudo-backend`, the one program sudoers lets a person run without a password. Everything it knows about the person comes from
//! what sudo sets (SUDO_USER, SUDO_UID, SUDO_GID), never from arguments or the environment the person chose.
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Instant;

use crate::audit::{self, Entry};
use crate::config::{self, Config, CONFIG_PATH};
use crate::guard;
use crate::notify;

pub const LOG_PATH: &str = "/var/log/agent-sudo.log";

pub struct Ctx<'a> {
    pub user: &'a str,
    pub uid: u32,
    pub gid: u32,
    pub log: &'a Path,
    pub config: Config,
}

static CHILD: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward(sig: libc::c_int) {
    let pid = CHILD.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe { libc::kill(pid, sig) };
    }
}

extern "C" fn ignore(_: libc::c_int) {}

fn log(ctx: &Ctx, outcome: &str, cwd: &str, extra: &str, command: &str) {
    let line = audit::format_line(&audit::timestamp(), &Entry { outcome, user: ctx.user, uid: ctx.uid, cwd, extra, command });
    let _ = audit::append(ctx.log, &line, Some(ctx.gid));
}

/// Check, log and run `argv` in `cwd`. Returns the exit code to give back (126 when blocked, 127 when it can't be found).
pub fn run(ctx: &Ctx, cwd: &str, argv: &[String]) -> i32 {
    let dir = if cwd.starts_with('/') && Path::new(cwd).is_dir() { cwd } else { "/" };
    let command = audit::command_line(argv);
    if let Err(v) = guard::check(argv, Path::new(dir), &ctx.config.policy) {
        log(ctx, "BLOCKED", dir, &format!("rule={}", v.rule), &command);
        eprintln!("[agent-sudo-backend] BLOCKED ({}): {}", v.rule, v.reason);
        if ctx.config.notify {
            notify::send(ctx.uid, ctx.gid, ctx.user, &command, true);
        }
        return 126;
    }
    log(ctx, "ALLOW", dir, "", &command);
    if ctx.config.notify {
        notify::send(ctx.uid, ctx.gid, ctx.user, &command, false);
    }
    let started = Instant::now();
    let child = Command::new(&argv[0]).args(&argv[1..]).current_dir(dir).spawn();
    let code = match child {
        Ok(mut c) => {
            CHILD.store(c.id() as i32, Ordering::SeqCst);
            unsafe {
                libc::signal(libc::SIGTERM, forward as *const () as usize);
                libc::signal(libc::SIGHUP, forward as *const () as usize);
                libc::signal(libc::SIGINT, ignore as *const () as usize); // a Ctrl-C reaches the command through the terminal; handlers (unlike SIG_IGN) reset on exec
                libc::signal(libc::SIGQUIT, ignore as *const () as usize);
            }
            match c.wait() {
                Ok(s) => s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0)),
                Err(_) => 1,
            }
        }
        Err(e) => {
            eprintln!("[agent-sudo-backend] can't run '{}': {e}", argv[0]);
            if e.kind() == std::io::ErrorKind::NotFound { 127 } else { 126 }
        }
    };
    log(ctx, "DONE", dir, &format!("exit={code} time={:.1}s", started.elapsed().as_secs_f64()), &command);
    code
}

fn env_u32(name: &str) -> Option<u32> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

/// The entry point when run as `agent-sudo-backend`: `agent-sudo-backend CWD COMMAND [ARGS...]` (or `CWD --healthcheck`).
pub fn main(args: &[String]) -> i32 {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("[agent-sudo-backend] FATAL: must run as root (it is started through sudo).");
        return 1;
    }
    let user = std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| "root".into());
    let (uid, gid) = (env_u32("SUDO_UID").unwrap_or(0), env_u32("SUDO_GID").unwrap_or(0));
    let Some((cwd, command)) = args.split_first() else {
        eprintln!("[agent-sudo-backend] ERROR: no command supplied.");
        return 1;
    };
    if command.is_empty() {
        eprintln!("[agent-sudo-backend] ERROR: no command supplied.");
        return 1;
    }
    if command[0] == "--healthcheck" {
        println!("OK: agent-sudo-backend healthy (UID=0, CALLER={user})");
        return 0;
    }
    let config = match config::load_checked(Path::new(CONFIG_PATH)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[agent-sudo-backend] REFUSING to run: {e}");
            return 1;
        }
    };
    run(&Ctx { user: &user, uid, gid, log: Path::new(LOG_PATH), config }, cwd, command)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("agent-sudo-be-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn ctx<'a>(log: &'a Path, config: Config) -> Ctx<'a> {
        Ctx { user: "ty", uid: 1000, gid: 1000, log, config: Config { notify: false, ..config } }
    }

    fn a(args: &[&str]) -> Vec<String> { args.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn an_allowed_command_runs_and_is_logged_start_and_end() {
        let d = tmp("ok");
        let log = d.join("a.log");
        let code = run(&ctx(&log, Config::default()), d.to_str().unwrap(), &a(&["sh", "-c", "exit 7"]));
        assert_eq!(code, 7, "the command's own exit code comes back");
        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("[ALLOW]") && lines[0].contains("user=ty") && lines[0].contains("uid=1000"));
        assert!(lines[1].contains("[DONE]") && lines[1].contains("exit=7") && lines[1].contains("time="));
        assert!(lines[0].contains(&format!("cwd={}", d.display())));
    }

    #[test]
    fn a_blocked_command_never_runs_and_says_which_rule() {
        let d = tmp("blocked");
        let log = d.join("a.log");
        let marker = d.join("ran");
        let code = run(&ctx(&log, Config::default()), "/", &a(&["sh", "-c", &format!("touch {}; rm -rf /etc", marker.display())]));
        assert_eq!(code, 126);
        assert!(!marker.exists(), "not even the harmless first half ran");
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("[BLOCKED]") && text.contains("rule=root-delete") && !text.contains("[ALLOW]") && !text.contains("[DONE]"));
    }

    #[test]
    fn the_command_runs_where_the_caller_was() {
        let d = tmp("cwd");
        let out = d.join("pwd.txt");
        run(&ctx(&d.join("a.log"), Config::default()), d.to_str().unwrap(), &a(&["sh", "-c", &format!("pwd > {}", out.display())]));
        assert_eq!(std::fs::read_to_string(out).unwrap().trim(), std::fs::canonicalize(&d).unwrap().to_string_lossy());
    }

    #[test]
    fn a_missing_program_is_127_and_a_bad_directory_falls_back_to_root() {
        let d = tmp("missing");
        assert_eq!(run(&ctx(&d.join("a.log"), Config::default()), "/", &a(&["definitely-not-a-program-xyz"])), 127);
        assert_eq!(run(&ctx(&d.join("a.log"), Config::default()), "relative/dir", &a(&["true"])), 0);
        assert!(std::fs::read_to_string(d.join("a.log")).unwrap().contains("cwd=/ "));
    }

    #[test]
    fn a_signal_death_is_128_plus_the_signal() {
        let d = tmp("sig");
        assert_eq!(run(&ctx(&d.join("a.log"), Config::default()), "/", &a(&["sh", "-c", "kill -9 $$"])), 137);
    }

    #[test]
    fn the_policy_applies_on_the_root_side() {
        let d = tmp("policy");
        let cfg = config::parse(r#"{"allow_programs":["true"]}"#).unwrap();
        assert_eq!(run(&ctx(&d.join("a.log"), cfg.clone()), "/", &a(&["true"])), 0);
        assert_eq!(run(&ctx(&d.join("a.log"), cfg), "/", &a(&["ls"])), 126);
    }

    #[test]
    fn what_was_typed_cannot_forge_the_log() {
        let d = tmp("forge");
        let log = d.join("a.log");
        run(&ctx(&log, Config::default()), "/", &a(&["echo", "x\n2026-01-01T00:00:00+00:00 [ALLOW] user=root uid=0 cwd=/ cmd=forged"]));
        let text = std::fs::read_to_string(&log).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(text.lines().all(|l| l.starts_with("20")));
    }
}
