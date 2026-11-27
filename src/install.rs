//! `agent-sudo --install` and `--uninstall`: put the two programs, the sudoers rule, the log and the completions where they belong.
//!
//! The one thing that makes this work is a sudoers file that lets ONE person run ONE root-owned program without a password. The program is a
//! copy of this binary, so it can't be changed by the person. `--root DIR` writes everything under DIR instead (for packagers and tests) and
//! skips the steps that need a real system (owners, visudo).
use std::ffi::CString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const BACKEND: &str = "/usr/local/libexec/agent-sudo-backend";
pub const FRONTEND: &str = "/usr/local/bin/agent-sudo";
pub const ASUDO: &str = "/usr/local/bin/asudo";
pub const SUDOERS: &str = "/etc/sudoers.d/99-agent-sudo";
pub const LOGROTATE: &str = "/etc/logrotate.d/agent-sudo";
pub const LOG: &str = "/var/log/agent-sudo.log";
const FISH: &str = "/usr/share/fish/vendor_completions.d/agent-sudo.fish";
const BASH: &str = "/usr/share/bash-completion/completions/agent-sudo";
const ZSH: &str = "/usr/share/zsh/site-functions/_agent-sudo";

#[derive(Default)]
pub struct Opts {
    pub user: Option<String>,
    pub root: Option<PathBuf>,
    pub purge: bool,
}

fn at(root: &Option<PathBuf>, path: &str) -> PathBuf {
    match root {
        Some(r) => r.join(path.trim_start_matches('/')),
        None => PathBuf::from(path),
    }
}

/// A login name: what useradd accepts, and never root.
pub fn valid_user(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 32 && name != "root"
        && chars.next().is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' || c == '$')
}

pub fn sudoers_text(user: &str) -> String {
    format!("# agent-sudo: lets {user} run one root-owned program without a password.\n# Remove it with `sudo agent-sudo --uninstall`.\n{user} ALL=(root) NOPASSWD: {BACKEND}\n")
}

pub fn logrotate_text() -> String {
    format!("{LOG} {{\n    weekly\n    rotate 8\n    compress\n    delaycompress\n    missingok\n    notifempty\n    create 0640 root adm\n}}\n")
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("can't create {}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, bytes).map_err(|e| format!("can't write {}: {e}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| format!("can't move {} into place: {e}", path.display()))
}

fn chown(path: &Path, uid: u32, gid: u32) {
    if let Ok(c) = CString::new(path.as_os_str().as_encoded_bytes()) {
        unsafe { libc::chown(c.as_ptr(), uid, gid) };
    }
}

/// (uid, gid) of an account, if it exists.
fn lookup(user: &str) -> Option<(u32, u32)> {
    let c = CString::new(user).ok()?;
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    (!pw.is_null()).then(|| unsafe { ((*pw).pw_uid, (*pw).pw_gid) })
}

/// Who is being given access: --user, else the person who ran sudo or pkexec.
fn target_user(o: &Opts) -> Result<String, String> {
    let name = o.user.clone()
        .or_else(|| std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty()))
        .or_else(|| {
            let uid: u32 = std::env::var("PKEXEC_UID").ok()?.parse().ok()?;
            let pw = unsafe { libc::getpwuid(uid) };
            (!pw.is_null()).then(|| unsafe { std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned() })
        })
        .ok_or("say who may use it: agent-sudo --install --user NAME (it won't guess, and it never grants root itself)")?;
    if !valid_user(&name) {
        return Err(format!("'{name}' isn't a usable account name (and root never needs this)"));
    }
    Ok(name)
}

fn need_root(o: &Opts) -> Result<(), String> {
    if o.root.is_none() && unsafe { libc::geteuid() } != 0 {
        return Err("this changes system files, so it needs root: sudo agent-sudo --install".into());
    }
    Ok(())
}

pub fn install(o: &Opts) -> Result<Vec<String>, String> {
    need_root(o)?;
    let user = target_user(o)?;
    let ids = if o.root.is_some() { None } else { Some(lookup(&user).ok_or_else(|| format!("there's no account called '{user}'"))?) };
    let me = std::fs::read(std::env::current_exe().map_err(|e| e.to_string())?).map_err(|e| format!("can't read myself: {e}"))?;
    let mut done = Vec::new();

    for (dest, name) in [(BACKEND, "backend"), (FRONTEND, "command")] {
        let p = at(&o.root, dest);
        write_atomic(&p, &me, 0o755)?;
        if o.root.is_none() { chown(&p, 0, 0); }
        done.push(format!("installed the {name}: {}", p.display()));
    }
    let asudo = at(&o.root, ASUDO);
    let _ = std::fs::remove_file(&asudo);
    std::os::unix::fs::symlink("agent-sudo", &asudo).map_err(|e| format!("can't link asudo: {e}"))?;
    done.push(format!("linked the short name: {}", asudo.display()));

    // the sudoers rule goes in last among the privileged bits, and only after visudo agrees it's valid
    let sudoers = at(&o.root, SUDOERS);
    let text = sudoers_text(&user);
    let tmp = sudoers.with_file_name(".agent-sudo.tmp");
    write_atomic(&tmp, text.as_bytes(), 0o440)?;
    if o.root.is_none() {
        let ok = Command::new("visudo").arg("-cf").arg(&tmp).output().map(|r| r.status.success()).unwrap_or(false);
        if !ok {
            let _ = std::fs::remove_file(&tmp);
            return Err("visudo says the sudoers rule isn't valid (or visudo is missing), so nothing was changed there".into());
        }
        chown(&tmp, 0, 0);
    }
    std::fs::rename(&tmp, &sudoers).map_err(|e| format!("can't move the sudoers rule into place: {e}"))?;
    done.push(format!("allowed {user} to run the backend without a password: {}", sudoers.display()));

    let log = at(&o.root, LOG);
    if !log.exists() {
        write_atomic(&log, b"", 0o640)?;
    }
    if let Some((_, gid)) = ids { chown(&log, 0, gid); }
    done.push(format!("audit log: {}", log.display()));
    write_atomic(&at(&o.root, LOGROTATE), logrotate_text().as_bytes(), 0o644)?;
    for (dest, text) in [(FISH, crate::completions::FISH), (BASH, crate::completions::BASH), (ZSH, crate::completions::ZSH)] {
        write_atomic(&at(&o.root, dest), text.as_bytes(), 0o644)?;
    }
    done.push("completions for fish, bash and zsh, and weekly log rotation".into());
    Ok(done)
}

pub fn uninstall(o: &Opts) -> Result<Vec<String>, String> {
    need_root(o)?;
    let mut done = Vec::new();
    let mut paths = vec![SUDOERS, BACKEND, FRONTEND, ASUDO, LOGROTATE, FISH, BASH, ZSH];
    if o.purge {
        paths.push(LOG);
    }
    for p in paths {
        let path = at(&o.root, p);
        if path.is_symlink() || path.exists() {
            std::fs::remove_file(&path).map_err(|e| format!("can't remove {}: {e}", path.display()))?;
            done.push(format!("removed {}", path.display()));
        }
    }
    if !o.purge {
        done.push(format!("kept the audit log ({LOG}); add --purge to delete it too"));
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("agent-sudo-inst-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn opts(root: &Path) -> Opts { Opts { user: Some("ty".into()), root: Some(root.to_path_buf()), purge: false } }

    #[test]
    fn account_names() {
        for ok in ["ty", "alice", "_svc", "a-b", "user1", "machine$"] {
            assert!(valid_user(ok), "{ok}");
        }
        for bad in ["", "root", "Ty", "1a", "a b", "a;b", "a\nb", "../x", "-x", &"a".repeat(33)] {
            assert!(!valid_user(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_sudoers_rule_names_one_user_and_one_program() {
        let t = sudoers_text("ty");
        let rule: Vec<&str> = t.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(rule, vec!["ty ALL=(root) NOPASSWD: /usr/local/libexec/agent-sudo-backend"]);
        assert!(!t.contains("ALL=(ALL)") && !t.contains("NOPASSWD: ALL"));
    }

    #[test]
    fn install_puts_everything_in_place_with_the_right_modes() {
        let root = stage("ok");
        let done = install(&opts(&root)).unwrap();
        assert!(done.len() >= 5);
        let mode = |p: &str| std::fs::metadata(at(&Some(root.clone()), p)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(BACKEND), 0o755);
        assert_eq!(mode(FRONTEND), 0o755);
        assert_eq!(mode(SUDOERS), 0o440);
        assert_eq!(mode(LOG), 0o640);
        assert!(at(&Some(root.clone()), ASUDO).is_symlink());
        assert_eq!(std::fs::read_link(at(&Some(root.clone()), ASUDO)).unwrap(), PathBuf::from("agent-sudo"));
        assert_eq!(std::fs::read_to_string(at(&Some(root.clone()), SUDOERS)).unwrap(), sudoers_text("ty"));
        assert!(std::fs::read_to_string(at(&Some(root.clone()), LOGROTATE)).unwrap().contains(LOG));
        for c in [FISH, BASH, ZSH] {
            assert!(at(&Some(root.clone()), c).is_file(), "{c}");
        }
        assert!(!std::fs::read_dir(at(&Some(root.clone()), "/etc/sudoers.d")).unwrap().flatten().any(|e| e.file_name().to_string_lossy().contains("tmp")), "no temp file left behind");
        install(&opts(&root)).unwrap(); // and running it again is fine
    }

    #[test]
    fn it_will_not_guess_or_grant_root() {
        let root = stage("nouser");
        let e = install(&Opts { user: None, root: Some(root.clone()), purge: false });
        if std::env::var("SUDO_USER").is_err() && std::env::var("PKEXEC_UID").is_err() {
            assert!(e.unwrap_err().contains("say who may use it"));
        }
        assert!(install(&Opts { user: Some("root".into()), root: Some(root.clone()), purge: false }).is_err());
        assert!(install(&Opts { user: Some("a b".into()), root: Some(root), purge: false }).is_err());
    }

    #[test]
    fn uninstall_removes_the_rule_first_and_keeps_the_log_unless_purged() {
        let root = stage("un");
        install(&opts(&root)).unwrap();
        let r = Some(root.clone());
        let done = uninstall(&opts(&root)).unwrap();
        assert!(done[0].contains("99-agent-sudo"), "the sudoers rule goes first: {done:?}");
        assert!(!at(&r, SUDOERS).exists() && !at(&r, BACKEND).exists() && !at(&r, FRONTEND).exists() && !at(&r, ASUDO).is_symlink());
        assert!(at(&r, LOG).exists(), "the audit trail is kept");
        uninstall(&Opts { purge: true, ..opts(&root) }).unwrap();
        assert!(!at(&r, LOG).exists());
        uninstall(&opts(&root)).unwrap(); // nothing left: still fine
    }

    #[test]
    fn without_root_or_a_staging_dir_it_refuses() {
        if unsafe { libc::geteuid() } != 0 {
            assert!(install(&Opts { user: Some("ty".into()), root: None, purge: false }).unwrap_err().contains("needs root"));
            assert!(uninstall(&Opts::default()).unwrap_err().contains("needs root"));
        }
    }
}
