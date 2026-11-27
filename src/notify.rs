//! A quiet desktop notification so a person sees every elevated command. Fire and forget: it never delays or fails a command.
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// Notification bodies are read as markup by most servers: escape what could be taken for it.
pub fn escape_markup(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Cut a command down to what fits a toast, on a character boundary.
pub fn summary(cmd: &str, max: usize) -> String {
    let one_line: String = cmd.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    if one_line.chars().count() <= max { one_line } else { format!("{}...", one_line.chars().take(max - 3).collect::<String>()) }
}

pub fn send(uid: u32, gid: u32, user: &str, command: &str, blocked: bool) {
    let bus = format!("/run/user/{uid}/bus");
    if !Path::new(&bus).exists() {
        return; // no graphical session for that user
    }
    let (title, icon) = if blocked { ("Elevated command blocked", "dialog-warning") } else { ("Elevated command running", "security-high") };
    let body = format!("{}: {}", escape_markup(user), escape_markup(&summary(command, 60)));
    let mut cmd = Command::new("notify-send");
    cmd.args(["-a", "agent-sudo", "-i", icon, "-u", if blocked { "normal" } else { "low" }, title, &body])
        .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={bus}"))
        .env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"))
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    // drop root completely (user, group and supplementary groups) before running anything as the person
    unsafe {
        cmd.pre_exec(move || {
            if libc::setgroups(1, &gid) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    if let Ok(mut child) = cmd.spawn() {
        std::thread::spawn(move || { let _ = child.wait(); });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markup_is_escaped() {
        assert_eq!(escape_markup("<b>x</b> & y"), "&lt;b&gt;x&lt;/b&gt; &amp; y");
    }

    #[test]
    fn long_commands_are_cut_on_a_character_boundary() {
        assert_eq!(summary("short", 60), "short");
        let long = "\u{e9}".repeat(100);
        let s = summary(&long, 60);
        assert_eq!(s.chars().count(), 60);
        assert!(s.ends_with("..."));
        assert_eq!(summary("a\nb\u{1b}c", 60), "a b c");
    }
}
