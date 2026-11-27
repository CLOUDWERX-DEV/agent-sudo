//! The audit log: one line per command, that nobody can forge by what they type.
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Escape everything that could fake a log line or fool a terminal reading it: newlines, tabs, ESC and other control characters.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f || (0x80..0xa0).contains(&(c as u32)) => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// An argument as a shell would need it, so the log shows exactly which words there were.
pub fn quote(arg: &str) -> String {
    if !arg.is_empty() && arg.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:,@%+".contains(c)) {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

pub fn command_line(argv: &[String]) -> String {
    argv.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
}

/// Local time as ISO 8601 with the offset, like `date --iso-8601=seconds`.
pub fn timestamp() -> String {
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&now, &mut tm);
        let mut buf = [0u8; 40];
        let n = libc::strftime(buf.as_mut_ptr().cast(), buf.len(), b"%Y-%m-%dT%H:%M:%S%z\0".as_ptr().cast(), &tm);
        let s = String::from_utf8_lossy(&buf[..n]).into_owned();
        if s.len() >= 5 { format!("{}:{}", &s[..s.len() - 2], &s[s.len() - 2..]) } else { s }
    }
}

pub struct Entry<'a> {
    pub outcome: &'a str, // ALLOW, BLOCKED or DONE
    pub user: &'a str,
    pub uid: u32,
    pub cwd: &'a str,
    pub extra: &'a str, // "rule=root-delete" or "exit=0 time=1.2s"
    pub command: &'a str,
}

pub fn format_line(ts: &str, e: &Entry) -> String {
    let extra = if e.extra.is_empty() { String::new() } else { format!("{} ", sanitize(e.extra)) };
    format!("{ts} [{}] user={} uid={} cwd={} {extra}cmd={}", e.outcome, sanitize(e.user), e.uid, sanitize(e.cwd), sanitize(e.command))
}

/// Append one line. A new file is made readable by root and the group that owns the account (mode 0640).
pub fn append(path: &Path, line: &str, group: Option<u32>) -> std::io::Result<()> {
    let existed = path.exists();
    let mut f = std::fs::OpenOptions::new().create(true).append(true).mode(0o640).open(path)?;
    if !existed {
        if let Some(gid) = group {
            let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap_or_default();
            unsafe { libc::chown(c.as_ptr(), 0, gid) };
        }
    }
    f.write_all(format!("{line}\n").as_bytes()) // one write, so concurrent runs don't interleave
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_a_command_contains_can_forge_a_log_line() {
        let evil = "ls\n2026-01-01T00:00:00+00:00 [ALLOW] user=root uid=0 cwd=/ cmd=fake";
        let line = format_line("T", &Entry { outcome: "ALLOW", user: "ty", uid: 1000, cwd: "/home/ty", extra: "", command: evil });
        assert_eq!(line.lines().count(), 1, "{line}");
        assert!(line.contains("\\n2026"));
        assert!(!sanitize("\u{1b}[31mred\u{1b}[0m").contains('\u{1b}'));
        assert_eq!(sanitize("a\tb\\c"), "a\\tb\\\\c");
        assert_eq!(sanitize("\u{0}\u{7f}"), "\\x00\\x7f");
        assert_eq!(sanitize("caf\u{e9}"), "caf\u{e9}", "ordinary non-ASCII text is kept");
    }

    #[test]
    fn quoting_keeps_the_words_apart() {
        assert_eq!(command_line(&["pacman".into(), "-S".into(), "ripgrep".into()]), "pacman -S ripgrep");
        assert_eq!(command_line(&["echo".into(), "two words".into(), "it's".into(), "".into()]), "echo 'two words' 'it'\\''s' ''");
    }

    #[test]
    fn timestamps_look_like_iso_8601_with_an_offset() {
        let t = timestamp();
        assert!(t.len() == 25 && t.as_bytes()[10] == b'T' && (t.as_bytes()[19] == b'+' || t.as_bytes()[19] == b'-') && t.as_bytes()[22] == b':', "{t}");
    }

    #[test]
    fn append_writes_whole_lines_and_makes_the_file_private() {
        let dir = std::env::temp_dir().join(format!("agent-sudo-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.log");
        let _ = std::fs::remove_file(&f);
        append(&f, "one", None).unwrap();
        append(&f, "two", None).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "one\ntwo\n");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o640 & !unsafe { libc::umask(0) as u32 } | 0o640 & 0o640);
    }
}
