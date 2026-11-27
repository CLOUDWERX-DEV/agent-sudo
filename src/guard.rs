//! The guardrails: refuse the commands that destroy a machine.
//!
//! They look at the command as the program will see it (its argument list), not at a string. They see through wrappers (`env`, `nice`,
//! `timeout`, `sudo`...), read what is inside `sh -c "..."`, follow redirections, and normalise every path (`..`, `//`, symlinks, `*`)
//! before comparing it. They are a seatbelt, not a wall: anything that can run arbitrary code as root (an interpreter, an editor with a shell
//! escape) can get around them. See SECURITY.md.
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

/// Why a command was refused: the rule's name (what `disable_rules` takes) and a sentence for the person.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub rule: &'static str,
    pub reason: String,
}

fn no<T>(rule: &'static str, reason: impl Into<String>) -> Result<T, Verdict> {
    Err(Verdict { rule, reason: reason.into() })
}

/// What the administrator configured (see config.rs).
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub disabled: HashSet<String>,
    /// When not empty, only these programs may run (every program in a chain: `env`, `sh`, the real one...).
    pub allow_programs: Vec<String>,
    pub deny_programs: Vec<String>,
}

impl Policy {
    fn on(&self, rule: &str) -> bool {
        !self.disabled.contains(rule)
    }
}

pub const RULES: &[(&str, &str)] = &[
    ("root-delete", "recursive deletion of /, or of a system directory such as /etc, /usr or /boot"),
    ("disk-format", "formatting, wiping or repartitioning a disk (mkfs, wipefs, sfdisk, blkdiscard...)"),
    ("disk-write", "writing straight onto a disk device (dd of=/dev/sda, > /dev/nvme0n1, tee /dev/sda...)"),
    ("auth-files", "changing /etc/shadow, /etc/passwd, /etc/group, /etc/sudoers or /etc/sudoers.d"),
    ("recursive-perms", "recursive chmod, chown or chattr on / or a system directory"),
    ("move-critical", "moving a system directory away"),
    ("find-delete", "find with -delete or -exec rm starting at / or a system directory"),
    ("fork-bomb", "a fork bomb"),
    ("unverifiable-delete", "a recursive delete whose path starts with a shell variable that could be empty"),
    ("power", "rebooting, powering off or halting the machine"),
];

const CRITICAL: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/usr",
    "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib32", "/usr/lib64", "/usr/share", "/usr/local", "/var", "/var/lib",
];

const AUTH_FILES: &[&str] = &["/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/group", "/etc/sudoers"];

/// Lexically clean a path: absolute against `cwd`, no `.`, `..` or `//`.
pub fn normalize(path: &str, cwd: &Path) -> PathBuf {
    let joined = if path.starts_with('/') { PathBuf::from(path) } else { cwd.join(path) };
    let mut out = PathBuf::from("/");
    for c in joined.components() {
        match c {
            Component::ParentDir => { out.pop(); }
            Component::Normal(n) => out.push(n),
            _ => {}
        }
    }
    out
}

/// The paths a word may mean: its lexical form and, if it exists, where symlinks really lead.
fn candidates(word: &str, cwd: &Path) -> Vec<PathBuf> {
    let lexical = normalize(word, cwd);
    let mut v = vec![lexical.clone()];
    if let Ok(real) = std::fs::canonicalize(&lexical) {
        if real != lexical {
            v.push(real);
        }
    }
    v
}

fn has_glob(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

/// Is this path, or what a glob at its end would reach into, critical? `/*`, `/etc/*` and `/etc/.` all count.
fn is_critical(word: &str, cwd: &Path) -> bool {
    let base = match word.rfind('/') {
        Some(i) if has_glob(&word[i + 1..]) => &word[..i.max(1)],
        None if has_glob(word) => ".",
        _ => word,
    };
    candidates(base, cwd).iter().any(|p| CRITICAL.iter().any(|c| p == Path::new(c)))
}

fn is_auth_file(word: &str, cwd: &Path) -> bool {
    candidates(word, cwd).iter().any(|p| AUTH_FILES.iter().any(|a| p == Path::new(a)) || p.starts_with("/etc/sudoers.d"))
}

/// A whole-disk or partition device: /dev/sda1, /dev/nvme0n1p2, /dev/vdb, /dev/mmcblk0, /dev/mapper/x, /dev/md0, /dev/dm-0, /dev/loop0.
fn is_block_device(word: &str, cwd: &Path) -> bool {
    candidates(word, cwd).iter().any(|p| {
        let s = p.to_string_lossy();
        let Some(rest) = s.strip_prefix("/dev/") else { return false };
        ["sd", "hd", "vd", "xvd", "nvme", "mmcblk", "md", "dm-", "loop", "mapper/", "disk/", "sr"].iter().any(|pre| rest.starts_with(pre) && rest.len() > pre.len())
    })
}

fn base(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

/// Short option letters present in a cluster like `-rf`. Long options are returned whole (`--recursive`).
fn has_flag(args: &[String], short: &[char], long: &[&str]) -> bool {
    args.iter().take_while(|a| a.as_str() != "--").any(|a| {
        if let Some(l) = a.strip_prefix("--") { long.contains(&l.split('=').next().unwrap_or("")) } else { a.starts_with('-') && a.len() > 1 && a[1..].chars().any(|c| short.contains(&c)) }
    })
}

/// The non-option words (everything after `--` counts as a word).
fn operands(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut dashdash = false;
    for a in args {
        if dashdash || !a.starts_with('-') || a == "-" {
            out.push(a.as_str());
        } else if a == "--" {
            dashdash = true;
        }
    }
    out
}

/// A wrapper: (name, options that take a value, leading positionals to skip after the options).
const WRAPPERS: &[(&str, &[&str], usize)] = &[
    ("env", &["-u", "-C", "-S", "--unset", "--chdir", "--split-string"], 0),
    ("nice", &["-n", "--adjustment"], 0),
    ("ionice", &["-c", "-n", "-p", "-P", "-u", "--class", "--classdata"], 0),
    ("nohup", &[], 0),
    ("setsid", &[], 0),
    ("time", &["-f", "-o", "--format", "--output"], 0),
    ("command", &[], 0),
    ("exec", &["-a"], 0),
    ("stdbuf", &["-i", "-o", "-e", "--input", "--output", "--error"], 0),
    ("timeout", &["-k", "-s", "--kill-after", "--signal"], 1),
    ("chrt", &[], 1),
    ("taskset", &[], 1),
    ("flock", &["-w", "-E", "--timeout", "--conflict-exit-code"], 1),
    ("sudo", &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "--user", "--group", "--chdir"], 0),
    ("doas", &["-u", "-C"], 0),
    ("pkexec", &["--user"], 0),
    ("runuser", &["-u", "-g", "-c", "-s", "-l"], 0),
    ("unshare", &[], 0),
    ("nsenter", &["-t", "-S", "-G", "-r", "-w"], 0),
    ("chroot", &["--userspec", "--groups"], 1),
];

/// If `argv` starts with a wrapper, the command it wraps.
fn unwrap_once(argv: &[String]) -> Option<&[String]> {
    let (name, opts, skip) = WRAPPERS.iter().find(|(n, _, _)| *n == base(&argv[0])).copied()?;
    let mut i = 1;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" { i += 1; break; }
        if name == "env" && a.contains('=') && !a.starts_with('-') { i += 1; continue; }
        if a.starts_with('-') && a.len() > 1 {
            i += 1 + usize::from(opts.contains(&a.as_str()) || (name == "sudo" && a == "-u"));
            continue;
        }
        break;
    }
    i += skip;
    (i < argv.len()).then(|| &argv[i..])
}

const SHELLS: &[&str] = &["sh", "bash", "zsh", "fish", "dash", "ksh", "ash", "csh", "tcsh"];

/// `sh -c "script"` (also `-lc`, `-ec`): the script.
fn shell_script(argv: &[String]) -> Option<&str> {
    if !SHELLS.contains(&base(&argv[0])) {
        return None;
    }
    let at = argv.iter().skip(1).position(|a| a.starts_with('-') && !a.starts_with("--") && a[1..].contains('c'))?;
    argv.get(at + 2).map(String::as_str)
}

/// One simple command found in a script: its words and where it redirects output.
#[derive(Debug, Default, PartialEq)]
struct Simple {
    words: Vec<String>,
    outputs: Vec<String>,
}

/// Split a shell script into simple commands, reading quotes and the operators `; && || | & ( ) { }` and newlines.
fn split_script(script: &str) -> Vec<Simple> {
    let (mut out, mut cur, mut word) = (Vec::new(), Simple::default(), String::new());
    let (mut in_word, mut redirect_next) = (false, false);
    let mut chars = script.chars().peekable();
    fn end_word(cur: &mut Simple, word: &mut String, in_word: &mut bool, redirect_next: &mut bool) {
        if *in_word {
            if *redirect_next { cur.outputs.push(std::mem::take(word)); *redirect_next = false; } else { cur.words.push(std::mem::take(word)); }
            *in_word = false;
        }
    }
    while let Some(c) = chars.next() {
        match c {
            '\'' => { in_word = true; for q in chars.by_ref() { if q == '\'' { break; } word.push(q); } }
            '"' => {
                in_word = true;
                while let Some(q) = chars.next() {
                    match q { '"' => break, '\\' => { if let Some(n) = chars.next() { word.push(n); } } _ => word.push(q) }
                }
            }
            '\\' => { in_word = true; if let Some(n) = chars.next() { word.push(n); } }
            c if c.is_whitespace() && c != '\n' => end_word(&mut cur, &mut word, &mut in_word, &mut redirect_next),
            ';' | '\n' | '|' | '&' | '(' | ')' | '{' | '}' if !(c == '&' && chars.peek() == Some(&'>')) => {
                end_word(&mut cur, &mut word, &mut in_word, &mut redirect_next);
                if matches!(c, '|' | '&') && chars.peek() == Some(&c) { chars.next(); }
                if !cur.words.is_empty() || !cur.outputs.is_empty() { out.push(std::mem::take(&mut cur)); }
            }
            '>' => {
                // 2>file, &>file, >>file, >|file: a digit just before is the descriptor, not a word
                if in_word && word.chars().all(|d| d.is_ascii_digit()) { word.clear(); in_word = false; }
                if chars.peek() == Some(&'>') || chars.peek() == Some(&'|') { chars.next(); }
                end_word(&mut cur, &mut word, &mut in_word, &mut redirect_next);
                redirect_next = true;
            }
            '&' => {} // the & of &>
            c => { in_word = true; word.push(c); }
        }
    }
    end_word(&mut cur, &mut word, &mut in_word, &mut redirect_next);
    if !cur.words.is_empty() || !cur.outputs.is_empty() { out.push(cur); }
    out
}

/// The text inside `$( ... )` and backticks in a script, so commands hidden there are checked too.
fn substitutions(script: &str) -> Vec<String> {
    let mut found = Vec::new();
    let bytes: Vec<char> = script.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '$' && bytes.get(i + 1) == Some(&'(') {
            let (mut depth, mut j) = (1, i + 2);
            while j < bytes.len() && depth > 0 {
                match bytes[j] { '(' => depth += 1, ')' => depth -= 1, _ => {} }
                j += 1;
            }
            found.push(bytes[i + 2..j.saturating_sub(1).max(i + 2)].iter().collect());
            i = j;
        } else if bytes[i] == '`' {
            let end = bytes[i + 1..].iter().position(|c| *c == '`').map_or(bytes.len(), |p| i + 1 + p);
            found.push(bytes[i + 1..end].iter().collect());
            i = end + 1;
        } else {
            i += 1;
        }
    }
    found
}

fn fork_bomb(s: &str) -> bool {
    let squashed: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    squashed.contains(":(){:|:&};:") || squashed.contains(":(){:|:&}")
}

fn check_script(script: &str, cwd: &Path, policy: &Policy, depth: usize) -> Result<(), Verdict> {
    if policy.on("fork-bomb") && fork_bomb(script) {
        return no("fork-bomb", "that is a fork bomb");
    }
    if depth > 6 {
        return no("unverifiable-delete", "shell commands nested too deeply to check");
    }
    for inner in substitutions(script) {
        check_script(&inner, cwd, policy, depth + 1)?;
    }
    for cmd in split_script(script) {
        for target in &cmd.outputs {
            redirect_target(target, cwd, policy)?;
        }
        if !cmd.words.is_empty() {
            check_inner(&cmd.words, cwd, policy, depth + 1, true)?;
        }
    }
    Ok(())
}

fn redirect_target(target: &str, cwd: &Path, policy: &Policy) -> Result<(), Verdict> {
    if policy.on("auth-files") && is_auth_file(target, cwd) {
        return no("auth-files", format!("writing to {target} is blocked: change accounts with the proper tools (useradd, passwd, visudo)"));
    }
    if policy.on("disk-write") && is_block_device(target, cwd) {
        return no("disk-write", format!("writing to the disk device {target} is blocked"));
    }
    Ok(())
}

/// Check a command (its argument list) against the guardrails and the administrator's policy. `cwd` is where it will run.
pub fn check(argv: &[String], cwd: &Path, policy: &Policy) -> Result<(), Verdict> {
    if argv.is_empty() {
        return Ok(());
    }
    if policy.on("fork-bomb") && fork_bomb(&argv.join(" ")) {
        return no("fork-bomb", "that is a fork bomb");
    }
    check_inner(argv, cwd, policy, 0, false)
}

fn check_inner(argv: &[String], cwd: &Path, policy: &Policy, depth: usize, in_script: bool) -> Result<(), Verdict> {
    if argv.is_empty() || depth > 12 {
        return Ok(());
    }
    // a leading VAR=value in a script command is an assignment, not the program
    let skip = if in_script { argv.iter().take_while(|w| w.contains('=') && !w.starts_with('/') && !w.starts_with('-') && !w.starts_with('=')).count() } else { 0 };
    let argv = &argv[skip..];
    if argv.is_empty() {
        return Ok(());
    }
    let program = base(&argv[0]).to_string();
    if policy.deny_programs.contains(&program) {
        return no("policy-deny", format!("{program} is on this machine's deny list"));
    }
    if !policy.allow_programs.is_empty() && !policy.allow_programs.contains(&program) {
        return no("policy-allow", format!("{program} isn't on this machine's allow list"));
    }
    if let Some(inner) = unwrap_once(argv) {
        return check_inner(inner, cwd, policy, depth + 1, in_script);
    }
    if let Some(script) = shell_script(argv) {
        return check_script(script, cwd, policy, depth + 1);
    }
    if let Some(i) = argv.iter().position(|a| a == "-c") {
        if program == "su" { if let Some(script) = argv.get(i + 1) { return check_script(script, cwd, policy, depth + 1); } }
    }
    if program == "eval" {
        return check_script(&argv[1..].join(" "), cwd, policy, depth + 1);
    }
    let args = &argv[1..];
    let ops = operands(args);

    // power
    if policy.on("power") {
        let sub = ops.first().copied().unwrap_or("");
        if matches!(program.as_str(), "reboot" | "poweroff" | "halt" | "shutdown") || (program == "systemctl" && matches!(sub, "reboot" | "poweroff" | "halt" | "kexec")) || (matches!(program.as_str(), "init" | "telinit") && matches!(sub, "0" | "6")) {
            return no("power", format!("{} would take the machine down: do it yourself, or add \"power\" to disable_rules", format!("{program} {sub}").trim()));
        }
    }
    match program.as_str() {
        "rm" => check_rm(args, &ops, cwd, policy),
        "chmod" | "chown" | "chgrp" | "chattr" => {
            if policy.on("recursive-perms") && has_flag(args, &['R'], &["recursive"]) {
                let targets = if program == "chattr" { &ops[..] } else { ops.get(1..).unwrap_or(&[]) };
                if let Some(t) = targets.iter().find(|t| is_critical(t, cwd)) {
                    return no("recursive-perms", format!("recursive {program} on {t} would break the system"));
                }
            }
            check_auth_targets(&program, &ops, cwd, policy)
        }
        "mv" => {
            if policy.on("move-critical") {
                if let Some(s) = ops.iter().take(ops.len().saturating_sub(1)).find(|s| is_critical(s, cwd) && !has_glob(s)) {
                    return no("move-critical", format!("moving {s} away would break the system"));
                }
            }
            check_auth_targets(&program, &ops, cwd, policy)
        }
        "find" => {
            if policy.on("find-delete") {
                let starts: Vec<&str> = args.iter().map(String::as_str).take_while(|a| !a.starts_with('-') && *a != "(" && *a != "!").collect();
                let deletes = args.iter().any(|a| a == "-delete") || args.windows(2).any(|w| (w[0] == "-exec" || w[0] == "-execdir" || w[0] == "-ok") && base(&w[1]) == "rm");
                let from_critical = starts.iter().any(|s| is_critical(s, cwd)) || (starts.is_empty() && is_critical(".", cwd));
                if deletes && from_critical {
                    return no("find-delete", "find would delete starting from a system directory");
                }
            }
            Ok(())
        }
        "dd" => {
            for a in args {
                if let Some(of) = a.strip_prefix("of=") {
                    if policy.on("disk-write") && is_block_device(of, cwd) {
                        return no("disk-write", format!("dd onto the disk device {of} is blocked"));
                    }
                    redirect_target(of, cwd, policy)?;
                }
            }
            Ok(())
        }
        "tee" | "truncate" | "shred" | "ln" | "install" | "cp" | "sed" | "perl" => {
            if program == "tee" || program == "shred" || program == "truncate" {
                if let Some(d) = ops.iter().find(|o| is_block_device(o, cwd)) {
                    if policy.on("disk-write") {
                        return no("disk-write", format!("writing to the disk device {d} is blocked"));
                    }
                }
            }
            if program == "cp" || program == "install" {
                // only where it copies TO matters: copying /etc/shadow somewhere for a backup is fine
                let dest = args.iter().position(|a| a == "-t" || a == "--target-directory").and_then(|i| args.get(i + 1).map(String::as_str)).or_else(|| ops.last().copied());
                if let Some(d) = dest {
                    if policy.on("auth-files") && is_auth_file(d, cwd) { return no("auth-files", format!("writing to {d} is blocked")); }
                    if policy.on("disk-write") && is_block_device(d, cwd) { return no("disk-write", format!("writing to the disk device {d} is blocked")); }
                }
                return Ok(());
            }
            if program == "sed" && !has_flag(args, &['i'], &["in-place"]) { return Ok(()); }
            if program == "perl" && !has_flag(args, &['i'], &[]) { return Ok(()); }
            check_auth_targets(&program, &ops, cwd, policy)
        }
        p if p.starts_with("mkfs") || matches!(p, "mke2fs" | "mkswap" | "blkdiscard") => {
            let dev = ops.iter().find(|o| is_block_device(o, cwd));
            match dev {
                Some(d) if policy.on("disk-format") => no("disk-format", format!("{p} on {d} would destroy its data")),
                _ => Ok(()),
            }
        }
        "wipefs" | "sfdisk" | "sgdisk" | "gdisk" | "fdisk" | "cfdisk" | "parted" | "cryptsetup" | "pvcreate" | "dmsetup" => {
            let read_only = has_flag(args, &['n', 'l', 'p', 's'], &["no-act", "list", "print", "show-size"]) && program != "cryptsetup" || ops.contains(&"print") || ops.contains(&"status") || ops.contains(&"isLuks");
            let dev = ops.iter().find(|o| is_block_device(o, cwd));
            match dev {
                Some(d) if policy.on("disk-format") && !read_only => no("disk-format", format!("{program} on {d} would change or destroy its partitions or data")),
                _ => Ok(()),
            }
        }
        _ => Ok(()),
    }
}

fn check_rm(args: &[String], ops: &[&str], cwd: &Path, policy: &Policy) -> Result<(), Verdict> {
    if policy.on("root-delete") && args.iter().any(|a| a == "--no-preserve-root") {
        return no("root-delete", "rm --no-preserve-root is blocked");
    }
    let recursive = has_flag(args, &['r', 'R'], &["recursive"]);
    if recursive {
        if policy.on("root-delete") {
            if let Some(t) = ops.iter().find(|t| is_critical(t, cwd)) {
                return no("root-delete", format!("recursive delete of {t} would destroy the system"));
            }
        }
        if policy.on("unverifiable-delete") {
            if let Some(t) = ops.iter().find(|t| t.starts_with('$') || t.starts_with('`')) {
                return no("unverifiable-delete", format!("{t} starts with a shell variable: if it's empty this deletes from /"));
            }
        }
    }
    check_auth_targets("rm", ops, cwd, policy)
}

/// Programs that change, move or remove a file: none may touch the account and sudo files.
fn check_auth_targets(program: &str, ops: &[&str], cwd: &Path, policy: &Policy) -> Result<(), Verdict> {
    if policy.on("auth-files") {
        if let Some(t) = ops.iter().find(|t| is_auth_file(t, cwd)) {
            return no("auth-files", format!("{program} on {t} is blocked: change accounts with the proper tools (useradd, passwd, visudo)"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(s: &str) -> Vec<String> { s.split_whitespace().map(String::from).collect() }

    fn verdict(argv: &[&str]) -> Result<(), Verdict> {
        check(&argv.iter().map(|s| s.to_string()).collect::<Vec<_>>(), Path::new("/home/user/work"), &Policy::default())
    }

    fn blocked(argv: &[&str], rule: &str) {
        match verdict(argv) {
            Err(v) => assert_eq!(v.rule, rule, "{argv:?}: {}", v.reason),
            Ok(()) => panic!("{argv:?} should be blocked by {rule}"),
        }
    }

    fn allowed(argv: &[&str]) {
        if let Err(v) = verdict(argv) { panic!("{argv:?} should be allowed, but {}: {}", v.rule, v.reason) }
    }

    #[test]
    fn recursive_deletes_of_the_system() {
        for argv in [&["rm", "-rf", "/"][..], &["rm", "-rf", "/*"], &["rm", "-r", "-f", "/"], &["rm", "-fr", "/"], &["rm", "-Rf", "/etc"], &["rm", "--recursive", "--force", "/usr"],
            &["rm", "-rf", "/boot"], &["rm", "-rf", "/bin"], &["rm", "-rf", "/etc/"], &["rm", "-rf", "//etc//"], &["rm", "-rf", "/etc/."], &["rm", "-rf", "/usr/../etc"],
            &["rm", "-rf", "/usr/*"], &["rm", "-rf", "/var/lib"], &["rm", "-rf", "/home"], &["rm", "-rf", "--", "/"], &["rm", "-rf", "/tmp/x", "/etc"], &["rm", "-rf", "../../.."],
            &["rm", "-rf", "/usr/lib"], &["rm", "-ri", "/"]] {
            blocked(argv, "root-delete");
        }
        blocked(&["rm", "-rf", "--no-preserve-root", "/tmp/x"], "root-delete");
    }

    #[test]
    fn safe_deletes_are_allowed() {
        for argv in [&["rm", "-rf", "/tmp/my-temp-dir"][..], &["rm", "-rf", "/var/tmp/x"], &["rm", "-rf", "/opt/app"], &["rm", "file.txt"], &["rm", "-f", "/etc/myapp.conf"],
            &["rm", "-rf", "/usr/local/share/foo"], &["rm", "-rf", "./build"], &["rm", "-r", "/home/user/old"], &["rm", "-rf", "/etc/myapp/*"], &["rm", "-rf", "/var/cache/pacman/pkg/*"]] {
            allowed(argv);
        }
    }

    #[test]
    fn relative_paths_are_resolved_against_where_it_runs() {
        let at = |cwd: &str, argv: &[&str]| check(&argv.iter().map(|s| s.to_string()).collect::<Vec<_>>(), Path::new(cwd), &Policy::default());
        assert!(at("/", &["rm", "-rf", "etc"]).is_err());
        assert!(at("/", &["rm", "-rf", "*"]).is_err(), "* in / is everything");
        assert!(at("/etc", &["rm", "-rf", "."]).is_err());
        assert!(at("/home/user/work", &["rm", "-rf", "build"]).is_ok());
        assert!(at("/tmp/x", &["rm", "-rf", "../../etc"]).is_err());
    }

    #[test]
    fn a_symlink_to_a_critical_directory_is_followed() {
        let dir = std::env::temp_dir().join(format!("agent-sudo-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink("/etc", dir.join("innocent")).unwrap();
        let target = dir.join("innocent").to_string_lossy().into_owned();
        assert!(check(&["rm".into(), "-rf".into(), target], Path::new("/"), &Policy::default()).is_err());
    }

    #[test]
    fn disks() {
        blocked(&["mkfs.ext4", "/dev/nvme0n1p1"], "disk-format");
        blocked(&["mkfs", "-t", "ext4", "/dev/sda"], "disk-format");
        blocked(&["wipefs", "-a", "/dev/sda"], "disk-format");
        blocked(&["sfdisk", "/dev/sda"], "disk-format");
        blocked(&["parted", "/dev/sda", "mklabel", "gpt"], "disk-format");
        blocked(&["blkdiscard", "/dev/nvme0n1"], "disk-format");
        blocked(&["cryptsetup", "luksFormat", "/dev/sdb1"], "disk-format");
        blocked(&["mkswap", "/dev/mapper/vg-root"], "disk-format");
        blocked(&["dd", "if=/dev/zero", "of=/dev/sda", "bs=1M"], "disk-write");
        blocked(&["dd", "if=/dev/urandom", "of=/dev/nvme0n1"], "disk-write");
        blocked(&["dd", "if=x", "of=/dev/mmcblk0p1"], "disk-write");
        blocked(&["tee", "/dev/sda"], "disk-write");
        blocked(&["shred", "-n", "3", "/dev/sdb"], "disk-write");
        blocked(&["cp", "image.img", "/dev/sdb"], "disk-write");
    }

    #[test]
    fn reading_and_listing_disks_is_fine() {
        for argv in [&["fdisk", "-l", "/dev/sda"][..], &["wipefs", "-n", "/dev/sda"], &["parted", "/dev/sda", "print"], &["dd", "if=/dev/sda", "of=/tmp/backup.img"], &["cat", "/dev/sda"],
            &["cp", "/dev/sda", "/tmp/x"], &["blkid", "/dev/sda1"], &["lsblk", "/dev/sda"], &["mkfs.ext4", "/tmp/disk.img"], &["dd", "if=/dev/zero", "of=/tmp/file", "bs=1M", "count=1"], &["sfdisk", "-l", "/dev/sda"]] {
            allowed(argv);
        }
    }

    #[test]
    fn account_and_sudo_files() {
        for argv in [&["rm", "/etc/shadow"][..], &["rm", "-f", "/etc/passwd"], &["tee", "/etc/shadow"], &["tee", "-a", "/etc/sudoers"], &["truncate", "-s", "0", "/etc/passwd"], &["mv", "x", "/etc/passwd"],
            &["cp", "x", "/etc/shadow"], &["sed", "-i", "s/x/y/", "/etc/passwd"], &["chmod", "777", "/etc/shadow"], &["chown", "user", "/etc/sudoers"], &["ln", "-sf", "/dev/null", "/etc/shadow"],
            &["dd", "if=x", "of=/etc/passwd"], &["tee", "/etc/sudoers.d/evil"], &["rm", "/etc/sudoers.d/99-agent-sudo"], &["install", "x", "/etc/group"], &["perl", "-pi", "-e", "x", "/etc/passwd"]] {
            blocked(argv, "auth-files");
        }
    }

    #[test]
    fn reading_account_files_and_editing_others_is_fine() {
        for argv in [&["cat", "/etc/shadow"][..], &["cp", "/etc/shadow", "/tmp/backup"], &["sed", "s/x/y/", "/etc/passwd"], &["grep", "root", "/etc/passwd"], &["visudo", "-c"], &["tee", "/etc/systemd/system/app.service"],
            &["install", "-m", "644", "a.conf", "/etc/app.conf"], &["sed", "-i", "s/a/b/", "/etc/app.conf"], &["useradd", "bob"]] {
            allowed(argv);
        }
    }

    #[test]
    fn shell_scripts_are_read_not_just_matched() {
        blocked(&["bash", "-c", "echo hacked > /etc/shadow"], "auth-files");
        blocked(&["sh", "-c", "echo x >> /etc/passwd"], "auth-files");
        blocked(&["bash", "-lc", "cat foo 2>/dev/null; rm -rf /"], "root-delete");
        blocked(&["sh", "-c", "cd /tmp && rm -rf /usr"], "root-delete");
        blocked(&["sh", "-c", "true || rm -rf /etc"], "root-delete");
        blocked(&["bash", "-c", "ls | xargs echo; dd if=/dev/zero of=/dev/sda"], "disk-write");
        blocked(&["bash", "-c", "echo x > /dev/sda"], "disk-write");
        blocked(&["bash", "-c", "echo $(rm -rf /usr)"], "root-delete");
        blocked(&["bash", "-c", "echo `rm -rf /boot`"], "root-delete");
        blocked(&["bash", "-c", "rm -rf \"/etc\""], "root-delete");
        blocked(&["bash", "-c", "rm -rf '/usr'"], "root-delete");
        blocked(&["bash", "-c", "bash -c 'rm -rf /'"], "root-delete");
        blocked(&["su", "-c", "rm -rf /", "root"], "root-delete");
        blocked(&["bash", "-c", "rm -rf $TARGET/"], "unverifiable-delete");
        blocked(&["bash", "-c", "mkfs.ext4 /dev/sda1"], "disk-format");
        allowed(&["bash", "-c", "echo hello > /tmp/out && ls /etc"]);
        allowed(&["sh", "-c", "cd /tmp && rm -rf build && mkdir build"]);
        allowed(&["bash", "-c", "echo $(date) >> /var/log/mine.log"]);
        allowed(&["bash", "-c", "cat /etc/passwd | grep root > /tmp/roots"]);
        allowed(&["bash", "-c", "ls 2>&1 > /tmp/ls.out"]);
    }

    #[test]
    fn wrappers_do_not_hide_anything() {
        blocked(&["env", "FOO=1", "rm", "-rf", "/"], "root-delete");
        blocked(&["nice", "-n", "5", "rm", "-rf", "/etc"], "root-delete");
        blocked(&["timeout", "30", "rm", "-rf", "/usr"], "root-delete");
        blocked(&["nohup", "rm", "-rf", "/"], "root-delete");
        blocked(&["sudo", "-u", "root", "rm", "-rf", "/"], "root-delete");
        blocked(&["env", "-i", "PATH=/bin", "bash", "-c", "rm -rf /"], "root-delete");
        blocked(&["ionice", "-c", "3", "nice", "timeout", "5", "dd", "if=x", "of=/dev/sda"], "disk-write");
        blocked(&["/usr/bin/rm", "-rf", "/"], "root-delete");
        blocked(&["stdbuf", "-oL", "mkfs.ext4", "/dev/sda"], "disk-format");
        blocked(&["flock", "/tmp/lock", "rm", "-rf", "/"], "root-delete");
        allowed(&["env", "FOO=1", "ls", "/"]);
        allowed(&["timeout", "30", "pacman", "-Syu", "--noconfirm"]);
    }

    #[test]
    fn other_ways_to_wreck_a_system() {
        blocked(&["chmod", "-R", "777", "/"], "recursive-perms");
        blocked(&["chown", "-R", "user", "/etc"], "recursive-perms");
        blocked(&["chmod", "-R", "000", "/usr"], "recursive-perms");
        blocked(&["mv", "/etc", "/tmp/etc"], "move-critical");
        blocked(&["mv", "/usr", "/dev/null"], "move-critical");
        blocked(&["find", "/", "-delete"], "find-delete");
        blocked(&["find", "/etc", "-exec", "rm", "-rf", "{}", ";"], "find-delete");
        allowed(&["chmod", "-R", "755", "/opt/app"]);
        allowed(&["chown", "-R", "user", "/home/user/project"]);
        allowed(&["mv", "/tmp/a", "/etc/app.conf"]);
        allowed(&["find", "/tmp", "-name", "*.log", "-delete"]);
        allowed(&["find", "/etc", "-name", "*.pacnew"]);
    }

    #[test]
    fn fork_bombs() {
        blocked(&[":(){ :|:& };:"], "fork-bomb");
        blocked(&[":(){:|:&};:"], "fork-bomb");
        blocked(&["bash", "-c", ":(){ :|:& };:"], "fork-bomb");
        blocked(&["sh", "-c", ": ( ) { : | : & } ; :"], "fork-bomb");
    }

    #[test]
    fn power_is_blocked_unless_allowed() {
        for argv in [&["reboot"][..], &["poweroff"], &["shutdown", "-h", "now"], &["systemctl", "reboot"], &["systemctl", "poweroff"], &["halt"], &["init", "0"], &["bash", "-c", "reboot"]] {
            blocked(argv, "power");
        }
        allowed(&["systemctl", "restart", "NetworkManager"]);
        allowed(&["systemctl", "status", "reboot.target"]);
        let policy = Policy { disabled: ["power".to_string()].into(), ..Default::default() };
        assert!(check(&cmd("reboot"), Path::new("/"), &policy).is_ok());
    }

    #[test]
    fn ordinary_admin_work_goes_through() {
        for argv in [&["pacman", "-S", "--noconfirm", "ripgrep"][..], &["systemctl", "restart", "NetworkManager"], &["mkdir", "-p", "/opt/custom-app"], &["chmod", "0755", "/opt/custom-app"],
            &["tee", "/etc/systemd/system/myapp.service"], &["reflector", "--latest", "5", "--save", "/etc/pacman.d/mirrorlist"], &["snapper", "create", "-d", "Pre-update state"],
            &["journalctl", "-u", "sshd"], &["apt-get", "install", "-y", "curl"], &["useradd", "-m", "bob"], &["ufw", "allow", "22"], &["whoami"], &["id"], &["ls", "-la", "/root"]] {
            allowed(argv);
        }
    }

    #[test]
    fn rules_can_be_switched_off_one_at_a_time() {
        let off = |rule: &str| Policy { disabled: [rule.to_string()].into(), ..Default::default() };
        assert!(check(&cmd("rm -rf /usr"), Path::new("/"), &off("root-delete")).is_ok());
        assert!(check(&cmd("rm -rf /usr"), Path::new("/"), &off("power")).is_err());
        assert!(check(&cmd("dd if=x of=/dev/sda"), Path::new("/"), &off("disk-write")).is_ok());
    }

    #[test]
    fn allow_and_deny_lists() {
        let allow = Policy { allow_programs: vec!["pacman".into(), "systemctl".into()], ..Default::default() };
        assert!(check(&cmd("pacman -S x"), Path::new("/"), &allow).is_ok());
        assert_eq!(check(&cmd("ls /"), Path::new("/"), &allow).unwrap_err().rule, "policy-allow");
        assert!(check(&["bash".into(), "-c".into(), "pacman -S x".into()], Path::new("/"), &allow).is_err(), "a shell has to be allowed too");
        assert!(check(&cmd("env pacman -S x"), Path::new("/"), &allow).is_err(), "so does every wrapper");
        let deny = Policy { deny_programs: vec!["curl".into()], ..Default::default() };
        assert_eq!(check(&cmd("curl http://x"), Path::new("/"), &deny).unwrap_err().rule, "policy-deny");
        assert!(check(&["bash".into(), "-c".into(), "echo hi; curl x".into()], Path::new("/"), &deny).is_err(), "inside a script too");
    }

    #[test]
    fn every_rule_in_the_table_exists_and_is_described() {
        for (name, why) in RULES {
            assert!(!name.is_empty() && !why.is_empty());
        }
        assert_eq!(RULES.len(), 10);
    }

    #[test]
    fn odd_input_never_panics() {
        let words = ["rm", "-rf", "/", "*", "bash", "-c", "$(", ")", "`", "'", "\"", ">", ">>", "&&", ";", "|", "\\", "", " ", "dd", "of=/dev/sda", "env", "--", "-", "\u{e9}", "\u{0}", "a=b", "$X/*", "{", "}", "(", "2>", "&>"];
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };
        for _ in 0..30_000 {
            let n = 1 + (next() % 7) as usize;
            let argv: Vec<String> = (0..n).map(|_| words[(next() % words.len() as u64) as usize].to_string()).collect();
            let _ = check(&argv, Path::new("/tmp"), &Policy::default());
            let _ = check(&["sh".into(), "-c".into(), argv.join(" ")], Path::new("/tmp"), &Policy::default());
        }
    }
}
