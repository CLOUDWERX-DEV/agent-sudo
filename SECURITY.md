# Security

## The honest version

`agent-sudo` gives **one account the ability to run one root-owned program without a password**, and that program runs whatever command it's given. That is, on its own terms, the same power as `NOPASSWD: ALL` for that account, with a speed bump in front. The guardrails make the speed bump good: they refuse the commands that destroy a machine, see through the usual wrappers and shell tricks, and everything is logged. But:

- **They can't stop something determined.** A program running as root can do anything. `python3 -c`, `perl -e`, an editor with a shell escape, a script written to a file and run, a downloaded binary: none of those can be inspected for what they'll do. Anything that gets arbitrary code running as root can also remove the log.
- **They're a list.** They catch what they know about. A new kind of destructive command isn't caught until a rule is added.

So use it for what it's for: automation and agents that are **trying to do the right thing** and might make a catastrophic mistake. Don't use it to contain something that's trying to get out.

## What it protects against

- **Mistakes and careless commands**: `rm -rf /`, an empty variable in `rm -rf "$X/"*`, a mistyped device in `dd`, `mkfs` on the wrong disk, a stray write to `/etc/passwd`.
- **Obvious dodges**: wrappers (`env`, `nice`, `timeout`, `sudo`, `nohup`, `setsid`...), `sh -c "..."`, `$(...)` and backticks, redirections, `..`, `//`, `.` and symlinks.
- **Log forging**: whatever a command contains, newlines, escape codes and other control characters are escaped, so a command can't write a fake log line or mess with your terminal. Arguments are shell-quoted so the words are unambiguous.
- **A tampered runner**: `agent-sudo --status` checks that the root program is owned by root and not writable by anyone else.
- **A tampered policy**: the root side refuses to run at all if `/etc/agent-sudo.json` isn't owned by root and writable only by root, or has a typo in it. A policy that's ignored by accident is looser than you meant, so it fails closed.
- **A confused root side**: it learns the account from what sudo sets (`SUDO_USER`, `SUDO_UID`, `SUDO_GID`), never from arguments, and it never uses an environment variable to decide a path.
- **Leaking root into the notification**: the desktop notification runs as you, with root's groups dropped first, and the command text is escaped so it can't inject markup.
- **Granting root by accident**: the installer never guesses the account, refuses `root`, validates the sudoers rule with `visudo` before it's put in place, and the rule names exactly one program and one account.

## Hardening it

1. **Use `allow_programs`.** It's the strongest thing in here. If your automation only ever runs `pacman` and `systemctl`, say so, and nothing else can run, shells included. See [docs/policy.md](docs/policy.md).
2. Keep `deny_programs` for things you never want (`curl`, `wget`).
3. Read the audit log. It's there to be looked at: `agent-sudo --logs 50`.
4. Give it to one account, not several.
5. If the audit trail matters, forward it somewhere the account can't write (journald, a remote syslog). A local file is only as good as root.

## Reporting a problem

Please don't open a public issue for a security problem. A bypass of a guardrail is welcome as a normal issue or pull request (it's a rule to add, not a vulnerability, given the above), but anything that gets root without the sudoers rule, escapes the checks on the root side, or breaks the log or policy protections should come privately: use a [private security advisory](https://github.com/CLOUDWERX-DEV/agent-sudo/security/advisories/new) or email mail@cloudwerxlab.com.
