<p align="center">
  <img src="assets/banner.png?v=3" alt="agent-sudo" width="720">
</p>

<p align="center">
  <a href="CHANGELOG.md"><img alt="version" src="https://img.shields.io/badge/version-0.3.2-ff6b81?style=flat-square"></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-ffc857?style=flat-square"></a>
  <img alt="rust" src="https://img.shields.io/badge/rust-single%20binary-ff6b81?style=flat-square">
  <img alt="dependencies" src="https://img.shields.io/badge/dependencies-2-ffc857?style=flat-square">
  <a href="https://github.com/CLOUDWERX-DEV/agent-sudo/actions/workflows/ci.yml"><img alt="tests" src="https://github.com/CLOUDWERX-DEV/agent-sudo/actions/workflows/ci.yml/badge.svg"></a>
</p>

<p align="center"><b>Digital Food for the Analog Soul</b><br>by <a href="https://cloudwerxlab.com">CLOUDWERX LAB</a></p>

---

`agent-sudo` runs a command as root without asking for a password, for the things that can't type one: scripts, cron jobs, automation and coding agents. Before anything runs, it checks the command against guardrails that refuse the ones that wreck a machine, writes a line to an audit log, and pops a quiet desktop notification so you can see it happened.

```sh
agent-sudo pacman -S --noconfirm ripgrep
agent-sudo systemctl restart NetworkManager
agent-sudo rm -rf /usr        # [agent-sudo] BLOCKED (root-delete): recursive delete of /usr would destroy the system
```

> [!WARNING]
> **It's a seatbelt, not a security boundary.** The one thing `agent-sudo` does is let one account run one root-owned program without a password, and that program runs whatever it's given. The guardrails stop the mistakes and the careless commands. They can't stop something that's trying to get around them, because a program running as root can do anything. Read [SECURITY.md](SECURITY.md) before you give this to something you don't trust.

## Why it exists

Normal `sudo` wants a password from a terminal. A script or an agent can't give one, so it hangs forever, or you do the dangerous thing and put `NOPASSWD: ALL` in sudoers, and now one bad command (an empty variable in `rm -rf "$DIR/"*`, a typo in a device name) takes the whole machine with it.

`agent-sudo` sits in the middle. It still lets the automation work, but it:

- **refuses the catastrophic stuff**: `rm -rf /`, `mkfs` on a disk, `dd` onto `/dev/sda`, editing `/etc/shadow`, fork bombs, and more,
- **sees through the tricks**: `env`, `nice`, `timeout`, `sudo`, `sh -c "..."`, `$(...)`, redirections, `..` and symlinks don't hide anything,
- **keeps a paper trail**: every command, who ran it, where, how it ended and how long it took,
- **tells you**: a desktop notification for every elevated command.

## What you get

- **Guardrails that read the command**, not a regex over a string. Ten named rules, each one switchable. `agent-sudo --explain CMD` says which rule fired and why.
- **An audit log** at `/var/log/agent-sudo.log`: when, who, where, what, and how it ended (`[ALLOW]`, `[BLOCKED]`, `[DONE] exit=0 time=1.2s`). What a command contains can't forge a log line.
- **An optional policy file** to allow only certain programs, deny others, or switch rules off.
- **Desktop notifications** for every run and every refusal.
- **Everything in one small binary** with two dependencies, and a one command installer that verifies the sudoers rule with `visudo` before it touches anything.
- **Passes everything through**: stdin, stdout, stderr, the terminal, signals and the exit code are exactly the command's.
- **Short name and completions**: `asudo` for `agent-sudo`, with fish, bash and zsh completions.

## Install

Grab a binary from the [releases page](https://github.com/CLOUDWERX-DEV/agent-sudo/releases) (or `cargo install --git https://github.com/CLOUDWERX-DEV/agent-sudo`), then install it once as root, naming the account that may use it:

```sh
sudo ./agent-sudo --install --user "$USER"
agent-sudo --status
```

That puts the program in `/usr/local/libexec/agent-sudo-backend` and `/usr/local/bin/agent-sudo` (plus `asudo`), adds a one line sudoers rule at `/etc/sudoers.d/99-agent-sudo` after `visudo` approves it, creates the log, and installs completions. It never guesses who to trust: you name the account, and it refuses `root`.

Remove it again with `sudo agent-sudo --uninstall` (`--purge` also deletes the log). There's a [PKGBUILD](packaging/PKGBUILD) for Arch.

## Use it

```sh
agent-sudo pacman -S --noconfirm ripgrep          # run anything, as root
asudo systemctl restart sshd                      # the short name
agent-sudo tee /etc/systemd/system/app.service < app.service
agent-sudo -- -weird-command-that-starts-with-a-dash

agent-sudo --check rm -rf /tmp/build              # would it be allowed? (runs nothing)
agent-sudo --explain dd if=x of=/dev/sda          # which rule, and why
agent-sudo --rules                                # every rule
agent-sudo --logs 10                              # the last 10 audit lines
agent-sudo --status                               # is everything set up right?
```

Exit codes are the command's own, plus `126` for blocked and `127` for not found or not installed.

### What the guardrails stop

| Rule | Stops |
| --- | --- |
| `root-delete` | recursive `rm` of `/`, `/*`, `/etc`, `/usr`, `/boot`, `/var/lib`, `/home`..., `--no-preserve-root` |
| `disk-format` | `mkfs.*`, `wipefs`, `sfdisk`, `sgdisk`, `parted mklabel`, `blkdiscard`, `cryptsetup luksFormat` on a disk |
| `disk-write` | `dd of=/dev/sda`, `tee /dev/sda`, `cp x /dev/sda`, `> /dev/nvme0n1` |
| `auth-files` | changing `/etc/shadow`, `passwd`, `group`, `sudoers`, `sudoers.d` with `rm`, `mv`, `cp`, `tee`, `sed -i`, `chmod`, redirects... |
| `recursive-perms` | `chmod -R`, `chown -R`, `chattr -R` on `/` or a system directory |
| `move-critical` | `mv /etc ...`, `mv /usr ...` |
| `find-delete` | `find / -delete`, `find /etc -exec rm ...` |
| `fork-bomb` | `:(){ :\|:& };:` and friends |
| `unverifiable-delete` | `rm -rf $VAR/` in a script, where an empty variable means `/` |
| `power` | `reboot`, `poweroff`, `halt`, `shutdown`, `systemctl reboot` |

It reads paths properly: `//etc//`, `/usr/../etc`, `/etc/.` and a symlink that points at `/etc` are all `/etc`. Relative paths are resolved against where the command runs. Reading is never blocked: `cat /etc/shadow`, `fdisk -l`, `dd if=/dev/sda of=backup.img` and `rm -rf /tmp/anything` go through. [Full detail in docs/guardrails.md.](docs/guardrails.md)

### The audit log

```
2026-11-26T23:37:49-05:00 [ALLOW] user=ty uid=1000 cwd=/tmp cmd=id -u
2026-11-26T23:37:49-05:00 [DONE] user=ty uid=1000 cwd=/tmp exit=0 time=0.0s cmd=id -u
2026-11-26T23:37:49-05:00 [BLOCKED] user=ty uid=1000 cwd=/ rule=disk-write cmd=tee /dev/sdz9
```

Arguments are shell-quoted so you can see exactly which words there were, and newlines and escape codes inside a command are escaped, so nothing can fake a line or mess with your terminal when you read the log. It rotates weekly (`/etc/logrotate.d/agent-sudo`).

## Policy

Optional. Put JSON in `/etc/agent-sudo.json`, owned by root and writable by nobody else:

```json
{
  "allow_programs": ["pacman", "systemctl", "tee"],
  "deny_programs": ["curl"],
  "disable_rules": ["power"],
  "notify": true
}
```

`allow_programs` is the real hardening: when it's set, **only** those programs can run, and every program in a chain has to be on it (`env`, `sh`, the command itself). A typo is an error, not a silent "allow everything", and an unsafe or broken file makes the root side refuse to run at all. More in [docs/policy.md](docs/policy.md).

## How it works

```
you ──► agent-sudo ──► guardrails ──► sudo -n ──► agent-sudo-backend (root)
                                                    │  guardrails again, policy
                                                    │  audit log, notification
                                                    └─► your command, as root
```

It's one binary that plays two parts. As `agent-sudo` it checks the command (so a blocked one fails fast) and hands it to `sudo -n`, which never prompts: it works or it fails. The sudoers rule lets your account run exactly one program, `agent-sudo-backend`, which is a root-owned copy of the same binary. That one checks again on the root side (defense in depth), logs, runs the command in your directory, waits, and logs how it ended. It learns who you are from what sudo sets, never from arguments. [More in docs/how-it-works.md.](docs/how-it-works.md)

## Develop

```sh
cargo test
cargo clippy --all-targets
```

Tests never run `sudo` and never touch your system: installs go to a staging folder, and there are well over a hundred guardrail cases, random-input tests, and end to end tests of the real binary. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Support

If it's useful to you, you can [buy me a coffee](https://buymeacoffee.com/cloudwerxl3). More from us at [cloudwerxlab.com](https://cloudwerxlab.com) and [github.com/CLOUDWERX-DEV](https://github.com/CLOUDWERX-DEV).

MIT licensed. See [LICENSE](LICENSE).
