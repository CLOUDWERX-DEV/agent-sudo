# Changelog

All notable changes to `agent-sudo` are in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **A new logo**: a terminal window with a shield and padlock, in the icon and the banner (`assets/`). The vector mark is `assets/src/logo.svg`, traced from the artwork in `assets/src/logo-master.png`.
- The pixel-art logo generator (`examples/make_logo.rs`) is gone; the icon and banner are plain files in `assets/`.


## [0.3.2] - 2026-11-27

### Fixed

- `--status` no longer shows a failing "sudoers rule" line when the rule is fine. The rule's file is mode 0440 and an ordinary account usually can't read it, so it now counts sudo's own answer (`sudo -n -l`) as the real test and says "readable only by root; sudo allows it".

## [0.3.1] - 2026-11-26

### Changed

- Removed the files left over from the very first import (the old shell scripts, installer and their tests). Everything they did is in the Rust binary, and `--install` replaces the installer. Nothing else changed.

## [0.3.0] - 2026-11-26

First public release.

### Added

- **One small Rust binary** (two dependencies) that is both the command (`agent-sudo`, short name `asudo`) and the root side (`agent-sudo-backend`, run by sudo with no password).
- **Guardrails that read the command**, not a string: ten named rules (`root-delete`, `disk-format`, `disk-write`, `auth-files`, `recursive-perms`, `move-critical`, `find-delete`, `fork-bomb`, `unverifiable-delete`, `power`). They see through wrappers (`env`, `nice`, `timeout`, `sudo`...), read `sh -c` scripts, `$(...)`, backticks and redirections, and normalize paths (`//`, `..`, `.`, trailing `*`, relative paths, symlinks). Reading and listing is never blocked. The checks run on both sides, so the root side doesn't trust the first.
- `--check` and `--explain` (which rule, and why), and `--rules` to list them.
- **An audit log** (`/var/log/agent-sudo.log`) with `[ALLOW]`, `[BLOCKED]` and `[DONE]` lines: who, where, what, how it ended (`exit=`) and how long it took. Arguments are shell-quoted, and newlines, escape codes and other control characters are escaped so a command can't forge a line or fool a terminal. Weekly log rotation is installed.
- **An optional policy file** (`/etc/agent-sudo.json`): `allow_programs` (only these may run, every program in a chain), `deny_programs`, `disable_rules` and `notify`. Typos, unknown keys and unsafe permissions make the root side refuse to run rather than quietly allow more.
- **Desktop notifications** for every run and refusal, sent as the account that ran it with root's groups dropped, and with the command escaped.
- `--install --user NAME` and `--uninstall [--purge]`: copies the root runner to a root-owned path, writes a one line sudoers rule (one account, one program) after `visudo` approves it, creates the log, logrotate rule and completions. It never guesses the account and refuses `root`. `--root DIR` stages everything in a folder for packagers.
- `--status` checks the runner (root-owned, not writable by others), the sudoers rule, that sudo allows it without a password, a health check, the log and the policy file, and exits 0 only when the root runner really works.
- `--logs [N]`, `--version`, `--completions fish|bash|zsh` and a `--` form for commands that start with a dash.
- The command passes through exactly: it is `exec`ed into sudo, and the root side forwards `SIGTERM` and `SIGHUP`, waits, and returns the exit code (`128 + signal` if it was killed).
- Docs (how it works, guardrails, policy), a security policy that says plainly what this is and isn't, a CI workflow, release binaries for x86_64 and aarch64, a PKGBUILD, a pixel-art mascot and issue and pull request templates.
- Tests: well over a hundred table-driven guardrail cases, random-input tests, the root side run for real in a temporary directory, an installer test into a staging folder, and end to end tests of the real binary. Nothing in them runs `sudo`.

[0.3.2]: https://github.com/CLOUDWERX-DEV/agent-sudo/releases/tag/v0.3.2
[0.3.1]: https://github.com/CLOUDWERX-DEV/agent-sudo/releases/tag/v0.3.1
[0.3.0]: https://github.com/CLOUDWERX-DEV/agent-sudo/releases/tag/v0.3.0
