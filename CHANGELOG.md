# Changelog

All notable changes to `agent-sudo` are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-10

### Added
- Initial release of `agent-sudo`, a non-interactive privilege execution runner.
- Frontend CLI (`bin/agent-sudo`) with pre-flight parameter parsing, guardrail enforcement, and `--status` / `--logs` inspection tools.
- Elevated backend runner (`bin/agent-sudo-backend`) with root execution, caller working directory restoration, and defense-in-depth verification.
- Audit logging pipeline recording timestamp, caller UID, PID, working directory, and execution status to `/var/log/agent-sudo.log`.
- Graphical session desktop notification dispatch via `notify-send`.
- Safety guardrails blocking destructive commands (root filesystem deletion, raw disk clobbering, direct auth file modifications, fork bombs).
- Automated installer (`install.sh`) configuring `/usr/local/bin`, `/usr/local/libexec`, and verified `/etc/sudoers.d/99-agent-sudo` drop-in.
- Fish shell completions (`completions/agent-sudo.fish`) with command wrapping and `asudo` shorthand support.
- Bash shell completions (`completions/agent-sudo.bash`).
- Automated test suite (`tests/test-guardrails.sh`) covering guardrail enforcement and standard command pass-through.
