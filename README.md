# agent-sudo

Non-interactive elevated execution runner for automated tooling and headless processes on CLOUDWERX OS.

`agent-sudo` provides a guarded bridge for automated routines and scripts that require root privileges without stalling on interactive `sudo` password prompts or exposing sensitive credentials.

---

## The Problem

Standard `sudo` requires interactive stdin password authentication. In automated or headless environments:
- Commands block indefinitely waiting for password input.
- Passing credentials into process environments or shell history leaks secrets.
- Unrestricted `NOPASSWD: ALL` in sudoers removes all safety margins, exposing the host to catastrophic mistakes (e.g. accidental `rm -rf /` or raw disk clobbering).

## The Solution

`agent-sudo` decouples privilege execution using a split frontend/backend model:

1. **Frontend CLI (`agent-sudo`)**:
   - Inspects the command line against strict safety guardrails.
   - Passes execution directly to the elevated backend using `sudo -n` (non-interactive mode).
   - Preserves all standard streams (stdin, stdout, stderr), terminal flags, and exact exit codes.

2. **Backend Runner (`agent-sudo-backend`)**:
   - Restricted in `/etc/sudoers.d/99-agent-sudo` to execute passwordless only for user `cloudwerx`.
   - Runs under root UID 0, restores caller working directory, and performs defense-in-depth guardrail verification.
   - Writes an immutable audit trail entry to `/var/log/agent-sudo.log`.
   - Dispatches a subtle, non-blocking desktop notification (`notify-send`) to the graphical session for full operational visibility.
   - Replaces itself (`exec`) with the target command.

---

## Installation

Run the installer with root privileges once:

```fish
cd ~/Code/agent-sudo
sudo ./install.sh
```

The installer:
- Deploys `/usr/local/libexec/agent-sudo-backend` (root:root, `0755`)
- Deploys `/usr/local/bin/agent-sudo` and shorthand alias `/usr/local/bin/asudo`
- Validates and writes `/etc/sudoers.d/99-agent-sudo` via `visudo -cf`
- Initializes `/var/log/agent-sudo.log` (mode `0644`, root:cloudwerx)
- Installs Fish completions to `~/.config/fish/completions/agent-sudo.fish`
- Installs Bash completions to `/etc/bash_completion.d/agent-sudo`
- Executes an automated self-test verification (`agent-sudo whoami`)

### Uninstallation

To completely remove `agent-sudo` and restore default sudoers:

```fish
sudo ./install.sh --uninstall
```

---

## Usage

### Direct Execution

Prefix any administrative command with `agent-sudo` (or shorthand `asudo`):

```fish
# Package management
agent-sudo pacman -S --noconfirm ripgrep

# Systemd services
agent-sudo systemctl restart NetworkManager

# File creation in protected directories
agent-sudo tee /etc/systemd/system/app.service < app.service

# Snapshots
agent-sudo snapper create -d "Pre-update state"
```

### Checking Status & Health

```fish
agent-sudo --status
```

Sample output:
```text
=== agent-sudo status ===
Version: 0.1.0
Backend binary: INSTALLED (/usr/local/libexec/agent-sudo-backend)
Sudoers drop-in: CONFIGURED & ACTIVE
Audit log: FOUND (/var/log/agent-sudo.log, 12 lines)
Health check: PASS (Elevated runner operational)
```

### Viewing Audit Logs

```fish
agent-sudo --logs 20
```

---

## Built-in Guardrails

`agent-sudo` blocks known catastrophic patterns before execution:

| Category | Blocked Patterns | Action |
| :--- | :--- | :--- |
| **System Deletion** | `rm -rf /`, `rm -rf /*`, `rm -rf /boot`, `/etc`, `/usr`, `/bin` | Rejection (Exit 126) |
| **Raw Disk Destruction** | `mkfs.* /dev/(sd*\|nvme*)`, `wipefs /dev/...` | Rejection (Exit 126) |
| **Direct Disk Clobbering** | `dd ... of=/dev/(sd*\|nvme*)` | Rejection (Exit 126) |
| **Auth File Tampering** | Writing or removing `/etc/shadow`, `/etc/passwd`, `/etc/sudoers` | Rejection (Exit 126) |
| **Fork Bombs** | `:(){ :\|:& };:` | Rejection (Exit 126) |

---

## Global Instructions Integration

Add the following rule to your global rules or agent system instructions:

```markdown
When you need root or administrative privileges (e.g. package installation, systemd service management, editing system files in /etc), NEVER run interactive `sudo` and never ask for a sudo password.
Instead, execute:
  agent-sudo <command> [args...]
Or shorthand:
  asudo <command> [args...]
```
