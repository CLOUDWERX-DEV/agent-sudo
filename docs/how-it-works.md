# How it works

One binary plays two parts, chosen by the name it's run under.

## `agent-sudo` (you)

1. Reads your command and runs the guardrails on it. A blocked command stops here, with the rule and the reason, exit 126. This is only so it fails fast: the root side decides.
2. Checks the root runner exists.
3. `exec`s `sudo -n /usr/local/libexec/agent-sudo-backend CWD COMMAND...`. `exec` means the terminal, signals and exit code are exactly sudo's and the command's, nothing in between. `-n` means sudo never prompts: it works or it fails.

## `agent-sudo-backend` (root)

A root-owned copy of the same binary, and the only program the sudoers rule lets your account run without a password:

```
you ALL=(root) NOPASSWD: /usr/local/libexec/agent-sudo-backend
```

1. Refuses to run unless it's root.
2. Learns who you are from `SUDO_USER`, `SUDO_UID` and `SUDO_GID` (set by sudo), never from arguments.
3. Loads `/etc/agent-sudo.json` if there is one, and refuses to run if it's unsafe or broken.
4. Runs the guardrails and the policy again (defense in depth, in case the first check was skipped).
5. Writes `[ALLOW]` or `[BLOCKED]` to `/var/log/agent-sudo.log` and sends a notification as you.
6. Runs the command in your directory, forwards `SIGTERM` and `SIGHUP`, waits, and writes `[DONE] exit=N time=Ts`. A command killed by a signal gives `128 + the signal`.

## Why a copy of the binary

The program that runs as root must not be something you can edit. `--install` copies the binary to a root-owned path (mode 0755, in a root-owned directory), and `--status` checks it still is. If you could change it, the sudoers rule would be a way to run anything as root.

## Files

| Path | What |
| --- | --- |
| `/usr/local/bin/agent-sudo`, `asudo` | the command, and its short name (a link) |
| `/usr/local/libexec/agent-sudo-backend` | the root side |
| `/etc/sudoers.d/99-agent-sudo` | the one line sudoers rule, mode 0440 |
| `/var/log/agent-sudo.log` | the audit log, mode 0640, root and your group |
| `/etc/logrotate.d/agent-sudo` | weekly rotation |
| `/etc/agent-sudo.json` | optional policy |
| fish, bash, zsh completion folders | completions |
