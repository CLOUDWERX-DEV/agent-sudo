# Policy

An optional file, `/etc/agent-sudo.json`, read by the root side on every command.

```json
{
  "allow_programs": ["pacman", "systemctl", "tee", "mkdir", "chmod"],
  "deny_programs": ["curl", "wget"],
  "disable_rules": [],
  "notify": true
}
```

| Key | What it does |
| --- | --- |
| `allow_programs` | When not empty, only these programs may run. **Every** program in a chain must be listed: a wrapper like `env`, a shell like `sh`, and the command itself. Leave it out to allow anything the guardrails allow. |
| `deny_programs` | These never run, anywhere in a chain or inside a shell script. |
| `disable_rules` | Guardrail rules to turn off, by name (`agent-sudo --rules`). |
| `notify` | `false` turns off the desktop notifications. |

## The file has to be safe

It must be owned by root and not writable by anyone else:

```sh
sudo chown root:root /etc/agent-sudo.json
sudo chmod 644 /etc/agent-sudo.json
```

If it isn't, or it has a typo (an unknown key, an unknown rule name, a value of the wrong type), **the root side refuses to run anything** and says why. That's on purpose: a policy that's quietly ignored is looser than you meant. `agent-sudo --status` shows whether the file is fine.

## An allowlist in practice

If your automation only needs to install packages and restart services, say so:

```json
{ "allow_programs": ["pacman", "systemctl"] }
```

Now `agent-sudo pacman -S ripgrep` works, and `agent-sudo bash -c "..."`, `agent-sudo env pacman ...` and `agent-sudo python3 ...` all refuse, because `bash`, `env` and `python3` aren't listed. That is the strongest protection in `agent-sudo`: not a list of bad things, a list of the only good things.
