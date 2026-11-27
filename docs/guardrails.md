# Guardrails

Run `agent-sudo --rules` for the list, and `agent-sudo --explain COMMAND` to see which rule would stop a command and why.

## How a command is read

The checker doesn't match a string. It takes the command the way the program would receive it (its argument list) and:

1. **Unwraps wrappers**: `env`, `nice`, `ionice`, `nohup`, `setsid`, `time`, `command`, `exec`, `stdbuf`, `timeout`, `chrt`, `taskset`, `flock`, `sudo`, `doas`, `pkexec`, `runuser`, `unshare`, `nsenter` and `chroot` are skipped to find what really runs. `/usr/bin/rm` is `rm`.
2. **Reads shell scripts**: `sh -c`, `bash -c` (and `-lc`, `-ec`), `zsh`, `fish`, `dash`, `ksh`, `su -c` and `eval`. The script is split into commands at `;`, `&&`, `||`, `|`, `&` and newlines, quotes are understood, `$(...)` and backticks are checked too, and redirections (`>`, `>>`, `2>`, `&>`) are checked as writes.
3. **Normalizes paths**: `//`, `.`, `..`, trailing slashes, relative paths (against where the command runs), a `*` at the end (it means "everything inside"), and where an existing symlink really leads.
4. **Applies the rules** to the program and its arguments.

## The rules

| Rule | Stops |
| --- | --- |
| `root-delete` | `rm` with `-r`, `-R` or `--recursive` on `/`, `/*`, or a protected directory; `rm --no-preserve-root` |
| `disk-format` | `mkfs`, `mkfs.*`, `mke2fs`, `mkswap`, `blkdiscard`, and `wipefs`, `sfdisk`, `sgdisk`, `gdisk`, `fdisk`, `cfdisk`, `parted`, `cryptsetup`, `pvcreate`, `dmsetup` on a disk device (read-only forms like `fdisk -l`, `wipefs -n` and `parted ... print` are fine) |
| `disk-write` | `dd of=` a disk device, `tee`, `shred` or `truncate` on one, `cp`/`install` to one, and `>` redirects to one |
| `auth-files` | `rm`, `mv`, `cp`, `install`, `tee`, `truncate`, `shred`, `ln`, `dd of=`, `sed -i`, `perl -i`, `chmod`, `chown`, `chgrp`, `chattr` and redirects on `/etc/shadow`, `gshadow`, `passwd`, `group`, `sudoers` and `/etc/sudoers.d/*`. Copying one somewhere (`cp /etc/shadow /tmp/backup`) and reading it are fine. |
| `recursive-perms` | `chmod`, `chown`, `chgrp`, `chattr` with `-R` on `/` or a protected directory |
| `move-critical` | `mv` of a protected directory |
| `find-delete` | `find` starting at a protected directory with `-delete` or `-exec rm` |
| `fork-bomb` | the classic `:(){ :\|:& };:` in any spacing |
| `unverifiable-delete` | a recursive `rm` in a script whose target starts with a shell variable or backtick |
| `power` | `reboot`, `poweroff`, `halt`, `shutdown`, `systemctl reboot\|poweroff\|halt\|kexec`, `init 0\|6` |

**Protected directories:** `/`, `/bin`, `/boot`, `/dev`, `/etc`, `/home`, `/lib`, `/lib32`, `/lib64`, `/libx32`, `/opt`, `/proc`, `/root`, `/run`, `/sbin`, `/srv`, `/sys`, `/usr`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/lib32`, `/usr/lib64`, `/usr/share`, `/usr/local`, `/var`, `/var/lib`. Their contents (`/etc/myapp`, `/usr/local/share/foo`, `/var/cache/...`) are not protected: you can delete those.

**Disk devices:** `/dev/sd*`, `hd*`, `vd*`, `xvd*`, `nvme*`, `mmcblk*`, `md*`, `dm-*`, `loop*`, `sr*`, `mapper/*` and `disk/*`.

## Switching a rule off

Add its name to `disable_rules` in `/etc/agent-sudo.json`. For example `"disable_rules": ["power"]` lets automation reboot the machine. Do it knowingly, one rule at a time.

## What it doesn't do

It can't see what a program does once it's running. `python3 -c "import shutil; shutil.rmtree('/')"` isn't inspected. If that matters, use `allow_programs` so interpreters aren't available at all. See [SECURITY.md](../SECURITY.md).
