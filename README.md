# Whence Touché

A desktop notifier that tells you **which program** made your YubiKey blink for a
touch — e.g. `ssh authenticate: github.com`, `gpg sign`, `git push`, or a browser
passkey. The notification clears itself once the touch is done.

## Why

[yubikey-touch-detector](https://github.com/maximbaz/yubikey-touch-detector) is
great but has two limitations:

1. It tells you a touch is pending, but not **what** asked for it.
2. It detects touches **indirectly** (e.g. watching GPG files), which is only
   approximate.

Whence Touché fixes both with **eBPF**. It attaches kprobes to the kernel
functions a security key's I/O passes through: a probe firing *is* the touch
happening (direct detection), and because it runs in the calling process's
context it carries that process's **PID**. From the PID we walk `/proc` and name
the actual tool and its target.

## Requirements

- Linux with eBPF + BTF (`/sys/kernel/btf/vmlinux`) — standard on modern kernels.
- Privilege to load eBPF: run as root, or grant the binary
  `cap_bpf,cap_perfmon,cap_sys_admin` (the package does this for you).
- `clang` to build the BPF object.
- A notification daemon (`dunst`, `mako`, `swaync`, …).

Only **YubiKey** security keys are supported for now.

## Build & run

```
make && make setcap     # build, then grant caps to run unprivileged
./whence-touche          # or: make run  (uses sudo)
```

Or install the Arch package and enable the user service:

```
makepkg -si
systemctl --user enable --now whence-touche
```

## Configuration

Environment variables (prefix `WHENCE_`):

| Variable | Default | Meaning |
|---|---|---|
| `WHENCE_TRACER_OBJ_PATH` | next to the binary | path to `tracer.bpf.o` |
| `WHENCE_NOTIFY_THRESHOLD` | `3` | I/O events before notifying |
| `WHENCE_NOTIFY_DELAY` | `500ms` | sustained activity before notifying |
| `WHENCE_QUIET` | `500ms` | silence before a touch is considered done |
| `WHENCE_SWEEP` | `200ms` | how often idle sessions are checked |
| `WHENCE_DEBUG` | `false` | debug logging (same as `-verbose`) |

`WHENCE_NOTIFY_DELAY` exists to avoid a notification "flash" when a key also
asks for a PIN (GPG, WebAuthn): the short command exchange before the PIN
prompt is over in milliseconds, while a real touch-wait keeps the device
polling until you touch. Requiring activity to persist for this long means the
pre-PIN burst never raises a notification, so there is nothing to close during
the prompt and reopen after.

## Supported tools

| Tool | Operations |
|---|---|
| `pass` | show, insert, generate, edit |
| `sops` | encrypt, decrypt, edit, rotate |
| `age` / `rage` | encrypt, decrypt |
| `git` | push, pull, fetch, clone, signed commit |
| `gpg` / `gpg2` | sign, decrypt, encrypt, verify |
| `ssh` / `scp` / `sftp` | authenticate |
| browsers | WebAuthn / passkey |

Unrecognised callers show the raw process chain.

## License

MIT
