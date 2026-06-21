# yubikey-notifier

Desktop notifier that shows **which tool** triggered a YubiKey touch request.

When your YubiKey is waiting for a touch, a critical notification appears showing
the responsible tool (e.g. `pass decrypt: ~/.password-store/GH_TOKEN`,
`git push: git@github.com/...`, `ssh authenticate: github.com`). It dismisses
itself once the key goes quiet (touch complete).

## How it works

Instead of depending on `yubikey-touch-detector`'s D-Bus signals, this tool
attaches **eBPF kprobes** directly (see `internal/tracer`) and watches the two
transports a YubiKey uses:

- **hidraw** (`hidraw_read`/`hidraw_write`) — FIDO/U2F/WebAuthn and HMAC.
- **usbfs/CCID** (`proc_do_submiturb`, filtered to security-key USB vendors) —
  OpenPGP via `scdaemon`.

Each probe runs in the calling process's context, so the event carries the exact
PID that hit the key. From there:

1. **PID → program** — `internal/proctree` + `internal/classifier` walk `/proc`
   and classify the tool/action/resource. When a request is routed through an
   agent daemon, the real client is a *socket peer* of that agent, not a process
   ancestor of the I/O leaf — `internal/agentpeer` resolves those generically
   (UNIX_DIAG peer-walk), with presets for the agents this project understands:
   - **FIDO**, key in file/config: the event PID *is* the client leaf
     (`ssh-sk-helper` with `ssh` as its parent, `chromium`) — walk directly.
   - **FIDO**, key in `ssh-agent`: the leaf was forked by `ssh-agent`, so the
     `ssh` client is resolved via `agentpeer.SSHAgent`.
   - **GPG**: the event PID is always `scdaemon`, so the client (`gpg`/`gopass`/
     `git`) is resolved via `agentpeer.GPGAgent`.
2. **Notification** — `internal/notifier` shows/dismisses the desktop
   notification over the freedesktop D-Bus interface.

Because eBPF reports a raw I/O firehose (not the detector's clean on/off), the
event loop debounces: a notification appears once a process accumulates a few
I/Os to the key, and is dismissed after the key is silent for a short window.
Those thresholds are project configuration (`internal/config`, loaded in `main`).

> **Heuristic, not exact touch detection.** The probes fire on *any* I/O to the
> key, so an operation that does not actually require a touch can still notify.
> Distinguishing "touch required" needs payload inspection (CTAPHID frame for
> FIDO, CCID/APDU for OpenPGP) and is a future refinement.

## Requirements

- Linux with eBPF + BTF (`/sys/kernel/btf/vmlinux`) and `CONFIG_HID_BPF`-class
  kprobe support (standard on modern kernels).
- **Root**, or the capabilities `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN`, to
  load/attach the probes.
- `clang` + libbpf headers to build the BPF object (build-time only).
- A notification daemon (e.g. `dunst`, `mako`, `swaync`).
- No longer requires `yubikey-touch-detector`.

## Build

```
make            # compiles tracer.bpf.o (clang) next to the binary, then builds it
```

The binary loads `tracer.bpf.o` at runtime (it is not embedded), defaulting to
`tracer.bpf.o` next to the executable. The `-bpf-object <path>` flag overrides
the configured path.

## Configuration

All settings are loaded once in `main` from `internal/config` (via `envconfig`):

| Env var | Default | Meaning |
|---|---|---|
| `YUBIKEY_TRACER_OBJ_PATH` | `<exe-dir>/tracer.bpf.o` | path to the BPF object |
| `YUBIKEY_NOTIFY_THRESHOLD` | `3` | I/O events before a notification shows |
| `YUBIKEY_QUIET` | `500ms` | silence before a touch is considered done |
| `YUBIKEY_SWEEP` | `200ms` | how often idle sessions are checked |

## Run

```
make run        # sudo -E ./yubikey-notifier -verbose
```

eBPF needs privilege, but desktop notifications go to *your* user session bus —
a root process points at root's (absent) bus, so they silently fail. Two ways to
bridge that:

- **`sudo`** (plain): the daemon derives your bus from `$SUDO_UID`
  (`/run/user/<uid>/bus`) automatically. `sudo -E` also works (preserves
  `DBUS_SESSION_BUS_ADDRESS`/`XDG_RUNTIME_DIR`).
- **Unprivileged (recommended)** — grant file capabilities and run as yourself,
  so the session bus is just there:

  ```
  make setcap            # sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ./yubikey-notifier
  ./yubikey-notifier -verbose
  ```

  File capabilities live on the binary, so re-run `make setcap` after every
  rebuild. (If GPG/SSH client resolution misses while unprivileged, add
  `cap_net_admin` for the UNIX_DIAG socket query.)

### As a service

The package installs a **systemd user unit** plus the eBPF file capabilities on
the binary, so the service runs as *you* (no root) — which is exactly why the
session bus, and thus notifications, work without any address juggling. A user
unit can't be granted ambient capabilities, but it inherits the binary's file
caps at exec. Enable it for your user:

```
systemctl --user enable --now yubikey-notifier
```

Installing from source (no package)? Apply the caps and drop the unit in
yourself:

```
make setcap
install -Dm644 packaging/yubikey-notifier.service ~/.config/systemd/user/yubikey-notifier.service
systemctl --user daemon-reload
systemctl --user enable --now yubikey-notifier
```

## Supported tools

| Tool | Detected operations |
|------|-------------------|
| `pass` | show, insert, generate, edit |
| `sops` | encrypt, decrypt, edit, rotate |
| `age` / `rage` | encrypt, decrypt |
| `git` | push, pull, fetch, clone, signed commit |
| `gpg` / `gpg2` | sign, decrypt, encrypt, verify |
| `ssh` / `scp` / `sftp` | authenticate |
| browsers | WebAuthn / passkey |

When the calling process isn't recognised, the raw process chain is shown instead.

## License

MIT
