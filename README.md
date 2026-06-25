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
  `cap_bpf,cap_perfmon,cap_sys_admin` (the package does this for you) to load and
  attach the probes. The real client behind an agent-mediated touch (gpg via
  gpg-agent, FIDO via ssh-agent) is resolved entirely in-kernel by the eBPF
  request graph, so no `/proc`-scanning privileges are needed.
- `clang` to build the BPF object.
- A notification daemon (`dunst`, `mako`, `swaync`, …).

Only **YubiKey** security keys are supported for now.

## Build & run

```
make             # build, then grant caps (sudo) so it runs unprivileged
./whence-touche  # or: make run  (uses sudo)
```

Don't want to install `clang`/`libbpf`/Go yourself? `nix develop` drops you into
a shell with the whole build toolchain (see [`flake.nix`](flake.nix)), then
`make` works as above.

Or grab a prebuilt package for your distro from the
[latest release](https://github.com/Talgarr/Whence-Touche/releases), install it
(pick the line for your distro), and enable the user service:

```
sudo pacman -U  whence-touche_*_linux_amd64.pkg.tar.zst   # Arch
sudo dpkg -i    whence-touche_*_linux_amd64.deb           # Debian/Ubuntu
sudo rpm -i     whence-touche_*_linux_amd64.rpm           # Fedora/openSUSE
systemctl --user enable --now whence-touche
```

The package's post-install grants the eBPF caps for you, so no `make setcap` is needed.

## Configuration

Environment variables (prefix `WHENCE_`):

| Variable | Default | Meaning |
|---|---|---|
| `WHENCE_NOTIFY_THRESHOLD` | `3` | I/O events before notifying |
| `WHENCE_NOTIFY_DELAY` | `200ms` | sustained activity before notifying |
| `WHENCE_QUIET` | `500ms` | silence before a touch is considered done |
| `WHENCE_SWEEP` | `200ms` | how often idle sessions are checked |
| `WHENCE_DEBUG` | `false` | debug logging (same as `-verbose`) |
| `WHENCE_NOTIFIER` | `dbus` | notification backend: `dbus` (desktop) or `log` (log only) |

## Supported tools

| Tool | Operations |
|---|---|
| `pass` | show, insert, generate, edit |
| `bitwarden` / `bw` | authenticate (YubiKey OTP 2FA) |
| `sops` | encrypt, decrypt, edit, rotate |
| `age` / `rage` | encrypt, decrypt |
| `git` | push, pull, fetch, clone, signed commit |
| `gpg` / `gpg2` | sign, decrypt, encrypt, verify |
| `ssh` / `scp` / `sftp` | authenticate |
| browsers | WebAuthn / passkey |

Unrecognised callers show the raw process chain.

## Testing

`go test ./...` covers the debounce/classification logic. For a real end-to-end
check, `make e2e` builds the tool and drives a live operation through **every
supported tool** against your actual YubiKey, asserting each is detected. It runs
in a [Nix dev shell](flake.nix) that provides the build toolchain plus all the
tools under test, so nothing needs installing. It needs a physical key and human
touches, so it's a local manual check rather than a CI job — see
[`e2e/`](e2e/README.md).

## License

MIT
