# End-to-end test

`run.sh` builds whence-touche and then drives a **real operation through every
supported tool**, asserting each one is detected and classified correctly.

It runs inside the **Nix dev shell** (`../flake.nix`), which provides both the
build toolchain (Go + the eBPF/clang toolchain) and every tool under test
(`gnupg`, `openssh`, `pass`, `gopass`, `sops`, `age`, `rage`, `git`, …) — so the
environment is reproducible and you don't have to install any of them yourself.

There is no GitHub workflow for this on purpose: a true e2e needs a physical
YubiKey and a human to touch it (and enter PINs), which CI can't provide.

## What it does

1. `make build` with the Nix toolchain (BPF object + binary).
2. `sudo setcap` the eBPF caps, then start the watcher with the **log-only**
   notifier (`-notifier=log`) so detections land in a log it can grep.
3. For each tool: set up ephemeral artifacts using your YubiKey credential, run
   the operation that needs a touch, and check the classifier named the tool.

## Usage

```sh
make e2e                 # build, then test every supported tool
./e2e/run.sh             # same (re-execs itself into `nix develop`)
./e2e/run.sh gpg ssh     # only the named tools
```

Before each tool it prompts `[Enter] run · [s] skip`. Perform the touch (and any
PIN entry) when prompted; the operation blocks until you do. At the end it prints
a PASS / FAIL / SKIP matrix and exits non-zero if anything failed.

### Tools and how each is exercised

| Tool | Operation driven | Credential needed |
|---|---|---|
| `gpg` | `gpg --sign` | GPG key on the YubiKey |
| `pass` | `pass show` (decrypt) | GPG key on the YubiKey |
| `gopass` | `gopass show` (decrypt) | GPG key on the YubiKey |
| `sops` | `sops --decrypt` (PGP) | GPG key on the YubiKey |
| `git` | `git commit -S` (signed) | GPG key on the YubiKey |
| `ssh` | `ssh-keygen -t ed25519-sk` | FIDO2 PIN set on the key |
| `age` | `age -d` via `age-plugin-yubikey` | PIV identity (best-effort) |
| browser | opens webauthn.io in your default browser | a passkey/WebAuthn credential |
| `bitwarden` | manual: unlock / login using YubiKey OTP 2FA | a Bitwarden account with YubiKey OTP 2FA |

The watcher is granted only the eBPF caps (`cap_bpf`, `cap_perfmon`,
`cap_sys_admin`). An agent-mediated touch (gpg, pass, sops, …) is attributed to
the real client rather than to scdaemon by the in-kernel request graph, so no
`/proc`-scanning capabilities are required.

Tools whose credential isn't present are **SKIP**ped with a reason.

> **Touch policy matters.** eBPF detection fires on a sustained touch-*wait*. A
> credential whose touch policy is **off** completes too quickly to register, so
> that test will FAIL even though the tool itself works. Enable the touch policy
> (GPG: `ykman openpgp keys set-touch`; PIV: per-slot touch; FIDO: a PIN /
> `verify-required`) for the keys you test.

## Environment

| var | default | meaning |
|---|---|---|
| `WHENCE_E2E_GPG_KEY` | first secret key | GPG key fingerprint to use |
| `E2E_TOUCH_TIMEOUT` | `60` | seconds to wait for each touch |
| `E2E_DEBUG` | `0` | `1` runs the watcher with `-verbose` and prints, per test, the full process call stack the classifier saw (plus how the gpg/ssh-agent client was resolved) — use it to explain a misclassification |

## Requirements

- Linux host with eBPF + BTF (`/sys/kernel/btf/vmlinux`).
- Nix with flakes enabled (the script passes the experimental flags itself).
- `sudo` (to grant the eBPF caps via `setcap`).
- A physical YubiKey configured for whatever tools you test.
