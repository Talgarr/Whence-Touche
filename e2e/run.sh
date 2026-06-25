#!/usr/bin/env bash
#
# End-to-end test for whence-touche.
#
# Runs inside the Nix dev shell (flake.nix), which provides BOTH the build
# toolchain and every tool the classifier supports. The script:
#
#   1. builds whence-touche (BPF object + binary) with the Nix toolchain,
#   2. grants it the eBPF caps and starts it with the log-only notifier,
#   3. drives a real operation through each supported tool and asserts the tool
#      was detected and classified correctly.
#
# This is a manual, hardware-in-the-loop test: it needs a physical YubiKey and a
# human to touch it (and enter PINs). eBPF detection only fires on a sustained
# touch-WAIT, so each credential exercised must have its touch policy enabled —
# a no-touch operation is too brief to register.
#
# Usage:
#   ./e2e/run.sh                 # build, then test every supported tool
#   ./e2e/run.sh gpg ssh         # only the named tools
#   make e2e
#
# Env:
#   WHENCE_E2E_GPG_KEY=<fpr>     GPG key to use (default: first secret key)
#   E2E_TOUCH_TIMEOUT=60         seconds to wait for each touch
#   E2E_DEBUG=1                  run the watcher with -verbose and print the full
#                                process call stack the classifier saw per test
#   E2E_LOG=<path>               write the results table + full watcher log here
#                                (default: e2e/last-run.log). Pair with E2E_DEBUG=1
#                                to capture the per-touch call stacks for triage.
#
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
REPO_ROOT="$(cd "$(dirname "$SCRIPT")/.." && pwd)"
NIX_FEATURES=(--extra-experimental-features nix-command --extra-experimental-features flakes)

# --- re-exec into the Nix dev shell -------------------------------------------
# Unless we are already inside a Nix shell, hand off to `nix develop` so the
# build toolchain and all the tools-under-test are on PATH.
if [ -z "${WHENCE_E2E_INSHELL:-}" ] && [ -z "${IN_NIX_SHELL:-}" ]; then
	command -v nix >/dev/null 2>&1 ||
		{ echo "error: nix not found; install Nix or run from inside 'nix develop'" >&2; exit 1; }
	exec nix "${NIX_FEATURES[@]}" develop "$REPO_ROOT" \
		--command env WHENCE_E2E_INSHELL=1 bash "$SCRIPT" "$@"
fi

# --- output helpers -----------------------------------------------------------
if [ -t 1 ]; then
	BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; BLU=$'\033[34m'; RST=$'\033[0m'
else
	BOLD=""; RED=""; GRN=""; YLW=""; BLU=""; RST=""
fi
say()  { printf '%b==>%b %s\n' "$BLU" "$RST" "$*"; }
ok()   { printf '  %bPASS%b %s\n' "$GRN" "$RST" "$*"; }
bad()  { printf '  %bFAIL%b %s\n' "$RED" "$RST" "$*"; }
warn() { printf '  %bSKIP%b %s\n' "$YLW" "$RST" "$*"; }
die()  { printf '%berror:%b %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

# --- preflight ----------------------------------------------------------------
[ "$(uname -s)" = "Linux" ] || die "eBPF e2e needs a Linux host"
command -v sudo >/dev/null 2>&1 || die "sudo is required (to grant eBPF caps via setcap)"
for t in go make gpg ssh-keygen; do
	command -v "$t" >/dev/null 2>&1 || die "$t missing — are you in the Nix dev shell? (run 'nix develop')"
done

# cap_bpf + cap_perfmon + cap_sys_admin load and attach the eBPF probes; the
# in-kernel request graph attributes agent-mediated touches with no extra caps.
CAPS="cap_bpf,cap_perfmon,cap_sys_admin+ep"
BIN="$REPO_ROOT/whence-touche"
TOUCH_TIMEOUT="${E2E_TOUCH_TIMEOUT:-60}"
WORK="$(mktemp -d)"
# The watcher (whence-touche) log goes to a persistent file so it — and the
# results appended at the end — survive cleanup() for post-run inspection. The
# per-tool scratch stays in $WORK (removed on exit). Override with E2E_LOG.
LOG="${E2E_LOG:-$REPO_ROOT/e2e/last-run.log}"
mkdir -p "$(dirname "$LOG")"

WATCHER=""
cleanup() {
	[ -n "$WATCHER" ] && kill "$WATCHER" 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# --- build --------------------------------------------------------------------
# A host version manager (mise/asdf) can leak a $GOROOT pointing at a different
# Go than the `go` on PATH, breaking the build with
#   compile: version "goX" does not match go tool version "goY"
# Drop it so the resolved `go` uses its own matching GOROOT, and pin the
# toolchain so Go doesn't try to fetch another. (flake.nix also prefers Nix Go.)
unset GOROOT
export GOTOOLCHAIN=local

say "Building whence-touche with the Nix toolchain ($(go version 2>/dev/null | awk '{print $3}'))…"
make -C "$REPO_ROOT" build >/dev/null || die "build failed"

# --- start the watcher --------------------------------------------------------
say "Granting eBPF caps (sudo) and starting the watcher (log-only notifier)…"
sudo setcap "$CAPS" "$BIN" || die "setcap failed"
WATCH_ARGS=(-notifier=log)
[ "${E2E_DEBUG:-0}" = "1" ] && WATCH_ARGS+=(-verbose)
"$BIN" "${WATCH_ARGS[@]}" >"$LOG" 2>&1 &
WATCHER=$!

for _ in $(seq 1 40); do
	grep -q "listening for YubiKey activity" "$LOG" 2>/dev/null && break
	kill -0 "$WATCHER" 2>/dev/null || { cat "$LOG" >&2; die "watcher exited before attaching (log: $LOG)"; }
	sleep 0.25
done
grep -q "listening for YubiKey activity" "$LOG" 2>/dev/null || { cat "$LOG" >&2; die "watcher never attached (log: $LOG)"; }
say "Watcher log → $LOG"

# --- detect what we can test --------------------------------------------------
GPG_KEY="${WHENCE_E2E_GPG_KEY:-}"
if [ -z "$GPG_KEY" ] && gpg --card-status >/dev/null 2>&1; then
	GPG_KEY="$(gpg -K --with-colons 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')"
fi

# --- result bookkeeping -------------------------------------------------------
declare -A STATUS DETAIL
ORDER=()
record() { ORDER+=("$1"); STATUS["$1"]="$2"; DETAIL["$1"]="$3"
	case "$2" in PASS) ok "$1 — $3";; FAIL) bad "$1 — $3";; SKIP) warn "$1 — $3";; esac; }

LOGMARK=0
mark()       { LOGMARK="$(wc -l <"$LOG" 2>/dev/null || echo 0)"; }
since_mark() { tail -n +"$((LOGMARK + 1))" "$LOG" 2>/dev/null; }
# touch_bodies: every classified body the watcher logged since the mark, pulled
# from `… touch needed touch="…" …`, tolerant of zerolog field ordering/quoting.
touch_bodies() {
	since_mark | grep -F "touch needed" |
		grep -oE 'touch=("[^"]*"|[^ ]*)' | sed -E 's/^touch=//; s/^"//; s/"$//'
}
# show_stack: with E2E_DEBUG, print the call stack (and agent-client resolution)
# the watcher logged since the mark, so a classification is explainable.
show_stack() {
	[ "${E2E_DEBUG:-0}" = "1" ] || return 0
	since_mark | grep -E 'call stack|gpg-agent client|ssh-agent client|process gone' |
		sed -E 's/^/     /'
}
# finish NAME TOKEN: PASS if a body logged since the mark contains TOKEN.
finish() {
	local bodies; bodies="$(touch_bodies)"
	if grep -q -- "$2" <<<"$bodies"; then
		record "$1" PASS "$(tail -1 <<<"$bodies")"
	else
		local saw; saw="$(paste -sd'|' - <<<"$bodies")"
		record "$1" FAIL "expected '$2', saw: ${saw:-<no touch detected>}"
	fi
	show_stack
}

# ask_run DESC: prompt to run/skip the next test. Auto-runs without a TTY.
ask_run() {
	[ -t 0 ] || return 0
	local reply
	printf '\n%b▶ next:%b %s\n   [Enter] run · [s] skip > ' "$BOLD" "$RST" "$1"
	read -r reply || return 0
	[ "$reply" = "s" ] || [ "$reply" = "S" ] && return 1
	return 0
}
touch_now() { printf '   touch your YubiKey when it blinks%s…\n' "${1:+ ($1)}"; }

# --- per-tool tests -----------------------------------------------------------
# Each: check prereqs (SKIP if missing) -> set up ephemeral artifacts using the
# real YubiKey credential -> run the operation that needs a touch -> assert the
# classifier named the tool.

test_gpg() {
	[ -n "$GPG_KEY" ] || { record gpg SKIP "no GPG secret key (set WHENCE_E2E_GPG_KEY)"; return; }
	ask_run "gpg — sign data with key $GPG_KEY" || { record gpg SKIP "skipped"; return; }
	touch_now "enter card PIN if prompted"; mark
	if printf 'whence-touche-e2e\n' |
		timeout "$TOUCH_TIMEOUT" gpg --local-user "$GPG_KEY" --sign -o /dev/null 2>"$WORK/gpg.err"; then
		finish gpg gpg
	else
		record gpg FAIL "gpg sign failed/timed out: $(tail -1 "$WORK/gpg.err" 2>/dev/null)"
	fi
}

test_pass() {
	command -v pass >/dev/null || { record pass SKIP "pass not installed"; return; }
	[ -n "$GPG_KEY" ] || { record pass SKIP "needs a GPG key"; return; }
	ask_run "pass — show (decrypt) an entry" || { record pass SKIP "skipped"; return; }
	export PASSWORD_STORE_DIR="$WORK/pass-store"
	pass init "$GPG_KEY" >"$WORK/pass.log" 2>&1 &&
		printf 'hunter2\n' | pass insert -e -f e2e/secret >>"$WORK/pass.log" 2>&1 ||
		{ record pass SKIP "pass setup failed: $(tail -1 "$WORK/pass.log")"; unset PASSWORD_STORE_DIR; return; }
	touch_now; mark
	if timeout "$TOUCH_TIMEOUT" pass show e2e/secret >/dev/null 2>>"$WORK/pass.log"; then
		finish pass pass
	else
		record pass FAIL "pass show failed/timed out (see $WORK/pass.log)"
	fi
	unset PASSWORD_STORE_DIR
}

test_gopass() {
	command -v gopass >/dev/null || { record gopass SKIP "gopass not installed"; return; }
	[ -n "$GPG_KEY" ] || { record gopass SKIP "needs a GPG key"; return; }
	ask_run "gopass — show (decrypt) an entry" || { record gopass SKIP "skipped"; return; }
	export GOPASS_HOMEDIR="$WORK/gopass"
	mkdir -p "$GOPASS_HOMEDIR"
	# --storage=fs: a plain, git-less store. The default gitfs backend makes a
	# SIGNED commit on both init and insert, each needing a card touch during
	# *setup* — three touches total ("gopass asks 3 times"), the first of which got
	# classified as gopass before the mark while the measured `show` collapsed into
	# the same scdaemon session. fs has no git, so the only touch is the `show`
	# decrypt below. (pass doesn't commit on init/insert, so it never hit this.)
	gopass --yes init --storage=fs "$GPG_KEY" >"$WORK/gopass.log" 2>&1 &&
		printf 'hunter2\n' | gopass --yes insert -f e2e/secret >>"$WORK/gopass.log" 2>&1 ||
		{ record gopass SKIP "gopass setup failed: $(tail -1 "$WORK/gopass.log")"; unset GOPASS_HOMEDIR; return; }
	touch_now; mark
	if timeout "$TOUCH_TIMEOUT" gopass --yes show -o e2e/secret >/dev/null 2>>"$WORK/gopass.log"; then
		finish gopass gopass
	else
		record gopass FAIL "gopass show failed/timed out (see $WORK/gopass.log)"
	fi
	unset GOPASS_HOMEDIR
}

test_sops() {
	command -v sops >/dev/null || { record sops SKIP "sops not installed"; return; }
	[ -n "$GPG_KEY" ] || { record sops SKIP "needs a GPG key (PGP backend)"; return; }
	ask_run "sops — decrypt a file (PGP backend)" || { record sops SKIP "skipped"; return; }
	local f="$WORK/secret.yaml"
	printf 'creation_rules:\n  - pgp: "%s"\n' "$GPG_KEY" >"$WORK/.sops.yaml"
	printf 'token: hunter2\n' >"$f"
	( cd "$WORK" && sops --encrypt --in-place "$f" ) >"$WORK/sops.log" 2>&1 ||
		{ record sops SKIP "sops encrypt failed: $(tail -1 "$WORK/sops.log")"; return; }
	touch_now; mark
	if ( cd "$WORK" && timeout "$TOUCH_TIMEOUT" sops --decrypt "$f" ) >/dev/null 2>>"$WORK/sops.log"; then
		finish sops sops
	else
		record sops FAIL "sops decrypt failed/timed out (see $WORK/sops.log)"
	fi
}

test_git() {
	command -v git >/dev/null || { record git SKIP "git not installed"; return; }
	[ -n "$GPG_KEY" ] || { record git SKIP "needs a GPG key (signed commit)"; return; }
	ask_run "git — create a GPG-signed commit" || { record git SKIP "skipped"; return; }
	local repo="$WORK/git-repo"
	git init -q "$repo"
	git -C "$repo" config user.email e2e@whence-touche
	git -C "$repo" config user.name "whence-touche e2e"
	git -C "$repo" config user.signingkey "$GPG_KEY"
	git -C "$repo" config gpg.program gpg
	touch_now "enter card PIN if prompted"; mark
	if timeout "$TOUCH_TIMEOUT" git -C "$repo" commit -S --allow-empty -m whence-touche-e2e \
		>"$WORK/git.log" 2>&1; then
		finish git git
	else
		record git FAIL "signed commit failed/timed out (see $WORK/git.log)"
	fi
}

test_ssh() {
	command -v ssh-keygen >/dev/null || { record ssh SKIP "ssh-keygen not installed"; return; }
	ask_run "ssh — generate an ephemeral FIDO sk-key (needs your FIDO2 PIN)" || { record ssh SKIP "skipped"; return; }
	touch_now "enter FIDO PIN if prompted"; mark
	if timeout "$TOUCH_TIMEOUT" ssh-keygen -t ed25519-sk -N '' -C whence-touche-e2e \
		-f "$WORK/id_sk" >"$WORK/ssh.log" 2>&1; then
		finish ssh ssh
	else
		record ssh FAIL "sk-key generation failed/timed out (FIDO PIN set? see $WORK/ssh.log)"
	fi
}

test_age() {
	command -v age >/dev/null || { record age SKIP "age not installed"; return; }
	command -v age-plugin-yubikey >/dev/null || { record age SKIP "age-plugin-yubikey missing"; return; }
	local recip
	recip="$(age-plugin-yubikey --list 2>/dev/null | grep -oE 'age1yubikey1[0-9a-z]+' | head -1)"
	[ -n "$recip" ] || { record age SKIP "no age-plugin-yubikey identity (PIV not set up)"; return; }
	ask_run "age — decrypt a file with your YubiKey (PIV)" || { record age SKIP "skipped"; return; }
	age-plugin-yubikey --identity >"$WORK/age-id.txt" 2>/dev/null
	printf 'hunter2\n' | age -r "$recip" -o "$WORK/secret.age" 2>"$WORK/age.err" ||
		{ record age SKIP "age encrypt failed: $(tail -1 "$WORK/age.err")"; return; }
	touch_now; mark
	if timeout "$TOUCH_TIMEOUT" age -d -i "$WORK/age-id.txt" "$WORK/secret.age" >/dev/null 2>>"$WORK/age.err"; then
		finish age age
	else
		record age FAIL "age decrypt failed/timed out (PIV touch policy? pcscd may attribute it elsewhere)"
	fi
}

test_browser() {
	if [ ! -t 0 ]; then record browser SKIP "manual test needs a TTY"; return; fi
	ask_run "browser — WebAuthn/passkey at webauthn.io (opens your default browser)" || { record browser SKIP "skipped"; return; }
	local url="https://webauthn.io"
	mark
	if command -v xdg-open >/dev/null 2>&1; then
		say "Opening $url in your default browser…"
		xdg-open "$url" >/dev/null 2>&1 &
	else
		say "Open $url in your browser."
	fi
	say "Register (or authenticate) a passkey there, and touch the key when prompted."
	read -r -p "   press Enter once the browser touch is done… " _
	local bodies; bodies="$(touch_bodies)"
	if grep -qE 'firefox|chrome|chromium|brave|opera|vivaldi' <<<"$bodies"; then
		record browser PASS "$(tail -1 <<<"$bodies")"
	else
		local saw; saw="$(paste -sd'|' - <<<"$bodies")"
		record browser FAIL "expected a browser, saw: ${saw:-<no touch detected>}"
	fi
	show_stack
}

test_1password() {
	if [ ! -t 0 ]; then record 1password SKIP "manual test needs a TTY"; return; fi
	ask_run "1password — unlock / sign in with your security key (desktop app or 'op')" || { record 1password SKIP "skipped"; return; }
	command -v op >/dev/null 2>&1 || say "('op' CLI not found — use the 1Password desktop app instead)"
	say "In 1Password, do something that prompts for your YubiKey — unlock with a"
	say "security key, or 'op signin' on an account whose 2FA is a security key —"
	say "and touch the key when it blinks."
	mark
	read -r -p "   press Enter once the 1Password touch is done… " _
	finish 1password 1password
}

# --- driver -------------------------------------------------------------------
ALL=(gpg pass gopass sops git ssh age browser 1password)
if [ "$#" -gt 0 ]; then SELECTED=("$@"); else SELECTED=("${ALL[@]}"); fi

say "Testing: ${SELECTED[*]}"
[ -n "$GPG_KEY" ] && say "Using GPG key: $GPG_KEY" || warn "no GPG key found — GPG-backed tests will be skipped"

for t in "${SELECTED[@]}"; do
	case " ${ALL[*]} " in
		*" $t "*) "test_$t" ;;
		*) record "$t" SKIP "unknown tool (have: ${ALL[*]})" ;;
	esac
done

# --- summary ------------------------------------------------------------------
echo
say "Summary"
pass=0 fail=0 skip=0
for t in "${ORDER[@]}"; do
	printf '  %-9s %-4s %s\n' "$t" "${STATUS[$t]}" "${DETAIL[$t]}"
	case "${STATUS[$t]}" in
		PASS) pass=$((pass + 1)) ;;
		FAIL) fail=$((fail + 1)) ;;
		SKIP) skip=$((skip + 1)) ;;
	esac
done
printf '\n  %b%d passed%b · %b%d failed%b · %b%d skipped%b\n' \
	"$GRN" "$pass" "$RST" "$RED" "$fail" "$RST" "$YLW" "$skip" "$RST"

# Append the verdicts to the watcher log so one file holds both the whence-touche
# output (call stacks, touch detections) and the per-tool results.
{
	echo
	echo "===== e2e results ($(date '+%Y-%m-%d %H:%M:%S')) ====="
	for t in "${ORDER[@]}"; do
		printf '  %-9s %-4s %s\n' "$t" "${STATUS[$t]}" "${DETAIL[$t]}"
	done
	printf '\n  %d passed · %d failed · %d skipped\n' "$pass" "$fail" "$skip"
} >>"$LOG"
say "Results + watcher log saved to ${BOLD}$LOG${RST}"

[ "$fail" -eq 0 ]
