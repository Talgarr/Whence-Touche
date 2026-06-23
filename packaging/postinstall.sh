#!/bin/sh
set -e

BIN=/usr/bin/whence-touche
CAPS=cap_bpf,cap_perfmon,cap_sys_admin+ep

if command -v setcap >/dev/null 2>&1; then
    setcap "$CAPS" "$BIN" || \
        echo "whence-touche: could not setcap $BIN — run it as root or set caps manually" >&2
else
    echo "whence-touche: 'setcap' not found (install libcap); run as root or set caps manually" >&2
fi

cat <<'MSG'
==> Enable it for your user:  systemctl --user enable --now whence-touche.service
==> Requires a notification daemon (dunst/mako/swaync) and a kernel with
    eBPF + BTF (/sys/kernel/btf/vmlinux), i.e. Linux >= 5.8.
MSG

exit 0
