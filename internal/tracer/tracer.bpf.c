//go:build ignore

// tracer.bpf.c — kprobe-based YubiKey/security-key I/O tracer.
//
// Captures the PID of the process talking to a security key, across BOTH
// interfaces the key exposes:
//
//   * FIDO/U2F + HMAC  -> /dev/hidrawN (usbhid). Kprobe hidraw_read/_write.
//   * OpenPGP (CCID)   -> the CCID interface is bound to *usbfs*; scdaemon's
//     internal CCID driver talks to it via libusb, i.e. ioctl(USBDEVFS_SUBMITURB)
//     -> proc_do_submiturb(). Kprobe that.
//
// All three functions execute *in the context of the calling userspace process*,
// so bpf_get_current_pid_tgid() here is exactly the process that issued the I/O.
// (For CCID that process is scdaemon — the user-facing client is resolved from
// the gpg-agent socket peer in userspace.)
//
// usbfs is generic, so proc_do_submiturb() fires for every libusb user
// (fingerprint readers via fprintd, webcams, ...). We read the URB's target USB
// device's idVendor from arg0 and emit a ccid event ONLY when the vendor is in
// our security-key allow-list. The vendor id is used only to decide *whether* to
// emit, so it is not carried in the event.
//
// No bpftool required: instead of a full vmlinux.h we hand-declare just the few
// fields we touch and let CO-RE relocate their offsets at load time against
// /sys/kernel/btf/vmlinux.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Vendor IDs whose USB devices we treat as security keys. Currently just Yubico;
// add other FIDO/security-key vendors here (e.g. Feitian, SoloKeys, Nitrokey).
static const __u16 security_key_vids[] = {
	0x1050, // Yubico
};

static __always_inline int is_security_key_vid(__u16 vid)
{
#pragma unroll
	for (unsigned int i = 0; i < sizeof(security_key_vids) / sizeof(security_key_vids[0]); i++) {
		if (security_key_vids[i] == vid)
			return 1;
	}
	return 0;
}

// Minimal CO-RE "views" of kernel types: only the field we read (idVendor).
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
struct usb_device_descriptor {
	__u16 idVendor;
};
struct usb_device {
	struct usb_device_descriptor descriptor; // embedded, not a pointer
};
struct usb_dev_state {
	struct usb_device *dev;
};
// x86_64 kprobe context: 1st integer arg is in 'di'.
struct pt_regs {
	unsigned long di;
};
#pragma clang attribute pop

// event.flags bits — source and direction packed into one byte.
#define EV_WRITE 0x1 // set: write (host->key); clear: read (key->host)
#define EV_CCID  0x2 // set: ccid/usbfs (OpenPGP); clear: hidraw (FIDO/U2F/HMAC)

// Mirrored by `type rawEvent struct` in tracer.go. Keep field order/sizes in sync.
struct event {
	__u32 pid;   // process (TGID) that issued the I/O
	__u8  flags; // EV_WRITE | EV_CCID
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int emit(__u8 flags)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32; // high 32 bits = TGID
	e->flags = flags;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/hidraw_write")
int kprobe_hidraw_write(void *ctx)
{
	return emit(EV_WRITE);
}

SEC("kprobe/hidraw_read")
int kprobe_hidraw_read(void *ctx)
{
	return emit(0);
}

SEC("kprobe/proc_do_submiturb")
int kprobe_proc_do_submiturb(struct pt_regs *ctx)
{
	struct usb_dev_state *ps = (struct usb_dev_state *)BPF_CORE_READ(ctx, di);

	__u16 vid = BPF_CORE_READ(ps, dev, descriptor.idVendor);
	if (!is_security_key_vid(vid))
		return 0;

	return emit(EV_CCID | EV_WRITE);
}
