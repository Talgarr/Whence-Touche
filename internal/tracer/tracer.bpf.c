//go:build ignore

// tracer.bpf.c — kprobes reporting a process doing I/O to a security key.
//   hidraw_read/_write : FIDO/U2F/HMAC over /dev/hidrawN
//   proc_do_submiturb  : OpenPGP over usbfs/CCID, filtered to security-key
//                        vendors by idVendor (read via CO-RE, no vmlinux.h).
// Each runs in the caller's context, so bpf_get_current_pid_tgid() is the client.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Vendor IDs treated as security keys.
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

// Minimal CO-RE views; offsets relocated against the running kernel's BTF.
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
struct usb_device_descriptor {
	__u16 idVendor;
};
struct usb_device {
	struct usb_device_descriptor descriptor;
};
struct usb_dev_state {
	struct usb_device *dev;
};
struct pt_regs {
	unsigned long di; // x86_64 arg1
};
#pragma clang attribute pop

// event.flags bits.
#define EV_WRITE 0x1 // write (host->key) vs read
#define EV_CCID  0x2 // ccid (OpenPGP) vs hidraw (FIDO)

// Mirrored by rawEvent in tracer.go.
struct event {
	__u32 pid;
	__u8  flags;
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
	e->pid = bpf_get_current_pid_tgid() >> 32;
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

// proc_do_submiturb(struct usb_dev_state *ps, ...): usbfs URB submit.
SEC("kprobe/proc_do_submiturb")
int kprobe_proc_do_submiturb(struct pt_regs *ctx)
{
	struct usb_dev_state *ps = (struct usb_dev_state *)BPF_CORE_READ(ctx, di);
	__u16 vid = BPF_CORE_READ(ps, dev, descriptor.idVendor);
	if (!is_security_key_vid(vid))
		return 0;
	return emit(EV_CCID | EV_WRITE);
}
