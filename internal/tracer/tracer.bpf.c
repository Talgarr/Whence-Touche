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
	unsigned long si; // x86_64 arg2
	unsigned long ax; // x86_64 return value
};
// For the agent connect/accept graph: an accepted unix socket's sk_peer_pid is
// the connecting client's pid (set by the kernel at connect via init_peercred).
struct upid {
	int nr;
};
struct pid {
	struct upid numbers[1];
};
struct sock {
	struct pid *sk_peer_pid;
};
struct socket {
	struct sock *sk;
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

// --- agent request graph ----------------------------------------------------
// A touch through gpg-agent/ssh-agent is reported (via scdaemon/ssh-sk-helper)
// without the real client in its process tree. The client is a socket peer of the
// agent; the question is *which* peer, since an agent can hold several connections
// at once. The assuan and ssh-agent protocols are synchronous and the single
// physical key serializes touches, so "the client of the current touch" is exactly
// the one whose request the agent most recently read. We capture that in two steps:
//   unix_accept (return)  — mark every socket the agent accepts from a client in
//                           client_socks. This tells a client connection apart from
//                           the agent's own link to scdaemon/keyboxd, which it
//                           connects to and never accepts.
//   unix_stream_recvmsg   — when the agent reads a request on a marked socket,
//                           record its peer in agent_clients[kind]. This fires at
//                           the moment causally tied to the touch, not at connect
//                           time — which is what removes the connect-vs-touch race
//                           the old accept-time capture had.

#define AGENT_GPG 0
#define AGENT_SSH 1

struct client_info {
	__u32 pid;
	__u32 _pad;
	__u64 ts; // bpf_ktime_get_ns at the request read, for staleness/debugging
};

// Client whose request the agent most recently read, per agent kind; read by
// tracer.go (AgentClientPID).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct client_info);
} agent_clients SEC(".maps");

// client_socks marks the unix sockets an agent accepted from clients (value =
// AGENT_* kind). Populated at unix_accept return, consulted on every
// unix_stream_recvmsg. LRU so a closed connection ages out without a teardown
// hook: a sk address later reused by a different socket is harmless — it is
// re-marked at the next accept if it is a client, and the real request-read just
// before a touch overwrites any stale agent_clients entry.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);   // struct sock *
	__type(value, __u32); // AGENT_* kind
} client_socks SEC(".maps");

// Carries the accepted socket from the unix_accept entry to its return (where
// the socket's ->sk is grafted), keyed by pid_tgid.
struct accept_ctx {
	__u64 newsock;
	__u32 kind;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, struct accept_ctx);
} accept_scratch SEC(".maps");

// comm_is reports whether the NUL-terminated comm equals name.
static __always_inline int comm_is(const char *comm, const char *name)
{
#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (comm[i] != name[i])
			return 0;
		if (name[i] == 0)
			return 1;
	}
	return 1;
}

// agent_kind maps the current task's comm to an AGENT_* kind, or -1.
static __always_inline int agent_kind(void)
{
	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));
	if (comm_is(comm, "gpg-agent"))
		return AGENT_GPG;
	if (comm_is(comm, "ssh-agent"))
		return AGENT_SSH;
	return -1;
}

// unix_accept(struct socket *sock, struct socket *newsock, int flags, bool kern)
SEC("kprobe/unix_accept")
int kprobe_unix_accept(struct pt_regs *ctx)
{
	int kind = agent_kind();
	if (kind < 0)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	struct accept_ctx ac = {};
	ac.newsock = BPF_CORE_READ(ctx, si); // arg2: newsock (->sk set by return)
	ac.kind = (__u32)kind;
	bpf_map_update_elem(&accept_scratch, &id, &ac, BPF_ANY);
	return 0;
}

SEC("kretprobe/unix_accept")
int kretprobe_unix_accept(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct accept_ctx *ac = bpf_map_lookup_elem(&accept_scratch, &id);
	if (!ac)
		return 0;
	if ((long)BPF_CORE_READ(ctx, ax) != 0) // accept failed
		goto out;

	// ->sk is grafted onto newsock by the time accept returns. Mark it as a client
	// connection of this agent kind; the peer pid is read later, when the agent
	// actually reads a request on it (kprobe_unix_stream_recvmsg).
	struct socket *newsock = (struct socket *)ac->newsock;
	struct sock *sk = BPF_CORE_READ(newsock, sk);
	if (sk) {
		__u64 key = (__u64)sk;
		__u32 kind = ac->kind;
		bpf_map_update_elem(&client_socks, &key, &kind, BPF_ANY);
	}
out:
	bpf_map_delete_elem(&accept_scratch, &id);
	return 0;
}

// unix_stream_recvmsg(struct socket *sock, struct msghdr *msg, size_t len, int flags)
// The agent reading a request from one of its client connections. Synchronous
// agent protocols plus a serializing physical key make this read the event
// causally tied to the imminent touch, so this — not accept — is where we pin the
// client. Hot-path note: this fires on every unix-stream recv system-wide; the
// single client_socks lookup rejects all non-agent-client reads in one step.
SEC("kprobe/unix_stream_recvmsg")
int kprobe_unix_stream_recvmsg(struct pt_regs *ctx)
{
	struct socket *sock = (struct socket *)BPF_CORE_READ(ctx, di);
	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (!sk)
		return 0;
	__u64 key = (__u64)sk;
	__u32 *kind = bpf_map_lookup_elem(&client_socks, &key);
	if (!kind)
		return 0; // not an agent's client connection — the common case

	struct pid *peer = BPF_CORE_READ(sk, sk_peer_pid);
	if (!peer)
		return 0;
	struct client_info ci = {};
	ci.pid = BPF_CORE_READ(peer, numbers[0].nr);
	ci.ts = bpf_ktime_get_ns();
	if (ci.pid) {
		__u32 k = *kind;
		bpf_map_update_elem(&agent_clients, &k, &ci, BPF_ANY);
	}
	return 0;
}
