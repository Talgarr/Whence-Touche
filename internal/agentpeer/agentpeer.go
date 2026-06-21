// Package agentpeer resolves the user-facing client process behind a request
// routed through a local agent daemon over a UNIX socket (gpg-agent, ssh-agent,
// …). The eBPF tracer attributes such requests to the agent's helper/daemon
// (scdaemon, ssh-sk-helper), not the tool that asked — because the tool reaches
// the key by *connecting to the agent's socket*, so it is a socket peer, not a
// process ancestor. This finds it by walking that socket's peer.
//
// Strategy (per resolver):
//  1. Find the agent's PID by scanning /proc/*/comm for AgentComm.
//  2. Enumerate the agent's socket inodes from /proc/<pid>/fd.
//  3. For each connected socket, query the kernel via UNIX_DIAG netlink to get
//     the peer inode (the client's end of the connection).
//  4. Find which PID holds that peer inode, skipping the agent's own internal
//     daemons (SkipComms) and our own process.
//
// This is reliable because the client keeps its socket connection open for the
// whole duration of the operation (the touch-wait window).
package agentpeer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	sockDiagByFamily = 20  // SOCK_DIAG_BY_FAMILY from linux/sock_diag.h
	unixDiagPeer     = 2   // UNIX_DIAG_PEER attribute type from linux/unix_diag.h
	udiagShowPeer    = 0x4 // UDIAG_SHOW_PEER from linux/unix_diag.h
)

// Resolver finds the client connected to a particular agent's socket.
type Resolver struct {
	// AgentComm is the comm name of the agent daemon, e.g. "gpg-agent".
	AgentComm string
	// skip is the set of peer comm names to ignore (internal daemons the agent
	// spawns that may also appear as socket peers).
	skip map[string]bool
}

// New builds a Resolver for an agent identified by comm, ignoring the given
// internal-daemon comms when picking the client peer.
func New(agentComm string, skipComms ...string) *Resolver {
	skip := make(map[string]bool, len(skipComms))
	for _, c := range skipComms {
		skip[c] = true
	}
	return &Resolver{AgentComm: agentComm, skip: skip}
}

// Predefined resolvers for the agents this project understands.
var (
	// GPGAgent: client behind a gpg-agent/scdaemon OpenPGP card operation.
	GPGAgent = New("gpg-agent", "scdaemon", "keyboxd")
	// SSHAgent: client behind an ssh-agent FIDO ("-sk") authentication.
	SSHAgent = New("ssh-agent", "ssh-sk-helper")
)

// FindClientPID returns the PID of the process connected to the agent, or 0 if
// none can be determined. It skips the configured internal daemons and self.
func (r *Resolver) FindClientPID() uint32 {
	selfPID := uint32(os.Getpid())
	agentPID := findCommPID(r.AgentComm)
	if agentPID == 0 {
		return 0
	}

	for _, ino := range socketInodesForPID(agentPID) {
		peerIno, err := socketPeerInode(ino)
		if err != nil || peerIno == 0 {
			continue
		}
		pid := pidForSocketInode(peerIno, agentPID)
		if pid == 0 || pid == selfPID {
			continue
		}
		if r.skip[commForPID(pid)] {
			continue
		}
		return pid
	}
	return 0
}

// commForPID returns the comm name for the given PID, or "" on error.
func commForPID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// findCommPID scans /proc for a process whose comm matches name.
func findCommPID(name string) uint32 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		var pid uint32
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil || pid == 0 {
			continue
		}
		if commForPID(pid) == name {
			return pid
		}
	}
	return 0
}

// socketInodesForPID returns all socket inodes open by pid.
func socketInodesForPID(pid uint32) []uint32 {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	var inodes []uint32
	for _, fd := range fds {
		link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, fd.Name()))
		if err != nil {
			continue
		}
		var ino uint32
		if _, err := fmt.Sscanf(link, "socket:[%d]", &ino); err == nil && ino != 0 {
			inodes = append(inodes, ino)
		}
	}
	return inodes
}

// socketPeerInode uses the UNIX socket diagnostic netlink protocol to return
// the peer socket inode for the given socket inode.
func socketPeerInode(ino uint32) (uint32, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	body := unixDiagReq{
		SdiagFamily: unix.AF_UNIX,
		UdiagStates: ^uint32(0), // all states
		UdiagIno:    ino,
		UdiagShow:   udiagShowPeer,
		UdiagCookie: [2]uint32{^uint32(0), ^uint32(0)},
	}

	var bodyBuf bytes.Buffer
	if err := binary.Write(&bodyBuf, binary.NativeEndian, body); err != nil {
		return 0, err
	}

	hdr := unix.NlMsghdr{
		Type:  sockDiagByFamily,
		Flags: unix.NLM_F_REQUEST,
		Len:   uint32(unix.SizeofNlMsghdr) + uint32(bodyBuf.Len()),
	}

	var msg bytes.Buffer
	if err := binary.Write(&msg, binary.NativeEndian, hdr); err != nil {
		return 0, err
	}
	msg.Write(bodyBuf.Bytes())

	if err := unix.Sendto(fd, msg.Bytes(), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, err
	}

	resp := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, resp, 0)
	if err != nil {
		return 0, err
	}

	msgs, err := syscall.ParseNetlinkMessage(resp[:n])
	if err != nil {
		return 0, err
	}

	diagHdrSize := binary.Size(unixDiagMsgHeader{})

	for _, nlmsg := range msgs {
		if nlmsg.Header.Type != sockDiagByFamily {
			continue
		}
		if len(nlmsg.Data) < diagHdrSize {
			continue
		}
		data := nlmsg.Data[diagHdrSize:]
		for len(data) >= 4 {
			rtaLen := binary.NativeEndian.Uint16(data[0:2])
			rtaType := binary.NativeEndian.Uint16(data[2:4])
			if rtaLen < 4 || int(rtaLen) > len(data) {
				break
			}
			if rtaType == unixDiagPeer && rtaLen >= 8 {
				return binary.NativeEndian.Uint32(data[4:8]), nil
			}
			aligned := (uint(rtaLen) + 3) &^ 3
			if int(aligned) >= len(data) {
				break
			}
			data = data[aligned:]
		}
	}
	return 0, nil
}

// pidForSocketInode returns the PID that has the given socket inode open,
// excluding excludePID.
func pidForSocketInode(targetIno uint32, excludePID uint32) uint32 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		var pid uint32
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil || pid == excludePID || pid == 0 {
			continue
		}
		if slices.Contains(socketInodesForPID(pid), targetIno) {
			return pid
		}
	}
	return 0
}

// unixDiagReq mirrors struct unix_diag_req from linux/unix_diag.h
type unixDiagReq struct {
	SdiagFamily   uint8
	SdiagProtocol uint8
	Pad           uint16
	UdiagStates   uint32
	UdiagIno      uint32
	UdiagShow     uint32
	UdiagCookie   [2]uint32
}

// unixDiagMsgHeader mirrors struct unix_diag_msg from linux/unix_diag.h (16 bytes)
type unixDiagMsgHeader struct {
	UdiagFamily uint8
	UdiagType   uint8
	UdiagState  uint8
	Pad         uint8
	UdiagIno    uint32
	UdiagCookie [2]uint32
}
