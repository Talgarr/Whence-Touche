// Package agentpeer finds the client behind a request routed through a local
// agent socket (gpg-agent, ssh-agent). The tracer attributes such requests to
// the agent's helper (scdaemon, ssh-sk-helper); the real client is a socket
// peer of the agent, found via UNIX_DIAG netlink.
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
	sockDiagByFamily = 20  // SOCK_DIAG_BY_FAMILY
	unixDiagPeer     = 2   // UNIX_DIAG_PEER
	udiagShowPeer    = 0x4 // UDIAG_SHOW_PEER
)

// Resolver finds the client connected to a given agent's socket.
type Resolver struct {
	AgentComm string
	skip      map[string]bool
}

// New builds a Resolver, ignoring the given internal-daemon comms as peers.
func New(agentComm string, skipComms ...string) *Resolver {
	skip := make(map[string]bool, len(skipComms))
	for _, c := range skipComms {
		skip[c] = true
	}
	return &Resolver{AgentComm: agentComm, skip: skip}
}

var (
	GPGAgent = New("gpg-agent", "scdaemon", "keyboxd")
	SSHAgent = New("ssh-agent", "ssh-sk-helper")
)

// FindClientPID returns the agent's connected client PID, or 0.
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
		if pid == 0 || pid == selfPID || r.skip[commForPID(pid)] {
			continue
		}
		return pid
	}
	return 0
}

func commForPID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

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

func socketInodesForPID(pid uint32) []uint32 {
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return nil
	}
	var inodes []uint32
	for _, fd := range fds {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
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

// socketPeerInode returns the peer socket inode for ino via UNIX_DIAG netlink.
func socketPeerInode(ino uint32) (uint32, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	body := unixDiagReq{
		SdiagFamily: unix.AF_UNIX,
		UdiagStates: ^uint32(0),
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
		if nlmsg.Header.Type != sockDiagByFamily || len(nlmsg.Data) < diagHdrSize {
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

func pidForSocketInode(targetIno, excludePID uint32) uint32 {
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

// unixDiagReq mirrors struct unix_diag_req.
type unixDiagReq struct {
	SdiagFamily   uint8
	SdiagProtocol uint8
	Pad           uint16
	UdiagStates   uint32
	UdiagIno      uint32
	UdiagShow     uint32
	UdiagCookie   [2]uint32
}

// unixDiagMsgHeader mirrors struct unix_diag_msg (16 bytes).
type unixDiagMsgHeader struct {
	UdiagFamily uint8
	UdiagType   uint8
	UdiagState  uint8
	Pad         uint8
	UdiagIno    uint32
	UdiagCookie [2]uint32
}
