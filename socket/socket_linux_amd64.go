// Package socket carries Peios identities over sockets. Received handles are
// close-on-exec and owned by the caller. Operations preserve concurrent Close.
package socket

import (
	"encoding/binary"
	"os"
	"syscall"
	"unsafe"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/token"
)

func SetImpersonationLevel(c syscall.Conn, level token.ImpersonationLevel) error {
	return set(c, uapi.KACS_SO_IMPERSONATION_LEVEL, int(level))
}
func ImpersonationLevel(c syscall.Conn) (level token.ImpersonationLevel, e error) {
	e = native.WithFD(c, func(fd int) error {
		n, err := syscall.GetsockoptInt(fd, uapi.SOL_KACS, uapi.KACS_SO_IMPERSONATION_LEVEL)
		level = token.ImpersonationLevel(n)
		return err
	})
	return
}
func SetPassToken(c syscall.Conn, on bool) error {
	n := 0
	if on {
		n = 1
	}
	return set(c, uapi.KACS_SO_PASS_TOKEN, n)
}
func Restamp(c syscall.Conn) error { return set(c, uapi.KACS_SO_RESTAMP, 1) }
func set(c syscall.Conn, opt, value int) error {
	return native.WithFD(c, func(fd int) error { return syscall.SetsockoptInt(fd, uapi.SOL_KACS, opt, value) })
}
func PeerToken(c syscall.Conn) (*token.Token, error) { return token.OpenPeer(c) }
func PeerPIDFD(c syscall.Conn) (out *os.File, e error) {
	e = native.WithFD(c, func(fd int) error {
		n, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, 77 /* SO_PEERPIDFD */)
		if err == nil {
			out = native.File(uintptr(n), "peios.peer-pidfd")
		}
		return err
	})
	return
}
func ImpersonatePeer(c syscall.Conn, fn func() error) error {
	t, e := PeerToken(c)
	if e != nil {
		return e
	}
	defer t.Close()
	return t.Impersonate(fn)
}

// Send sends one message. Partial writes are returned without retrying, because
// retrying would duplicate transferred identity/handles. A stream message with
// ancillary data must contain at least one payload byte.
func Send(c syscall.Conn, data []byte, identity *token.Token, files []syscall.Conn, flags int) (n int, e error) {
	if c == nil {
		return 0, syscall.EBADF
	}
	if len(files) > 253 {
		return 0, syscall.EINVAL
	}
	var rights []int
	var controls []byte
	var borrow func(int) error
	borrow = func(i int) error {
		if i < len(files) {
			return native.WithFD(files[i], func(fd int) error { rights = append(rights, fd); return borrow(i + 1) })
		}
		if len(rights) > 0 {
			controls = append(controls, syscall.UnixRights(rights...)...)
		}
		raw, err := c.SyscallConn()
		if err != nil {
			return err
		}
		var inner error
		err = raw.Write(func(fd uintptr) bool {
			if len(data) == 0 {
				n, _, _, inner = emptyMessage(fd, controls, flags|syscall.MSG_NOSIGNAL, false)
			} else {
				n, inner = syscall.SendmsgN(int(fd), data, controls, nil, flags|syscall.MSG_NOSIGNAL)
			}
			return flags&syscall.MSG_DONTWAIT != 0 || inner != syscall.EAGAIN && inner != syscall.EWOULDBLOCK
		})
		if err != nil {
			return err
		}
		return inner
	}
	if identity == nil {
		e = borrow(0)
		return
	}
	e = native.WithFD(identity, func(fd int) error {
		b := make([]byte, syscall.CmsgSpace(4))
		h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
		h.Level = uapi.SOL_KACS
		h.Type = uapi.KACS_SCM_TOKEN
		h.SetLen(syscall.CmsgLen(4))
		binary.LittleEndian.PutUint32(b[syscall.CmsgLen(0):], uint32(fd))
		controls = append(controls, b...)
		return borrow(0)
	})
	return
}

type Message struct {
	N, Flags int
	Token    *token.Token
	Files    []*os.File
	From     syscall.Sockaddr
}

func (m *Message) Close() {
	if m.Token != nil {
		m.Token.Close()
		m.Token = nil
	}
	for _, f := range m.Files {
		f.Close()
	}
	m.Files = nil
}

// Receive uses MSG_CMSG_CLOEXEC. Truncated control data closes all delivered
// handles and returns EMSGSIZE; payload truncation is visible in Flags.
func Receive(c syscall.Conn, data []byte, maxFiles int, flags int) (Message, error) {
	out, e := ReceivePartial(c, data, maxFiles, flags)
	if e == nil && out.Flags&syscall.MSG_CTRUNC != 0 {
		out.Close()
		e = syscall.EMSGSIZE
	}
	return out, e
}

// ReceivePartial preserves delivered payload and handles when control data is
// truncated, matching libpeios. Flags uses Linux MSG_TRUNC/MSG_CTRUNC values.
// Excess handles are closed; the caller must close the returned Message.
func ReceivePartial(c syscall.Conn, data []byte, maxFiles int, flags int) (out Message, e error) {
	if c == nil {
		return out, syscall.EBADF
	}
	if maxFiles < 0 {
		return out, syscall.EINVAL
	}
	if maxFiles > 253 {
		maxFiles = 253
	}
	size := syscall.CmsgSpace(4)
	if maxFiles > 0 {
		size += syscall.CmsgSpace(maxFiles * 4)
	}
	control := make([]byte, size)
	raw, e := c.SyscallConn()
	if e != nil {
		return out, e
	}
	var used int
	var inner error
	e = raw.Read(func(fd uintptr) bool {
		if len(data) == 0 {
			out.N, used, out.Flags, inner = emptyMessage(fd, control, flags|syscall.MSG_CMSG_CLOEXEC, true)
		} else {
			out.N, used, out.Flags, out.From, inner = syscall.Recvmsg(int(fd), data, control, flags|syscall.MSG_CMSG_CLOEXEC)
		}
		return flags&syscall.MSG_DONTWAIT != 0 || inner != syscall.EAGAIN && inner != syscall.EWOULDBLOCK
	})
	if e != nil {
		return out, e
	}
	if inner != nil {
		return out, inner
	}
	defer func() {
		if e != nil {
			out.Close()
		}
	}()
	messages, err := syscall.ParseSocketControlMessage(control[:used])
	if err != nil {
		return out, err
	}
	for _, m := range messages {
		switch {
		case m.Header.Level == syscall.SOL_SOCKET && m.Header.Type == syscall.SCM_RIGHTS:
			fds, err := syscall.ParseUnixRights(&m)
			if err != nil {
				e = err
				continue
			}
			for _, fd := range fds {
				if len(out.Files) < maxFiles {
					out.Files = append(out.Files, native.File(uintptr(fd), "peios.received-fd"))
				} else {
					syscall.Close(fd)
					out.Flags |= syscall.MSG_CTRUNC
				}
			}
		case m.Header.Level == uapi.SOL_KACS && m.Header.Type == uapi.KACS_SCM_TOKEN:
			if len(m.Data) != 4 {
				e = syscall.EPROTO
				continue
			}
			fd := int(int32(binary.LittleEndian.Uint32(m.Data)))
			if fd < 0 {
				e = syscall.EPROTO
				continue
			}
			t := token.TakeFile(native.File(uintptr(fd), "peios.message-token"))
			if out.Token != nil {
				t.Close()
				out.Flags |= syscall.MSG_CTRUNC
			} else {
				out.Token = t
			}
		}
	}

	return
}

// Go's syscall helpers inject a dummy payload byte for empty ancillary sends.
// Use the native zero-length iovec to retain datagram/seqpacket semantics.
func emptyMessage(fd uintptr, control []byte, flags int, receive bool) (n, used, outflags int, e error) {
	var iov syscall.Iovec
	hdr := syscall.Msghdr{Iov: &iov, Iovlen: 1}
	if len(control) > 0 {
		hdr.Control = &control[0]
		hdr.SetControllen(len(control))
	}
	call := uintptr(syscall.SYS_SENDMSG)
	if receive {
		call = syscall.SYS_RECVMSG
	}
	v, _, errno := syscall.Syscall(call, fd, uintptr(unsafe.Pointer(&hdr)), uintptr(flags))
	if errno != 0 {
		return 0, 0, 0, errno
	}
	return int(v), int(hdr.Controllen), int(hdr.Flags), nil
}
