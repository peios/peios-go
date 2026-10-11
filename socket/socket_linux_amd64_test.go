package socket

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func pair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fds, e := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	a, b := os.NewFile(uintptr(fds[0]), "sender"), os.NewFile(uintptr(fds[1]), "receiver")
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}
func TestRightsAndTruncation(t *testing.T) {
	a, b := pair(t)
	f, e := os.Open("/dev/null")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if n, e := Send(a, []byte{1}, nil, []syscall.Conn{f}, 0); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	buf := make([]byte, 1)
	m, e := Receive(b, buf, 1, 0)
	if e != nil || len(m.Files) != 1 {
		t.Fatal(m, e)
	}
	fd := m.Files[0].Fd()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal(flags, errno)
	}
	m.Close()
	if _, e = Receive(b, buf, 0, syscall.MSG_DONTWAIT); !errors.Is(e, syscall.EAGAIN) {
		t.Fatal(e)
	}
	before, _ := os.ReadDir("/proc/self/fd")
	for range 32 {
		if _, e = Send(a, []byte{1}, nil, []syscall.Conn{f, f, f, f, f}, 0); e != nil {
			t.Fatal(e)
		}
		if _, e = Receive(b, buf, 0, 0); !errors.Is(e, syscall.EMSGSIZE) {
			t.Fatal(e)
		}
	}
	after, _ := os.ReadDir("/proc/self/fd")
	if len(after) != len(before) {
		t.Fatalf("fd leak %d => %d", len(before), len(after))
	}
}

func TestPartialAndEmptyMessage(t *testing.T) {
	a, b := pair(t)
	f, e := os.Open("/dev/null")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	// A zero-byte seqpacket can still carry descriptors; no dummy payload.
	if n, e := Send(a, nil, nil, []syscall.Conn{f}, 0); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	m, e := ReceivePartial(b, nil, 1, 0)
	if e != nil || m.N != 0 || len(m.Files) != 1 {
		t.Fatal(m, e)
	}
	m.Close()
	for _, count := range []int{0, 1, 2} {
		if _, e = Send(a, []byte("hello"), nil, []syscall.Conn{f, f}, 0); e != nil {
			t.Fatal(e)
		}
		buf := make([]byte, 1)
		m, e = ReceivePartial(b, buf, count, 0)
		if e != nil {
			t.Fatal(e)
		}
		if m.N != 1 || buf[0] != 'h' || len(m.Files) != count || m.Flags&syscall.MSG_TRUNC == 0 || (m.Flags&syscall.MSG_CTRUNC != 0) != (count < 2) {
			t.Fatal(m)
		}
		m.Close()
	}
}
