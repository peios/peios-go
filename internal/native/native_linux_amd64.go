// Package native contains the Linux/amd64 Peios syscall boundary.
package native

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// Pins keeps every address stored in a UAPI integer stable through the call.
// Callers must defer Unpin before constructing arguments. This also forces
// stack-backed data to escape: KeepAlive alone would not prevent stack moves.
type Pins struct{ runtime.Pinner }

func (p *Pins) Pointer(v unsafe.Pointer) uintptr {
	if v == nil {
		return 0
	}
	p.Pin(v)
	return uintptr(v)
}
func (p *Pins) Bytes(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	return p.Pointer(unsafe.Pointer(&b[0]))
}
func (p *Pins) String(s string) (uintptr, error) {
	b, e := syscall.ByteSliceFromString(s)
	if e != nil {
		return 0, e
	}
	return p.Bytes(b), nil
}
func Call(number uintptr, args ...uintptr) (uintptr, error) {
	if len(args) > 6 {
		panic("too many syscall arguments")
	}
	var a [6]uintptr
	copy(a[:], args)
	r, _, e := syscall.Syscall6(number, a[0], a[1], a[2], a[3], a[4], a[5])
	if e != 0 {
		return 0, e
	}
	return r, nil
}
func Ioctl(fd int, request uintptr, p unsafe.Pointer) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(p))
	if e != 0 {
		return e
	}
	return nil
}

// WithFD protects a borrowed descriptor from a concurrent Close. The callback
// must not retain the number or change blocking mode.
func WithFD(conn syscall.Conn, fn func(int) error) error {
	if conn == nil {
		return syscall.EBADF
	}
	raw, e := conn.SyscallConn()
	if e != nil {
		return e
	}
	var inner error
	e = raw.Control(func(fd uintptr) { inner = fn(int(fd)) })
	if e != nil {
		return e
	}
	return inner
}
func File(fd uintptr, name string) *os.File { return os.NewFile(fd, name) }
func Buffer(query func([]byte) (uint32, error)) ([]byte, error) {
	var b []byte
	for tries := 0; tries < 8; tries++ {
		n, e := query(b)
		if e != nil && !errors.Is(e, syscall.ERANGE) {
			return nil, e
		}
		if e == nil && uint64(n) <= uint64(len(b)) {
			return b[:n], nil
		}
		if n > 16*1024*1024 {
			return nil, syscall.EOVERFLOW
		}
		if int(n) <= len(b) {
			return nil, syscall.EPROTO
		}
		b = make([]byte, n)
	}
	return nil, syscall.EAGAIN
}
