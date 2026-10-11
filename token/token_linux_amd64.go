// Package token manages Peios access tokens. Impersonation is callback-scoped
// on a dedicated OS thread; it never changes the caller goroutine's identity.
package token

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/security"
)

// Token owns an fd. The zero value is closed. Close and other methods may run
// concurrently; the descriptor cannot be reused while an operation borrows it.
type Token struct{ f *os.File }

func (t *Token) SyscallConn() (syscall.RawConn, error) {
	if t == nil || t.f == nil {
		return nil, syscall.EBADF
	}
	return t.f.SyscallConn()
}
func (t *Token) Close() error {
	if t == nil || t.f == nil {
		return syscall.EBADF
	}
	return t.f.Close()
}
func opened(fd uintptr, e error) (*Token, error) {
	if e != nil {
		return nil, e
	}
	return &Token{native.File(fd, "peios.token")}, nil
}
func OpenSelf(flags uint32, access Access) (*Token, error) {
	return opened(native.Call(uapi.SYS_KACS_OPEN_SELF_TOKEN, uintptr(flags), uintptr(access)))
}
func OpenProcess(pidfd syscall.Conn, access Access) (out *Token, e error) {
	e = native.WithFD(pidfd, func(fd int) error {
		var err error
		out, err = opened(native.Call(uapi.SYS_KACS_OPEN_PROCESS_TOKEN, uintptr(fd), uintptr(access)))
		return err
	})
	return
}
func OpenThread(pidfd syscall.Conn, tid int, access Access) (out *Token, e error) {
	e = native.WithFD(pidfd, func(fd int) error {
		var err error
		out, err = opened(native.Call(uapi.SYS_KACS_OPEN_THREAD_TOKEN, uintptr(fd), uintptr(tid), uintptr(access)))
		return err
	})
	return
}
func OpenPeer(sock syscall.Conn) (out *Token, e error) {
	e = native.WithFD(sock, func(fd int) error {
		n, err := syscall.GetsockoptInt(fd, uapi.SOL_KACS, uapi.KACS_SO_PEER_TOKEN)
		if err != nil {
			return err
		}
		out = &Token{native.File(uintptr(n), "peios.peer-token")}
		return nil
	})
	return
}
func Create(spec []byte) (*Token, error) {
	var p native.Pins
	defer p.Unpin()
	return opened(native.Call(uapi.SYS_KACS_CREATE_TOKEN, p.Bytes(spec), uintptr(len(spec))))
}
func (t *Token) Query(class Class) (out []byte, e error) {
	e = native.WithFD(t, func(fd int) error {
		var err error
		out, err = native.Buffer(func(b []byte) (uint32, error) {
			var p native.Pins
			defer p.Unpin()
			a := uapi.Kacs_query_args{Token_class: uint32(class), Buf_len: uint32(len(b)), Buf_ptr: uint64(p.Bytes(b))}
			e := native.Ioctl(fd, uapi.KACS_IOC_QUERY, unsafe.Pointer(&a))
			return a.Buf_len, e
		})
		return err
	})
	return
}
func (t *Token) UserSID() (security.SID, error) {
	b, e := t.Query(User)
	if e != nil {
		return security.SID{}, e
	}
	return security.SIDFromBytes(b)
}
func (t *Token) Uint32(class Class) (uint32, error) {
	b, e := t.Query(class)
	if e != nil {
		return 0, e
	}
	if len(b) != 4 {
		return 0, syscall.EPROTO
	}
	return binary.LittleEndian.Uint32(b), nil
}

type PrivilegeSet struct{ Present, Enabled, EnabledByDefault, Used uint64 }

func (t *Token) Privileges() (PrivilegeSet, error) {
	b, e := t.Query(Privileges)
	if e != nil {
		return PrivilegeSet{}, e
	}
	if len(b) != 32 {
		return PrivilegeSet{}, syscall.EPROTO
	}
	return PrivilegeSet{binary.LittleEndian.Uint64(b), binary.LittleEndian.Uint64(b[8:]), binary.LittleEndian.Uint64(b[16:]), binary.LittleEndian.Uint64(b[24:])}, nil
}

type TokenStatistics struct {
	TokenID, AuthID, ModifiedID uint64
	Type                        Type
	Expiration                  uint64
}

func (t *Token) Statistics() (TokenStatistics, error) {
	b, e := t.Query(Statistics)
	if e != nil {
		return TokenStatistics{}, e
	}
	if len(b) != 40 {
		return TokenStatistics{}, syscall.EPROTO
	}
	return TokenStatistics{binary.LittleEndian.Uint64(b), binary.LittleEndian.Uint64(b[8:]), binary.LittleEndian.Uint64(b[16:]), Type(binary.LittleEndian.Uint32(b[24:])), binary.LittleEndian.Uint64(b[32:])}, nil
}
func (t *Token) Duplicate(access Access, kind Type, level ImpersonationLevel) (out *Token, e error) {
	e = native.WithFD(t, func(fd int) error {
		a := uapi.Kacs_duplicate_args{Access_mask: uint32(access), Token_type: uint32(kind), Impersonation_level: uint32(level), Result_fd: -1}
		if err := native.Ioctl(fd, uapi.KACS_IOC_DUPLICATE, unsafe.Pointer(&a)); err != nil {
			return err
		}
		if a.Result_fd < 0 {
			return syscall.EPROTO
		}
		out = &Token{native.File(uintptr(a.Result_fd), "peios.token")}
		return nil
	})
	return
}
func (t *Token) Linked() (out *Token, e error) {
	e = native.WithFD(t, func(fd int) error {
		a := uapi.Kacs_get_linked_token_args{Result_fd: -1}
		if err := native.Ioctl(fd, uapi.KACS_IOC_GET_LINKED_TOKEN, unsafe.Pointer(&a)); err != nil {
			return err
		}
		if a.Result_fd < 0 {
			return syscall.EPROTO
		}
		out = &Token{native.File(uintptr(a.Result_fd), "peios.linked-token")}
		return nil
	})
	return
}
func (t *Token) SetInteractivityScope(scope uint32) error {
	return native.WithFD(t, func(fd int) error {
		return native.Ioctl(fd, uapi.KACS_IOC_ADJUST_INTERACTIVITY_SCOPE, unsafe.Pointer(&scope))
	})
}

// Install replaces the process primary identity. The kernel enforces authority.
func (t *Token) Install() error {
	return native.WithFD(t, func(fd int) error { return native.Ioctl(fd, uapi.KACS_IOC_INSTALL, nil) })
}

// Impersonate executes fn on a dedicated locked goroutine, then reverts. A
// failed revert retires that OS thread. Goroutines started by fn do not inherit
// this identity. A panic in fn is rethrown in the caller after cleanup.
func (t *Token) Impersonate(fn func() error) error {
	if fn == nil {
		return syscall.EINVAL
	}
	return impersonate(func() error {
		return native.WithFD(t, func(fd int) error { return native.Ioctl(fd, uapi.KACS_IOC_IMPERSONATE, nil) })
	}, func() error { _, e := native.Call(uapi.SYS_KACS_REVERT); return e }, fn)
}
func impersonate(set, revert, fn func() error) error {
	type result struct {
		err        error
		panicValue any
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		active, done := false, false
		var r result
		defer func() {
			r.panicValue = recover()
			if active {
				if e := revert(); e != nil {
					r.err = errors.Join(r.err, fmt.Errorf("peios/token: revert: %w", e))
				} else {
					runtime.UnlockOSThread()
				}
			} else {
				runtime.UnlockOSThread()
			}
			if !done && r.panicValue == nil {
				r.err = errors.Join(r.err, errors.New("peios/token: callback exited its goroutine"))
			}
			ch <- r
		}()
		if e := set(); e != nil {
			r.err = e
			done = true
			return
		}
		active = true
		r.err = fn()
		done = true
	}()
	r := <-ch
	if r.panicValue != nil {
		panic(r.panicValue)
	}
	return r.err
}
