package token

import (
	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"sync/atomic"
	"syscall"
)

// IdentityThread permits repeated impersonate/revert operations within one
// WithIdentityThread callback. It must not be retained or used by a goroutine
// other than the callback. The enclosing scope always reverts before exit.
type IdentityThread struct{ tid atomic.Int64 }

func (s *IdentityThread) check() error {
	if s == nil || s.tid.Load() != int64(syscall.Gettid()) {
		return syscall.EPERM
	}
	return nil
}

// WithIdentityThread runs fn on a dedicated locked OS thread. The scope has the
// process identity initially. Panics and Goexit receive the same cleanup as
// Token.Impersonate; a thread whose final revert fails is retired.
func WithIdentityThread(fn func(*IdentityThread) error) error {
	if fn == nil {
		return syscall.EINVAL
	}
	return impersonate(func() error { return nil }, func() error { _, e := native.Call(uapi.SYS_KACS_REVERT); return e }, func() error {
		s := &IdentityThread{}
		s.tid.Store(int64(syscall.Gettid()))
		defer func() { s.tid.Store(0) }()
		return fn(s)
	})
}
func (s *IdentityThread) Impersonate(t *Token) error {
	if e := s.check(); e != nil {
		return e
	}
	return native.WithFD(t, func(fd int) error { return native.Ioctl(fd, uapi.KACS_IOC_IMPERSONATE, nil) })
}
func (s *IdentityThread) Revert() error {
	if e := s.check(); e != nil {
		return e
	}
	_, e := native.Call(uapi.SYS_KACS_REVERT)
	return e
}
func (s *IdentityThread) ImpersonatePeer(c syscall.Conn) error {
	if e := s.check(); e != nil {
		return e
	}
	t, e := OpenPeer(c)
	if e != nil {
		return e
	}
	defer t.Close()
	return s.Impersonate(t)
}
