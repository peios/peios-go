package token

import (
	"errors"
	"runtime"
	"syscall"
	"testing"
)

func TestImpersonationThreadAndCleanup(t *testing.T) {
	sentinel := errors.New("callback")
	revertErr := errors.New("revert")
	for _, mode := range []string{"return", "panic", "goexit", "revert-fails", "set-fails"} {
		t.Run(mode, func(t *testing.T) {
			var tid, called, reverted int
			set := func() error {
				tid = syscall.Gettid()
				if mode == "set-fails" {
					return sentinel
				}
				return nil
			}
			revert := func() error {
				reverted++
				if syscall.Gettid() != tid {
					t.Error("revert moved threads")
				}
				if mode == "revert-fails" {
					return revertErr
				}
				return nil
			}
			fn := func() error {
				called++
				for i := 0; i < 20; i++ {
					runtime.Gosched()
					if syscall.Gettid() != tid {
						t.Error("identity moved threads")
					}
				}
				if mode == "panic" {
					panic(sentinel)
				}
				if mode == "goexit" {
					runtime.Goexit()
				}
				return sentinel
			}
			var got error
			var pan any
			func() { defer func() { pan = recover() }(); got = impersonate(set, revert, fn) }()
			if mode == "set-fails" {
				if called != 0 || reverted != 0 {
					t.Fatal("ran after failed setup")
				}
				return
			}
			if called != 1 || reverted != 1 {
				t.Fatal("missing callback/revert")
			}
			if mode == "panic" {
				if pan != sentinel {
					t.Fatal("panic lost")
				}
				return
			}
			if mode == "goexit" {
				if got == nil {
					t.Fatal("Goexit silently succeeded")
				}
				return
			}
			if !errors.Is(got, sentinel) {
				t.Fatal("callback error lost")
			}
			if mode == "revert-fails" && !errors.Is(got, revertErr) {
				t.Fatal("revert error lost")
			}
		})
	}
}
