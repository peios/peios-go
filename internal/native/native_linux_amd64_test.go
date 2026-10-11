package native

import (
	"errors"
	"syscall"
	"testing"
)

func TestBufferGrowthAndErrors(t *testing.T) {
	calls := 0
	b, e := Buffer(func(b []byte) (uint32, error) {
		calls++
		if len(b) < 3 {
			return 3, syscall.ERANGE
		}
		if len(b) < 5 {
			return 5, nil
		}
		copy(b, "hello")
		return 5, nil
	})
	if e != nil || string(b) != "hello" || calls != 3 {
		t.Fatalf("%q %v %d", b, e, calls)
	}
	for _, tc := range []struct {
		n         uint32
		err, want error
	}{{0, syscall.ERANGE, syscall.EPROTO}, {0, syscall.EACCES, syscall.EACCES}, {1 << 30, nil, syscall.EOVERFLOW}} {
		_, e = Buffer(func([]byte) (uint32, error) { return tc.n, tc.err })
		if !errors.Is(e, tc.want) {
			t.Fatal(e)
		}
	}
}
