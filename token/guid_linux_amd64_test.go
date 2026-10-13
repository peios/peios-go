package token

import (
	"errors"
	"syscall"
	"testing"
)

func TestGUIDClosedToken(t *testing.T) {
	for _, tok := range []*Token{nil, {}} {
		guid, err := tok.GUID()
		if !errors.Is(err, syscall.EBADF) || guid != [16]byte{} {
			t.Fatalf("GUID on closed token: %x, %v", guid, err)
		}
	}
}
