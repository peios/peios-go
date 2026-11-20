package file

import (
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/peios/peios-go/internal/uapi"
)

func TestOpenErrorKeepsErrnoAndFailure(t *testing.T) {
	e := openError(syscall.EBUSY, uapi.KACS_STATUS_DELETE_PENDING)
	var oe *OpenError
	if !errors.As(e, &oe) || oe.Failure != DeletePending {
		t.Fatalf("want an OpenError naming DeletePending, got %v", e)
	}
	if !errors.Is(e, syscall.EBUSY) {
		t.Fatalf("an OpenError should still match its errno")
	}
	// A success status, or none, leaves the errno alone.
	if e := openError(syscall.EACCES, 0); e != syscall.EACCES {
		t.Fatalf("got %v", e)
	}
	if e := openError(syscall.EEXIST, uapi.KACS_STATUS_OPENED); e != syscall.EEXIST {
		t.Fatalf("got %v", e)
	}
}

func TestSpecialAttributesFromKernel(t *testing.T) {
	a := fromSattr(uapi.Kacs_sattr{Attributes: uapi.KACS_SATTR_READONLY, Flags: uapi.KACS_SATTR_CREATED_AT_SET, Created_at_sec: 1000000000, Created_at_nsec: 5})
	if !a.ReadOnly || !a.CreatedAt.Equal(time.Unix(1000000000, 5)) {
		t.Fatalf("got %+v", a)
	}
	// Created At unset reads as the zero time, even if the fields hold a value.
	if a := fromSattr(uapi.Kacs_sattr{Created_at_sec: 7}); a.ReadOnly || !a.CreatedAt.IsZero() {
		t.Fatalf("got %+v", a)
	}
}
