package access

import (
	"encoding/binary"
	"syscall"
	"testing"

	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/security"
)

func TestPackSubjectHeader(t *testing.T) {
	user, _ := security.ParseSID("S-1-5-21-1-2-3-1000")
	r := Request{Descriptor: []byte{1, 0, 4, 0x80, 0, 0, 0, 0}, Desired: 0x1, Mapping: security.GenericMapping{Read: 2, Write: 3, Execute: 4, All: 5}}
	b, e := packSubject(r, SuppliedSubject{User: user, Groups: []SubjectGroup{}, LocalClaims: &SuppliedClaims{Coverage: CompleteClaims}}, 7, SubjectNoAudit)
	if e != nil {
		t.Fatal(e)
	}
	u := func(at int) uint32 { return binary.LittleEndian.Uint32(b[at:]) }
	if u(0) != uapi.KACS_SUBJECT_VERSION || int(u(4)) != len(b) || u(8) != SubjectNoAudit {
		t.Fatalf("version, length or flags wrong: % x", b[:12])
	}
	// Groups known (empty), device groups unknown; local claims complete.
	if u(12) != 1 || u(36) != 7 || u(40) != 1<<2 {
		t.Fatalf("known %d, index %d, complete %d", u(12), u(36), u(40))
	}
	if u(16) != 1 || u(20) != 2 || u(32) != 5 {
		t.Fatalf("desired or mapping wrong")
	}
	// The descriptor is section 0 and the user section 1, right after the header.
	if u(48) != uapi.KACS_SUBJECT_HEADER_BYTES || u(52) != uint32(len(r.Descriptor)) || u(56) != uapi.KACS_SUBJECT_HEADER_BYTES+uint32(len(r.Descriptor)) || u(60) != uint32(len(user.Bytes())) {
		t.Fatalf("section table wrong: % x", b[48:64])
	}
	// An empty known group list has no section.
	if u(64) != 0 || u(68) != 0 {
		t.Fatalf("empty groups should have no section")
	}
}

func TestPackSubjectRefusesTokenRequests(t *testing.T) {
	r := Request{Descriptor: []byte{1}, PrivilegeIntent: 1}
	if _, e := packSubject(r, SuppliedSubject{}, 0, 0); e != syscall.EINVAL {
		t.Fatalf("privilege intent should be refused, got %v", e)
	}
	if _, e := packSubject(Request{Descriptor: []byte{1}}, SuppliedSubject{}, 0, 2); e != syscall.EINVAL {
		t.Fatalf("an unknown flag should be refused, got %v", e)
	}
}
