package access

import (
	"encoding/binary"
	"strings"
	"syscall"
	"unsafe"

	"github.com/peios/peios-go/internal/claimwire"
	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/security"
)

// SubjectGroup is a supplied group: its SID and KACS_SID_GROUP_* attributes,
// including the enabled and deny-only flags.
type SubjectGroup struct {
	SID        security.SID
	Attributes uint32
}

// ClaimCoverage says whether claims not given are unknown or absent.
type ClaimCoverage uint32

const (
	// PartialClaims: only the values and listed absences are known.
	PartialClaims ClaimCoverage = 0
	// CompleteClaims: every claim is given, so one not given is absent.
	CompleteClaims ClaimCoverage = 1
)

// SuppliedClaims are disclosed claim values and explicit known absences,
// compared under KACS name equivalence (Unicode lowercase).
type SuppliedClaims struct {
	Values   []security.Claim
	Absent   []string
	Coverage ClaimCoverage
}

// SuppliedSubject is a hypothetical identity, evaluated without an OS token. A
// zero User, a nil group slice and a nil claims pointer are unknown; a non-nil
// empty slice is known to be empty. The facts convey no authority to
// impersonate or mint tokens.
type SuppliedSubject struct {
	User         security.SID
	Groups       []SubjectGroup
	UserClaims   *SuppliedClaims
	DeviceGroups []SubjectGroup
	DeviceClaims *SuppliedClaims
	LocalClaims  *SuppliedClaims
}

// MissingContext names the kinds of facts a decision needed but did not have.
// The values are libpeios's PEIOS_SUBJECT_MISSING_*, which the kernel's
// advisory evaluator reports.
type MissingContext uint32

const (
	MissingUser             MissingContext = 1
	MissingGroups           MissingContext = 2
	MissingUserClaims       MissingContext = 4
	MissingDeviceGroups     MissingContext = 8
	MissingDeviceClaims     MissingContext = 16
	MissingLocalClaims      MissingContext = 32
	MissingSelf             MissingContext = 64
	MissingObjectTypes      MissingContext = 128
	MissingExecutionContext MissingContext = 256
	MissingAuditContext     MissingContext = 512
)

// SubjectDecision is the outcome of a supplied-subject check (libpeios's
// PEIOS_SUBJECT_ACCESS_*).
type SubjectDecision uint32

const (
	SubjectDenied         SubjectDecision = 0
	SubjectGranted        SubjectDecision = 1
	SubjectMissingContext SubjectDecision = 2
)

// SubjectResult is a supplied-subject check's answer. Only SubjectGranted is
// enough to admit a caller; a missing-context answer carries no provisional
// grant.
type SubjectResult struct {
	Decision SubjectDecision
	Granted  security.AccessMask
	Missing  MissingContext
}

// SubjectNoAudit suppresses a supplied-subject check's own audit records.
const SubjectNoAudit uint32 = uapi.KACS_SUBJECT_NO_AUDIT

// CheckSubject evaluates s against r's descriptor with the kernel's stateless
// supplied-identity query. r.Token must be nil, and its privilege intent, PIP
// and local claims empty; objectIndex selects a node of r.ObjectTree. The
// check is advisory: it computes the answer, and the caller enforces it.
func CheckSubject(r Request, s SuppliedSubject, objectIndex uint32) (SubjectResult, error) {
	return CheckSubjectEx(r, s, objectIndex, 0)
}

// CheckSubjectEx is CheckSubject with flags: zero, or SubjectNoAudit.
func CheckSubjectEx(r Request, s SuppliedSubject, objectIndex uint32, flags uint32) (out SubjectResult, e error) {
	b, e := packSubject(r, s, objectIndex, flags)
	if e != nil {
		return out, e
	}
	var raw struct{ Decision, Granted, Missing uint32 }
	var p native.Pins
	defer p.Unpin()
	if _, e = native.Call(uapi.SYS_KACS_ACCESS_CHECK_SUBJECT, p.Bytes(b), uintptr(len(b)), p.Pointer(unsafe.Pointer(&raw))); e != nil {
		return out, e
	}
	return SubjectResult{SubjectDecision(raw.Decision), security.AccessMask(raw.Granted), MissingContext(raw.Missing)}, nil
}

// packSubject lays out the kernel's supplied-subject request exactly as
// libpeios does: a fixed header naming the offset and length of each section.
func packSubject(r Request, s SuppliedSubject, objectIndex uint32, flags uint32) ([]byte, error) {
	const header = uapi.KACS_SUBJECT_HEADER_BYTES
	const maxBytes = uapi.KACS_SUBJECT_MAX_BYTES
	const maxItems = uapi.KACS_SUBJECT_MAX_ITEMS
	if flags&^SubjectNoAudit != 0 || r.Token != nil || len(r.Descriptor) == 0 || len(r.Descriptor) > 65535 ||
		r.PrivilegeIntent != 0 || r.PIPType != 0 || r.PIPTrust != 0 || len(r.LocalClaims) != 0 ||
		len(r.AuditContext) > 4096 || len(r.ObjectTree) > maxItems {
		return nil, syscall.EINVAL
	}
	put := func(b []byte, at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
	out := make([]byte, header)
	tooBig := false
	section := func(index int, value []byte) {
		if len(value) == 0 {
			return
		}
		if len(value) > maxBytes-len(out) {
			tooBig = true
			return
		}
		put(out, 48+index*8, uint32(len(out)))
		put(out, 52+index*8, uint32(len(value)))
		out = append(out, value...)
	}
	sidBytes := func(sid security.SID) ([]byte, bool) {
		b := sid.Bytes()
		return b, len(b) <= 68
	}
	groups := func(list []SubjectGroup) ([]byte, error) {
		if len(list) > maxItems {
			return nil, syscall.EINVAL
		}
		seen := map[string]bool{}
		var enc []byte
		for _, g := range list {
			b, ok := sidBytes(g.SID)
			if !g.SID.Valid() || !ok || seen[string(b)] {
				return nil, syscall.EINVAL
			}
			seen[string(b)] = true
			enc = binary.LittleEndian.AppendUint32(enc, uint32(len(b)))
			enc = append(enc, b...)
			enc = binary.LittleEndian.AppendUint32(enc, g.Attributes)
		}
		return enc, nil
	}
	put(out, 0, uapi.KACS_SUBJECT_VERSION)
	put(out, 8, flags)
	var known uint32
	if s.Groups != nil {
		known |= 1
	}
	if s.DeviceGroups != nil {
		known |= 2
	}
	put(out, 12, known)
	put(out, 16, uint32(r.Desired))
	put(out, 20, uint32(r.Mapping.Read))
	put(out, 24, uint32(r.Mapping.Write))
	put(out, 28, uint32(r.Mapping.Execute))
	put(out, 32, uint32(r.Mapping.All))
	put(out, 36, objectIndex)
	section(0, r.Descriptor)
	user, ok := sidBytes(s.User)
	if !ok || (len(user) != 0 && !s.User.Valid()) {
		return nil, syscall.EINVAL
	}
	section(1, user)
	for i, list := range [][]SubjectGroup{s.Groups, s.DeviceGroups} {
		enc, e := groups(list)
		if e != nil {
			return nil, e
		}
		section(2+i, enc)
	}
	var names [3][]byte
	var complete uint32
	for i, c := range []*SuppliedClaims{s.UserClaims, s.DeviceClaims, s.LocalClaims} {
		var enc []byte
		if c != nil {
			if c.Coverage > CompleteClaims || len(c.Values) > maxItems || len(c.Absent) > maxItems {
				return nil, syscall.EINVAL
			}
			complete |= uint32(c.Coverage) << i
			for _, v := range c.Values {
				claim, e := claimwire.Token(v)
				if e != nil {
					return nil, syscall.EINVAL
				}
				enc = binary.LittleEndian.AppendUint32(enc, uint32(len(claim)))
				enc = append(enc, claim...)
			}
			for _, name := range c.Absent {
				if len(name) >= 256 || strings.ContainsRune(name, 0) {
					return nil, syscall.EINVAL
				}
				names[i] = binary.LittleEndian.AppendUint32(names[i], uint32(len(name)))
				names[i] = append(names[i], name...)
			}
		}
		section(4+i, enc)
	}
	put(out, 40, complete)
	for i, n := range names {
		section(7+i, n)
	}
	self, ok := sidBytes(r.Self)
	if !ok || (len(self) != 0 && !r.Self.Valid()) {
		return nil, syscall.EINVAL
	}
	section(10, self)
	var tree []byte
	for _, node := range r.ObjectTree {
		tree = binary.LittleEndian.AppendUint16(tree, node.Level)
		tree = binary.LittleEndian.AppendUint16(tree, 0)
		tree = append(tree, node.GUID[:]...)
	}
	section(11, tree)
	section(12, r.AuditContext)
	if tooBig {
		return nil, syscall.EINVAL
	}
	put(out, 4, uint32(len(out)))
	return out, nil
}
