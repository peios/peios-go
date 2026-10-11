package security

import (
	"encoding/binary"

	"github.com/peios/peios-go/internal/uapi"
)

type AccessMask uint32
type Control uint16
type ACEFlags uint8
type ACEType uint8
type SecurityInformation uint32
type GUID [16]byte

const (
	GenericRead       AccessMask          = uapi.GENERIC_READ
	GenericWrite      AccessMask          = uapi.GENERIC_WRITE
	GenericExecute    AccessMask          = uapi.GENERIC_EXECUTE
	GenericAll        AccessMask          = uapi.GENERIC_ALL
	Delete            AccessMask          = uapi.DELETE
	ReadControl       AccessMask          = uapi.READ_CONTROL
	WriteDAC          AccessMask          = uapi.WRITE_DAC
	WriteOwner        AccessMask          = uapi.WRITE_OWNER
	Synchronize       AccessMask          = uapi.KACS_ACCESS_SYNCHRONIZE
	DACLPresent       Control             = uapi.KACS_SD_DACL_PRESENT
	SACLPresent       Control             = uapi.KACS_SD_SACL_PRESENT
	DACLProtected     Control             = uapi.KACS_SD_DACL_PROTECTED
	SACLProtected     Control             = uapi.KACS_SD_SACL_PROTECTED
	DACLAutoInherited Control             = uapi.KACS_SD_DACL_AUTO_INHERITED
	SACLAutoInherited Control             = uapi.KACS_SD_SACL_AUTO_INHERITED
	SelfRelative      Control             = uapi.KACS_SD_SELF_RELATIVE
	ObjectInherit     ACEFlags            = uapi.KACS_ACE_FLAG_OBJECT_INHERIT
	ContainerInherit  ACEFlags            = uapi.KACS_ACE_FLAG_CONTAINER_INHERIT
	NoPropagate       ACEFlags            = uapi.KACS_ACE_FLAG_NO_PROPAGATE_INHERIT
	InheritOnly       ACEFlags            = uapi.KACS_ACE_FLAG_INHERIT_ONLY
	Inherited         ACEFlags            = uapi.KACS_ACE_FLAG_INHERITED
	AuditSuccess      ACEFlags            = uapi.KACS_ACE_FLAG_SUCCESSFUL_ACCESS
	AuditFailure      ACEFlags            = uapi.KACS_ACE_FLAG_FAILED_ACCESS
	Allow             ACEType             = uapi.KACS_ACE_TYPE_ACCESS_ALLOWED
	Deny              ACEType             = uapi.KACS_ACE_TYPE_ACCESS_DENIED
	Audit             ACEType             = uapi.KACS_ACE_TYPE_SYSTEM_AUDIT
	MandatoryLabel    ACEType             = uapi.KACS_ACE_TYPE_SYSTEM_MANDATORY_LABEL
	InfoOwner         SecurityInformation = uapi.OWNER_SECURITY_INFORMATION
	InfoGroup         SecurityInformation = uapi.GROUP_SECURITY_INFORMATION
	InfoDACL          SecurityInformation = uapi.DACL_SECURITY_INFORMATION
	InfoSACL          SecurityInformation = uapi.SACL_SECURITY_INFORMATION
)

type GenericMapping struct{ Read, Write, Execute, All AccessMask }

func (m GenericMapping) Map(mask AccessMask) AccessMask {
	out := mask &^ (GenericRead | GenericWrite | GenericExecute | GenericAll)
	for _, p := range [][2]AccessMask{{GenericRead, m.Read}, {GenericWrite, m.Write}, {GenericExecute, m.Execute}, {GenericAll, m.All}} {
		if mask&p[0] != 0 {
			out |= p[1]
		}
	}
	return out
}

// ACE represents one entry. ApplicationData is preserved for callback and
// resource-attribute ACEs; it must never be discarded during an ACL rewrite.
type ACE struct {
	Type                            ACEType
	Flags                           ACEFlags
	Mask                            AccessMask
	SID                             SID
	ObjectType, InheritedObjectType *GUID
	ApplicationData                 []byte
	// ObjectFlags retains reserved object-ACE flag bits; GUID presence bits are derived from the GUID fields.
	ObjectFlags uint32
	// RawBody preserves an unknown or compound ACE verbatim. It is used only
	// for types without a typed representation; SDDL refuses to omit them.
	RawBody []byte
}

func objectACE(t ACEType) bool {
	switch t {
	case 5, 6, 7, 8, 11, 12, 15, 16:
		return true
	}
	return false
}
func callbackACE(t ACEType) bool {
	switch t {
	case 9, 10, 11, 12, 13, 14, 15, 16, 21:
		return true
	}
	return false
}
func supportedACE(t ACEType) bool { return t <= 21 && t != 4 }

func (a ACE) MarshalBinary() ([]byte, error) {
	if !supportedACE(a.Type) || a.Type == 21 && a.RawBody != nil {
		if len(a.RawBody) > 65528 || len(a.RawBody)%4 != 0 {
			return nil, invalid("raw ACE length")
		}
		b := []byte{byte(a.Type), byte(a.Flags), 0, 0}
		b = append(b, a.RawBody...)
		binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
		return b, nil
	}
	if !a.SID.Valid() || len(a.RawBody) != 0 {
		return nil, invalid("ACE type or SID")
	}
	if !objectACE(a.Type) && (a.ObjectType != nil || a.InheritedObjectType != nil) {
		return nil, invalid("GUID on non-object ACE")
	}
	if len(a.ApplicationData) > 0 && !callbackACE(a.Type) && a.Type != 18 {
		return nil, invalid("unexpected ACE payload")
	}
	b := make([]byte, 8)
	b[0] = byte(a.Type)
	b[1] = byte(a.Flags)
	binary.LittleEndian.PutUint32(b[4:], uint32(a.Mask))
	if objectACE(a.Type) {
		flags := a.ObjectFlags &^ 3
		if a.ObjectType != nil {
			flags |= 1
		}
		if a.InheritedObjectType != nil {
			flags |= 2
		}
		b = binary.LittleEndian.AppendUint32(b, flags)
		if a.ObjectType != nil {
			b = append(b, a.ObjectType[:]...)
		}
		if a.InheritedObjectType != nil {
			b = append(b, a.InheritedObjectType[:]...)
		}
	}
	b = append(b, a.SID.wire...)
	b = append(b, a.ApplicationData...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	if len(b) > 65535 {
		return nil, invalid("oversized ACE")
	}
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	if _, e := parseACE(b); e != nil {
		return nil, e
	}
	return b, nil
}
func parseACE(b []byte) (ACE, error) {
	var a ACE
	if len(b) < 4 || int(binary.LittleEndian.Uint16(b[2:])) != len(b) || len(b)%4 != 0 {
		return a, invalid("ACE header")
	}
	a.Type = ACEType(b[0])
	a.Flags = ACEFlags(b[1])
	// KACS treats access-filter ACEs as opaque. Decode the conventional layout
	// when available for SDDL, but retain every other body without rejecting it.
	if a.Type == 21 {
		if len(b) >= 8 {
			if sid, n, e := sidPrefix(b[8:]); e == nil {
				a.Mask = AccessMask(binary.LittleEndian.Uint32(b[4:]))
				a.SID = sid
				a.ApplicationData = append([]byte(nil), b[8+n:]...)
				return a, nil
			}
		}
		a.RawBody = append([]byte{}, b[4:]...)
		return a, nil
	}

	if !supportedACE(a.Type) {
		a.RawBody = append([]byte(nil), b[4:]...)
		return a, nil
	}
	if len(b) < 8 {
		return a, invalid("ACE mask")
	}
	a.Mask = AccessMask(binary.LittleEndian.Uint32(b[4:]))
	if a.Type != MandatoryLabel && a.Mask&0x0ee00000 != 0 {
		return a, invalid("reserved ACE mask")
	}
	pos := 8
	if objectACE(a.Type) {
		if len(b) < 12 {
			return a, invalid("object ACE")
		}
		f := binary.LittleEndian.Uint32(b[8:])
		a.ObjectFlags = f
		pos = 12
		for i, p := range []**GUID{&a.ObjectType, &a.InheritedObjectType} {
			if f&(1<<i) != 0 {
				if pos+16 > len(b) {
					return a, invalid("GUID")
				}
				g := new(GUID)
				copy(g[:], b[pos:pos+16])
				*p = g
				pos += 16
			}
		}
	}
	s, n, e := sidPrefix(b[pos:])
	if e != nil {
		return a, e
	}
	a.SID = s
	pos += n
	if callbackACE(a.Type) || a.Type == 18 {
		a.ApplicationData = append([]byte(nil), b[pos:]...)
	} else if pos != len(b) {
		return a, invalid("unexpected ACE bytes")
	}
	if a.Type == 18 {
		if a.SID.String() != "S-1-1-0" {
			return a, invalid("resource attribute SID")
		}
		if e := validateClaimWire(a.ApplicationData); e != nil {
			return a, e
		}
	}
	return a, nil
}

// ACL is an ordered list. An empty ACL denies access; it is distinct from an
// absent ACL. Entry ordering is preserved and is never silently canonicalised.
type ACL struct {
	ACEs []ACE
	// Revision is a compatibility floor when preserving opaque ACEs. Zero
	// chooses the minimum required revision; parsed ACLs retain their revision.
	Revision uint8
	// ExactRevision preserves a wire revision, including zero. Parsers set it;
	// new ACLs normally infer a revision from their entries.
	ExactRevision bool
	Reserved1     uint8
	Reserved2     uint16
}

func (a ACL) MarshalBinary() ([]byte, error) {
	b := make([]byte, 8)
	b[0] = 2
	b[1] = a.Reserved1
	binary.LittleEndian.PutUint16(b[6:], a.Reserved2)

	if a.Revision > b[0] {
		b[0] = a.Revision
	}
	if len(a.ACEs) > 65535 {
		return nil, invalid("too many ACEs")
	}
	for _, ace := range a.ACEs {
		v, e := ace.MarshalBinary()
		if e != nil {
			return nil, e
		}
		if !a.ExactRevision && b[0] < 4 && ace.Type >= 5 && ace.Type <= 16 {
			b[0] = 4
		}
		b = append(b, v...)
		if len(b) > 65535 {
			return nil, invalid("oversized ACL")
		}
	}
	if a.ExactRevision {
		b[0] = a.Revision
	}
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	binary.LittleEndian.PutUint16(b[4:], uint16(len(a.ACEs)))
	return b, nil
}
func ParseACL(b []byte) (ACL, error) {
	var a ACL
	if len(b) < 8 || int(binary.LittleEndian.Uint16(b[2:])) != len(b) {
		return a, invalid("ACL header")
	}
	a.Revision = b[0]
	a.ExactRevision = true
	a.Reserved1 = b[1]
	a.Reserved2 = binary.LittleEndian.Uint16(b[6:])
	count := int(binary.LittleEndian.Uint16(b[4:]))
	pos := 8
	for i := 0; i < count; i++ {
		if pos+4 > len(b) {
			return a, invalid("truncated ACE")
		}
		n := int(binary.LittleEndian.Uint16(b[pos+2:]))
		if n < 4 || n > len(b)-pos {
			return a, invalid("ACE length")
		}
		ace, e := parseACE(b[pos : pos+n])
		if e != nil {
			return a, e
		}

		a.ACEs = append(a.ACEs, ace)
		pos += n
	}
	if pos != len(b) {
		return a, invalid("trailing ACL bytes")
	}
	return a, nil
}

// Descriptor owns its components. A nil DACL with DACLPresent clear means no
// discretionary restriction. &ACL{} means deny all. A present NULL ACL is
// represented separately by DACLPresent plus nil and is rejected by MarshalBinary
// because Peios does not accept that encoding.
type Descriptor struct {
	Owner, Group           SID
	Control                Control
	DACL, SACL             *ACL
	ResourceManagerControl byte
}

func (d Descriptor) MarshalBinary() ([]byte, error) {
	if d.DACL == nil && d.Control&DACLPresent != 0 || d.SACL == nil && d.Control&SACLPresent != 0 {
		return nil, invalid("present NULL ACL")
	}
	b := make([]byte, 20)
	b[0] = 1
	b[1] = d.ResourceManagerControl
	c := d.Control | SelfRelative
	for i, s := range []SID{d.Owner, d.Group} {
		if s.Valid() {
			binary.LittleEndian.PutUint32(b[4+i*4:], uint32(len(b)))
			b = append(b, s.wire...)
		}
	}
	for i, a := range []*ACL{d.SACL, d.DACL} {
		if a == nil {
			continue
		}
		v, e := a.MarshalBinary()
		if e != nil {
			return nil, e
		}
		binary.LittleEndian.PutUint32(b[12+i*4:], uint32(len(b)))
		b = append(b, v...)
		if i == 0 {
			c |= SACLPresent
		} else {
			c |= DACLPresent
		}
	}
	binary.LittleEndian.PutUint16(b[2:], uint16(c))
	if len(b) > 65535 {
		return nil, invalid("descriptor exceeds 65535 bytes")
	}
	return b, nil
}

// ParseDescriptor validates a self-relative descriptor and copies its components.
func ParseDescriptor(b []byte) (Descriptor, error) {
	var d Descriptor
	if len(b) < 20 || len(b) > 65535 || b[0] != 1 {
		return d, invalid("descriptor header")
	}
	d.Control = Control(binary.LittleEndian.Uint16(b[2:]))
	d.ResourceManagerControl = b[1]
	var ranges [][2]uint64
	if d.Control&SelfRelative == 0 {
		return d, invalid("absolute descriptor")
	}
	for i, p := range []*SID{&d.Owner, &d.Group} {
		off := uint64(binary.LittleEndian.Uint32(b[4+i*4:]))
		if off == 0 {
			continue
		}
		if off < 20 || off > uint64(len(b)) {
			return d, invalid("SID offset")
		}
		s, n, e := sidPrefix(b[off:])
		if e != nil {
			return d, e
		}
		*p = s
		ranges = append(ranges, [2]uint64{off, off + uint64(n)})
	}
	for i, p := range []**ACL{&d.SACL, &d.DACL} {
		off := uint64(binary.LittleEndian.Uint32(b[12+i*4:]))
		flag := SACLPresent
		if i == 1 {
			flag = DACLPresent
		}
		if d.Control&flag == 0 {
			if off != 0 {
				return d, invalid("absent ACL offset")
			}
			continue
		}
		if off < 20 || off+8 > uint64(len(b)) {
			return d, invalid("ACL offset or NULL ACL")
		}
		n := uint64(binary.LittleEndian.Uint16(b[off+2:]))
		if off+n > uint64(len(b)) {
			return d, invalid("ACL bounds")
		}
		a, e := ParseACL(b[off : off+n])
		if e != nil {
			return d, e
		}
		*p = &a
		ranges = append(ranges, [2]uint64{off, off + n})
	}
	for i, a := range ranges {
		for _, b := range ranges[i+1:] {
			if a[0] < b[1] && b[0] < a[1] {
				return d, invalid("overlapping descriptor components")
			}
		}
	}
	return d, nil
}
