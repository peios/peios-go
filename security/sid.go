// Package security implements Peios security identifiers, descriptors and SDDL.
// It is portable and does not require a Peios kernel or libpeios.
package security

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

// SID is an immutable, comparable security identifier. The zero value is invalid.
type SID struct{ wire string }

func invalid(what string) error { return fmt.Errorf("peios/security: %s: %w", what, syscall.EINVAL) }

// NewSID constructs a revision-one SID with a 48-bit authority and at most 15 RIDs.
func NewSID(authority uint64, subauthorities ...uint32) (SID, error) {
	if authority>>48 != 0 || len(subauthorities) > 15 {
		return SID{}, invalid("SID authority or count")
	}
	b := make([]byte, 8+4*len(subauthorities))
	b[0] = 1
	b[1] = byte(len(subauthorities))
	for i := 7; i >= 2; i-- {
		b[i] = byte(authority)
		authority >>= 8
	}
	for i, v := range subauthorities {
		binary.LittleEndian.PutUint32(b[8+4*i:], v)
	}
	return SID{string(b)}, nil
}

// ParseSID parses a literal identifier or an absolute SDDL alias. The authority
// may be decimal or hexadecimal; domain-relative aliases require an authority
// Peios does not supply and are rejected.
func ParseSID(s string) (SID, error) {
	if v, ok := aliases[strings.ToUpper(s)]; ok {
		s = v
	}
	p := strings.Split(s, "-")
	if len(p) < 3 || !strings.EqualFold(p[0], "S") || p[1] != "1" || len(p) > 18 {
		return SID{}, invalid("SID text")
	}
	a, e := parseUnsigned(p[2], 48)
	if e != nil {
		return SID{}, invalid("SID authority")
	}
	subs := make([]uint32, len(p)-3)
	for i, s := range p[3:] {
		v, e := strconv.ParseUint(s, 10, 32)
		if e != nil {
			return SID{}, invalid("SID RID")
		}
		subs[i] = uint32(v)
	}
	return NewSID(a, subs...)
}

// SIDFromBytes validates an exact binary SID and takes an owned copy.
func SIDFromBytes(b []byte) (SID, error) {
	if len(b) < 8 || b[0] != 1 || b[1] > 15 || len(b) != 8+int(b[1])*4 {
		return SID{}, invalid("SID bytes")
	}
	return SID{string(b)}, nil
}
func sidPrefix(b []byte) (SID, int, error) {
	if len(b) < 8 {
		return SID{}, 0, invalid("truncated SID")
	}
	n := 8 + 4*int(b[1])
	if n > len(b) {
		return SID{}, 0, invalid("truncated SID")
	}
	s, e := SIDFromBytes(b[:n])
	return s, n, e
}
func (s SID) Valid() bool { return len(s.wire) >= 8 }

// Bytes returns an owned copy of the binary identifier.
func (s SID) Bytes() []byte { return []byte(s.wire) }
func (s SID) String() string {
	if !s.Valid() {
		return ""
	}
	var a uint64
	for i := 2; i < 8; i++ {
		a = a<<8 | uint64(s.wire[i])
	}
	out := "S-1-" + strconv.FormatUint(a, 10)
	if a > 0xffffffff {
		out = fmt.Sprintf("S-1-0x%012x", a)
	}
	for i := 8; i < len(s.wire); i += 4 {
		out += "-" + strconv.FormatUint(uint64(binary.LittleEndian.Uint32([]byte(s.wire[i:i+4]))), 10)
	}
	return out
}
func (s SID) RID() uint32 {
	if len(s.wire) <= 8 {
		return 0
	}
	return binary.LittleEndian.Uint32([]byte(s.wire[len(s.wire)-4:]))
}
func (s SID) MarshalText() ([]byte, error) {
	if !s.Valid() {
		return nil, invalid("zero SID")
	}
	return []byte(s.String()), nil
}
func (s *SID) UnmarshalText(b []byte) error {
	v, e := ParseSID(string(b))
	if e == nil {
		*s = v
	}
	return e
}
func IntegritySID(level uint32) SID { s, _ := NewSID(16, level); return s }
func LogonSID(session uint64) SID {
	s, _ := NewSID(5, 5, uint32(session>>32), uint32(session))
	return s
}
