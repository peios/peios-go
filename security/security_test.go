package security

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"syscall"
	"testing"
)

// The PSD wire layout is an independent oracle, not another implementation.
func TestSIDWireAndOwnership(t *testing.T) {
	s, e := ParseSID("S-1-5-32-544")
	if e != nil {
		t.Fatal(e)
	}
	if hex.EncodeToString(s.Bytes()) != "01020000000000052000000020020000" {
		t.Fatalf("SID wire %x", s.Bytes())
	}
	b := s.Bytes()
	b[0] = 9
	if s.String() != "S-1-5-32-544" {
		t.Fatal("mutable SID")
	}
	if LogonSID(0x100000002).String() != "S-1-5-5-1-2" {
		t.Fatal("logon SID halves")
	}
	for _, v := range []string{"", "S-0-5", "S-1-5-4294967296", "S-1-281474976710656", "DA", "S-1-5" + strings.Repeat("-1", 16)} {
		if _, e := ParseSID(v); !errors.Is(e, syscall.EINVAL) {
			t.Errorf("accepted %q", v)
		}
	}
}
func TestDescriptorAuthorityAndBounds(t *testing.T) {
	absent := Descriptor{}
	empty := Descriptor{DACL: &ACL{}}
	a, _ := absent.MarshalBinary()
	b, _ := empty.MarshalBinary()
	if len(a) != 20 || len(b) != 28 || binary.LittleEndian.Uint16(b[2:]) != 0x8004 || binary.LittleEndian.Uint32(b[16:]) != 20 {
		t.Fatal("absent versus empty DACL")
	}
	if _, e := (Descriptor{Control: DACLPresent}).MarshalBinary(); e == nil {
		t.Fatal("PRESENT DACL with no ACL accepted")
	}
	d, _ := ParseSDDL("O:SYG:BAD:(D;;GW;;;WD)(A;;GR;;;WD)")
	good, e := d.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	for n := 0; n < len(good); n++ {
		if _, e := ParseDescriptor(good[:n]); e == nil {
			t.Fatalf("accepted truncated descriptor at %d", n)
		}
	}
	overlap := bytes.Clone(good)
	copy(overlap[8:12], overlap[4:8])
	if _, e := ParseDescriptor(overlap); e == nil {
		t.Fatal("overlap accepted")
	}
	parsed, e := ParseDescriptor(good)
	if e != nil {
		t.Fatal(e)
	}
	good[20] = 9
	if parsed.Owner.String() != "S-1-5-18" || parsed.DACL.ACEs[0].Type != Deny {
		t.Fatal("ownership or ordering")
	}
	unknown := ACL{Revision: 4, ACEs: []ACE{{Type: 0xfe, Flags: Inherited, RawBody: []byte{1, 2, 3, 4}}}}
	wire, _ := unknown.MarshalBinary()
	round, e := ParseACL(wire)
	if e != nil {
		t.Fatal(e)
	}
	again, _ := round.MarshalBinary()
	if !bytes.Equal(wire, again) {
		t.Fatal("opaque ACE lost")
	}
	if _, e := (Descriptor{DACL: &round}).SDDL(); e == nil {
		t.Fatal("opaque ACE silently omitted")
	}
}
func TestAccessFilterAndRevisionPreservation(t *testing.T) {
	const sddl = "D:(FL;;GA;;;WD;(@User.Level == 1))"
	d, err := ParseSDDL(sddl)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := d.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDescriptor(wire)
	if err != nil {
		t.Fatal(err)
	}
	text, err := parsed.SDDL()
	if err != nil || text != sddl {
		t.Fatalf("filter lost: %q %v", text, err)
	}
	for _, revision := range []byte{0, 1, 2, 4, 255} {
		for _, body := range [][]byte{{}, {1, 2, 3, 4}} {
			a := ACL{Revision: revision, ExactRevision: true, Reserved1: 37, Reserved2: 513,
				ACEs: []ACE{{Type: 21, RawBody: body}}}
			b, err := a.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			a, err = ParseACL(b)
			if err != nil {
				t.Fatal(err)
			}
			again, err := a.MarshalBinary()
			if err != nil || !bytes.Equal(b, again) {
				t.Fatalf("opaque filter/revision lost: %x %x %v", b, again, err)
			}
		}
	}
	world, _ := ParseSID("S-1-1-0")
	a := ACL{Revision: 255, ACEs: []ACE{{Type: 5, SID: world}}}
	b, err := a.MarshalBinary()
	if err != nil || b[0] != 255 {
		t.Fatalf("revision floor lost: %x %v", b, err)
	}
}

func TestClaimsAndConditionalPayloads(t *testing.T) {
	for n := 0; n < 9; n++ {
		d, e := ParseSDDL(`S:(RA;;;;;WD;("Bytes",TX,0x0,#` + strings.Repeat("ab", n) + `))`)
		if e != nil {
			t.Fatal(e)
		}
		b, e := d.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		if len(b)%4 != 0 {
			t.Fatal("unaligned ACE")
		}
		d, e = ParseDescriptor(b)
		if e != nil {
			t.Fatal(e)
		}
		c, e := ParseClaim(d.SACL.ACEs[0].ApplicationData)
		if e != nil {
			t.Fatal(e)
		}
		if len(c.Values[0].([]byte)) != n {
			t.Fatal("padding became claim data")
		}
	}
	for _, s := range []string{`@User.x == "hello"`, `!(@User.x == 3 || Exists @Resource.y)`, `Member_of {SID(BA), SID(SY)}`} {
		b, e := ParseCondition(s)
		if e != nil {
			t.Fatal(e)
		}
		formatted, e := FormatCondition(b)
		if e != nil {
			t.Fatal(e)
		}
		again, e := ParseCondition(formatted)
		if e != nil || !bytes.Equal(b, again) {
			t.Fatalf("condition roundtrip: %s %v", formatted, e)
		}
	}
}
func FuzzBinaryParsers(f *testing.F) {
	d, _ := ParseSDDL("O:SYD:(A;;FR;;;WD)")
	b, _ := d.MarshalBinary()
	f.Add(b)
	f.Add([]byte("artx"))
	cond, _ := ParseCondition(`@User.x == "hello" && Member_of {SID(BA)}`)
	f.Add(cond)
	claim, _ := (Claim{Name: "Team", Values: []any{"Blue"}}).MarshalBinary()
	f.Add(claim)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if d, e := ParseDescriptor(b); e == nil {
			out, e := d.MarshalBinary()
			if e != nil {
				t.Fatal(e)
			}
			if _, e = ParseDescriptor(out); e != nil {
				t.Fatal(e)
			}
		}
		if a, e := ParseACL(b); e == nil {
			out, e := a.MarshalBinary()
			if e != nil {
				t.Fatal(e)
			}
			if _, e = ParseACL(out); e != nil {
				t.Fatal(e)
			}
		}
		SIDFromBytes(b)
		ParseClaim(b)
		FormatCondition(b)
	})
}
func FuzzSDDL(f *testing.F) {
	for _, s := range []string{"D:", "O:SYD:(A;;GA;;;WD)", `D:(XA;;GA;;;WD;(@User.x == 1))`, `S:(RA;;;;;WD;("x",TI,0x0,1))`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, e := ParseSDDL(s)
		if e != nil {
			return
		}
		b, e := d.MarshalBinary()
		if e != nil {
			return
		}
		round, e := ParseDescriptor(b)
		if e != nil {
			t.Fatal(e)
		}
		text, e := round.SDDL()
		if e != nil {
			return
		}
		again, e := ParseSDDL(text)
		if e != nil {
			t.Fatalf("format produced invalid SDDL %q: %v", text, e)
		}
		b2, e := again.MarshalBinary()
		if e != nil || !bytes.Equal(b, b2) {
			t.Fatalf("lossy SDDL %q to %q", s, text)
		}
	})
}
