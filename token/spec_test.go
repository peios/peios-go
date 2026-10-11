package token

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/peios/peios-go/security"
)

func TestTokenClaims(t *testing.T) {
	sid, _ := security.ParseSID("SY")
	for _, v := range []any{int64(-1), uint64(300), true, "hello", sid, []byte{1, 2, 3}} {
		c := security.Claim{Name: "test", Values: []any{v}}
		b, e := marshalClaim(c)
		if e != nil {
			t.Fatal(e)
		}
		got, e := security.ParseClaim(b)
		c.ValueType = binary.LittleEndian.Uint16(b[4:])
		if e != nil || !reflect.DeepEqual(c, got) {
			t.Fatal(c, got, e)
		}
	}
}
func TestSpecRejectsInvalidAndCopies(t *testing.T) {
	sid, _ := security.ParseSID("SY")
	g := Group{sid, 7}
	s := Spec{User: sid, Groups: []Group{g}}
	b, e := s.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	s.Groups[0].Attributes = 0
	if binary.LittleEndian.Uint32(b[len(b)-4:]) != 7 {
		t.Fatal("alias")
	}
	s.Groups[0].SID = security.SID{}
	if _, e = s.MarshalBinary(); e == nil {
		t.Fatal("invalid SID")
	}
	for _, c := range []LCSCredentials{{Scopes: []security.GUID{{}}}, {PrivateLayers: []string{"one", "ONE"}}, {PrivateLayers: []string{"a/b"}}} {
		if _, e = c.MarshalBinary(); e == nil {
			t.Fatal(c)
		}
	}
}
func FuzzGroups(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) { ParseGroups(b) })
}

func TestEmptyTypedClaims(t *testing.T) {
	for _, typ := range []uint16{1, 2, 3, 5, 6, 16} {
		c := security.Claim{Name: "empty", ValueType: typ}
		b, e := marshalClaim(c)
		if e != nil {
			t.Fatal(e)
		}
		got, e := security.ParseClaim(b)
		if e != nil || got.ValueType != typ || len(got.Values) != 0 || got.Name != "empty" {
			t.Fatal(got, e)
		}
	}
}
