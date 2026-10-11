package conformance

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/peios/peios-go/access"
	"github.com/peios/peios-go/file"
	"github.com/peios/peios-go/msgpack"
	"github.com/peios/peios-go/security"
	"github.com/peios/peios-go/token"
)

func references(t *testing.T) []string {
	t.Helper()
	c, r := os.Getenv("PEIOS_C_ORACLE"), os.Getenv("PEIOS_RUST_ORACLE")
	if c == "" || r == "" {
		if os.Getenv("PEIOS_REQUIRE_CONFORMANCE") == "1" {
			t.Fatal("missing reference drivers")
		}
		t.Skip("requires reference drivers")
	}
	return []string{c, r}
}
func compareBytes(t *testing.T, mode, arg string, want []byte) {
	t.Helper()
	for _, driver := range references(t) {
		b, e := exec.Command(driver, mode, arg).CombinedOutput()
		if e != nil {
			t.Fatalf("%s: %v: %s", driver, e, b)
		}
		got, e := hex.DecodeString(strings.TrimSpace(string(b)))
		if e != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s %s: Go %x reference %s (%v)", mode, arg, want, b, e)
		}
	}
}
func TestExtendedReferenceAPIs(t *testing.T) {
	references(t)
	t.Run("MessagePackWriter", func(t *testing.T) {
		b, e := msgpack.Marshal([]any{nil, true, int64(-129), uint64(math.MaxUint64), 1.5, "hello", []byte("abc"), msgpack.Extension{Type: -1, Data: []byte("xy")}, msgpack.Map{{Key: "n", Value: 128}}, []any{}})
		if e != nil {
			t.Fatal(e)
		}
		compareBytes(t, "mp-fixture", "", b)
	})
	t.Run("TokenSpec", func(t *testing.T) {
		sid, _ := security.ParseSID("SY")
		s := token.Spec{User: sid, Groups: []token.Group{{SID: sid, Attributes: 7}}, PrivilegesPresent: 3, PrivilegesEnabled: 1, Type: token.Primary, Level: token.LevelImpersonation, IntegrityRID: 8192, ProjectedUID: 42, ProjectedGID: 43, Expiration: 99, SourceName: "sdk", SourceID: 17, SupplementaryGIDs: []uint32{1, 2}}
		b, e := s.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		compareBytes(t, "token-spec", "", b)
		s.DeviceGroups = []token.Group{{SID: sid, Attributes: 7}}
		s.RestrictedSIDs = []token.Group{{SID: sid, Attributes: 4}}
		s.Confinement = sid
		s.WriteRestricted = true
		s.UserDenyOnly = true
		s.IsolationBoundary = true
		s.ConfinementExempt = true
		s.DefaultDACL = &security.ACL{}
		for _, v := range []any{int64(-9), uint64(300), true, "hello", sid, []byte("abc")} {
			c := security.Claim{Name: "claim", Values: []any{v}}
			s.UserClaims = append(s.UserClaims, c)
			s.DeviceClaims = append(s.DeviceClaims, c)
		}
		s.LCS = &token.LCSCredentials{Scopes: []security.GUID{{1}}, PrivateLayers: []string{"private"}}
		b, e = s.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		compareBytes(t, "token-spec", "full", b)
	})
	t.Run("Audit", func(t *testing.T) {
		b, e := access.AuditContext("service", []access.Field{{Name: "name", Value: "sdk"}, {Name: "id", Value: uint64(300)}, {Name: "ok", Value: true}})
		if e != nil {
			t.Fatal(e)
		}
		compareBytes(t, "audit", "service", b)
		for _, kind := range []string{"kind", "bad--kind", "9kind", "service-"} {
			if _, e = access.AuditContext(kind, []access.Field{{Name: "name", Value: "sdk"}}); e == nil {
				t.Fatal("invalid kind accepted", kind)
			}
			for _, driver := range references(t) {
				out, e := exec.Command(driver, "audit", kind).CombinedOutput()
				if e != nil || strings.TrimSpace(string(out)) != "error" {
					t.Fatal(kind, string(out), e)
				}
			}
		}
	})
	for _, flags := range []string{"", "OI", "CI", "OICI", "OINP", "CINP", "OICIIO", "OICIIOID", "OICINP"} {
		for _, sid := range []string{"WD", "CO", "CG"} {
			for _, container := range []bool{false, true} {
				for _, protected := range []string{"", "P"} {
					arg := fmt.Sprintf("O:SYD:(A;%s;GR;;;%s)S:(AU;%sSA;GW;;;WD)|O:SYG:BAD:%s(A;ID;FR;;;WD)(A;;FW;;;SY)|%d", flags, sid, flags, protected, map[bool]int{false: 0, true: 1}[container])
					t.Run("Inheritance/"+arg, func(t *testing.T) {
						parts := strings.Split(arg, "|")
						p, _ := security.ParseSDDL(parts[0])
						c, _ := security.ParseSDDL(parts[1])
						pb, _ := p.MarshalBinary()
						cb, _ := c.MarshalBinary()
						mapping := file.GenericMapping()
						b, e := security.Reinherit(pb, cb, container, &mapping, security.InfoDACL|security.InfoSACL)
						if e != nil {
							t.Fatal(e)
						}
						compareBytes(t, "inherit", arg, b)
					})
				}
			}
		}
	}
	for _, s := range []string{"O:SYG:BAD:PAI(A;ID;FR;;;WD)(A;;FW;;;SY)S:(AU;SAID;FA;;;WD)", "D:", "O:SY", "D:(XA;ID;GA;;;WD;(@User.Level == 1))"} {
		t.Run("Strip/"+s, func(t *testing.T) {
			d, _ := security.ParseSDDL(s)
			b, _ := d.MarshalBinary()
			b, e := security.StripInherited(b, security.InfoDACL|security.InfoSACL)
			if e != nil {
				t.Fatal(e)
			}
			compareBytes(t, "strip", s, b)
		})
	}
}
func TestMessagePackAcceptance(t *testing.T) {
	drivers := references(t)
	cases := [][]byte{{}, {0xc1}, {0xc0, 0}, {0x81}, {0xd9, 2, 0xff, 0xff}, {0xc7, 0, 1}, {0xdf, 255, 255, 255, 255}}
	for _, v := range []any{nil, true, int64(math.MinInt64), uint64(math.MaxUint64), "é", []byte{}, []any{}, msgpack.Map{}, msgpack.Extension{Type: 127, Data: []byte{}}, msgpack.Map{{Key: "kind", Value: "service"}}, msgpack.Map{{Key: "kind", Value: "service"}, {Key: "service", Value: msgpack.Map{{Key: "nested", Value: []any{1, true}}}}}} {
		b, e := msgpack.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		cases = append(cases, b)
		for n := 0; n < len(b); n++ {
			cases = append(cases, b[:n])
		}
	}
	for n := 30; n < 34; n++ {
		cases = append(cases, append(bytes.Repeat([]byte{0x91}, n), 0xc0))
	}
	for _, mode := range []string{"mp-validate", "audit-validate"} {
		for i, b := range cases {
			t.Run(fmt.Sprintf("%s/%d", mode, i), func(t *testing.T) {
				e := msgpack.Validate(b, 32)
				if mode == "audit-validate" {
					e = access.ValidateAuditContext(b)
				}
				want := "ok"
				if e != nil {
					want = "error"
				}
				for _, d := range drivers {
					out, err := exec.Command(d, mode, hex.EncodeToString(b)).CombinedOutput()
					if err != nil || strings.TrimSpace(string(out)) != want {
						t.Fatalf("%x Go=%s ref=%s err=%v", b, want, out, err)
					}
				}
			})
		}
	}
}
