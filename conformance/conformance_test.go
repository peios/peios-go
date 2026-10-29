// Package conformance tests the Go implementation through the C and Rust APIs.
package conformance

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/peios/peios-go/security"
)

func TestReferenceAPIs(t *testing.T) {
	c, r := os.Getenv("PEIOS_C_ORACLE"), os.Getenv("PEIOS_RUST_ORACLE")
	if c == "" || r == "" {
		if os.Getenv("PEIOS_REQUIRE_CONFORMANCE") == "1" {
			t.Fatal("both reference drivers are required")
		}
		t.Skip("run `pekit test conformance` to build both reference drivers")
	}
	cases := map[string][]string{
		"sid":       {"SY", "S-1-0", "s-1-5-18", "S-1-0xabcdef123456-4294967295", "S-2-5-18", "S-1-5-4294967296", "S-1-281474976710656", "DA"},
		"sddl":      {"O:SYG:BAD:(A;;FA;;;BA)(A;;FR;;;BU)", "D:", "O:SY", "D:PAI(A;OICI;FRFX0x6;;;CO)", "S:(ML;;NWNR;;;ME)", "D:(OA;;GA;00112233-4455-6677-8899-aabbccddeeff;;WD)", "D:(XA;;GA;;;WD;(@User.Department == \"Engineering\"))", "S:(RA;;;;;WD;(\"Level\",TI,0x0,3))", "S:(RA;;;;;WD;(\"Team\",TS,0x0,\"Blue\",\"Red\"))", "S:(RA;;;;;WD;(\"Group\",TD,0x0,SID(BA)))", "S:(RA;;;;;WD;(\"Bytes\",TX,0x0,#aabb))", "D:(A;;1179817;;;WD)", "D:(A;;FR0x;;;WD)", "D:(A;;GA;;;DA)", "garbage", "D:D:"},
		"condition": {"@User.Title == \"PM\"", "Exists @Resource.Level", "@User.Level >= -1 && !(Member_of {SID(BA), SID(SY)})", "@User.Team Any_of {\"Blue\", \"Red\"}", "@User.x == #aabb || Not_Exists @Device.y", "@User.x == 0x7f", "nonsense"},
	}
	for _, count := range []int{127, 128, 129} {
		for _, operator := range []string{" && ", " || "} {
			input := strings.Repeat("@User.x == 1"+operator, count-1) + "@User.x == 1"
			cases["condition"] = append(cases["condition"], input)
		}
	}
	corpus, e := os.ReadFile("testdata/sddl-conformance.txt")
	if e != nil {
		t.Fatal(e)
	}
	for _, line := range strings.Split(string(corpus), "\n") {
		p := strings.Split(line, "\t")
		if len(p) < 2 {
			continue
		}
		switch p[0] {
		case "sid":
			cases["sid"] = append(cases["sid"], p[1])
			cases["sddl"] = append(cases["sddl"], "O:"+p[1])
		case "rights", "badrights":
			cases["sddl"] = append(cases["sddl"], "D:(A;;"+p[1]+";;;WD)")
		}
	}
	for n := 0; n < 9; n++ {
		cases["sddl"] = append(cases["sddl"], fmt.Sprintf(`S:(RA;;;;;WD;("Bytes",TX,0x0,#%s))`, strings.Repeat("ab", n)))
	}
	for kind, inputs := range cases {
		for _, input := range inputs {
			t.Run(kind+"/"+input, func(t *testing.T) {
				var got []byte
				var text string
				var err error
				if kind == "sid" {
					var sid security.SID
					sid, err = security.ParseSID(input)
					if err == nil {
						got, text = sid.Bytes(), sid.String()
					}
				} else if kind == "sddl" {
					var d security.Descriptor
					d, err = security.ParseSDDL(input)
					if err == nil {
						got, err = d.MarshalBinary()
					}
					if err == nil {
						text, err = d.SDDL()
					}
				} else {
					got, err = security.ParseCondition(input)
					if err == nil {
						text, err = security.FormatCondition(got)
					}
				}
				for _, driver := range []string{c, r} {
					out, e := exec.Command(driver, kind, input).CombinedOutput()
					if e != nil {
						t.Fatalf("reference execution: %v: %s", e, out)
					}
					lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
					if strings.HasPrefix(lines[0], "error ") {
						if err == nil {
							t.Errorf("Go accepted reference rejection: %s", out)
						}
						continue
					}
					if err != nil {
						t.Fatalf("Go rejected reference success: %v", err)
					}
					want, e := hex.DecodeString(lines[0])
					if e != nil {
						t.Fatal(e)
					}
					if !bytes.Equal(got, want) {
						t.Errorf("wire mismatch\nGo:  %x\nref: %x", got, want)
					}
					if len(lines) < 2 || lines[1] != text {
						t.Errorf("text mismatch Go=%q reference=%q", text, lines)
					}
				}
			})
		}
	}
}
