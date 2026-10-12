package conformance

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/peios/peios-go/security"
)

func TestNullACLReferenceAPIs(t *testing.T) {
	ds := references(t)
	corpus, err := os.ReadFile("../security/testdata/null-acl-vectors.tsv")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(corpus), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			t.Fatalf("bad vector: %q", line)
		}
		t.Run(fields[0], func(t *testing.T) {
			d, err := security.ParseSDDL(fields[0])
			if err != nil {
				t.Fatal(err)
			}
			wire, err := d.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			text, err := d.SDDL()
			if err != nil {
				t.Fatal(err)
			}
			referenceText(t, ds, "sddl", fields[0], fmt.Sprintf("%x\n%s", wire, text))
		})
	}
}
