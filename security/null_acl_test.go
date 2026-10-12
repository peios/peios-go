package security

import (
	"bytes"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Shared with libpeios and libp-go. Control bits are PCDS expectations,
// independent of the implementations used by the differential tests.
func TestNullACLSpecificationVectors(t *testing.T) {
	corpus, err := os.ReadFile("testdata/null-acl-vectors.tsv")
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
			d, err := ParseSDDL(fields[0])
			if err != nil {
				t.Fatal(err)
			}
			wire, err := d.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			want, err := strconv.ParseUint(fields[2], 16, 16)
			if err != nil {
				t.Fatal(err)
			}
			if got := binary.LittleEndian.Uint16(wire[2:]); got != uint16(want) {
				t.Fatalf("control: %04x != %04x", got, want)
			}
			for _, item := range []struct {
				flag Control
				off  int
				acl  *ACL
			}{{DACLPresent, 16, d.DACL}, {SACLPresent, 12, d.SACL}} {
				present := want&uint64(item.flag) != 0
				if (binary.LittleEndian.Uint32(wire[item.off:]) != 0) != present || (item.acl != nil) != present {
					t.Fatal("PRESENT, ACL offset and parsed ACL disagree")
				}
			}
			parsed, err := ParseDescriptor(wire)
			if err != nil {
				t.Fatal(err)
			}
			text, err := parsed.SDDL()
			if err != nil || text != fields[1] {
				t.Fatalf("canonical %q: %v, want %q", text, err, fields[1])
			}
			again, err := ParseSDDL(text)
			if err != nil {
				t.Fatal(err)
			}
			round, err := again.MarshalBinary()
			if err != nil || !bytes.Equal(wire, round) {
				t.Fatalf("wire round trip %x != %x: %v", wire, round, err)
			}
		})
	}
}

func TestNullACLRejectsAmbiguity(t *testing.T) {
	for _, text := range []string{"D:NO_ACCESS_CONTROL(A;;GA;;;WD)", "S:NO_ACCESS_CONTROL(AU;SA;GR;;;WD)", "D:NO_ACCESS_CONTROLNO_ACCESS_CONTROL", "D:ANO_ACCESS_CONTROLR", "D:NO_ACCESS_CONTROLX"} {
		if _, err := ParseSDDL(text); err == nil {
			t.Errorf("accepted %q", text)
		}
	}
	for _, control := range []Control{DACLPresent, SACLPresent} {
		if _, err := (Descriptor{Control: control}).SDDL(); err == nil {
			t.Errorf("formatted invalid PRESENT/nil ACL: %x", control)
		}
	}
}
