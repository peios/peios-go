package process

import (
	"syscall"
	"testing"
)

func TestSecurityBlockParser(t *testing.T) {
	b, e := parseSecurityBlock("pip_type=512 pip_trust=8192 mitigations=0x105 process_guid=3f2c9a1e-6b0d-4c8e-9a41-2d7e5f10b6c3 later=1\n")
	if e != nil || b.PIPType != 512 || b.Mitigations != 0x105 || b.GUID[0] != 0x3f || b.GUID[15] != 0xc3 {
		t.Fatal(b, e)
	}
	for _, s := range []string{"", "pip_type=0 pip_trust=0 mitigations=0x0", "pip_type=0 pip_trust=0 mitigations=0x100000000 process_guid=00000000000000000000000000000000"} {
		if _, e = parseSecurityBlock(s); e != syscall.EPROTO {
			t.Fatal(e)
		}
	}
}
