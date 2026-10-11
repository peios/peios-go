// Package process exposes Peios process security blocks and one-way mitigation
// activation. Use os/exec for ordinary child-process creation.
package process

import (
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/security"
)

type SecurityBlock struct {
	PIPType, PIPTrust, Mitigations uint32
	GUID                           [16]byte
}

func GenericMapping() security.GenericMapping {
	return security.GenericMapping{Read: 0x20410, Write: 0x40220, Execute: 0x1801, All: 0xe1e73}
}

// SetMitigations activates bits atomically and cannot clear them. Nil targets
// the current process. Kernel authority and activation failures are returned.
func SetMitigations(pidfd syscall.Conn, bits uint32) error {
	run := func(fd int) error { _, e := native.Call(uapi.SYS_KACS_SET_PSB, uintptr(fd), uintptr(bits)); return e }
	if pidfd == nil {
		return run(-1)
	}
	return native.WithFD(pidfd, run)
}
func ReadSecurityBlock(pid int) (SecurityBlock, error) {
	name := "self"
	if pid > 0 {
		name = strconv.Itoa(pid)
	}
	b, e := os.ReadFile("/proc/" + name + "/psb")
	if e != nil {
		return SecurityBlock{}, e
	}
	return parseSecurityBlock(string(b))
}
func parseSecurityBlock(text string) (out SecurityBlock, e error) {
	line, _, _ := strings.Cut(text, "\n")
	fields := map[string]string{}
	for _, f := range strings.Fields(line) {
		k, v, ok := strings.Cut(f, "=")
		if ok {
			fields[k] = v
		}
	}
	t, e1 := strconv.ParseUint(fields["pip_type"], 10, 32)
	trust, e2 := strconv.ParseUint(fields["pip_trust"], 10, 32)
	mit := fields["mitigations"]
	if !strings.HasPrefix(mit, "0x") {
		return out, syscall.EPROTO
	}
	m, e3 := strconv.ParseUint(mit[2:], 16, 32)
	g, e4 := hex.DecodeString(strings.ReplaceAll(fields["process_guid"], "-", ""))
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || len(g) != 16 {
		return out, syscall.EPROTO
	}
	out.PIPType = uint32(t)
	out.PIPTrust = uint32(trust)
	out.Mitigations = uint32(m)
	copy(out.GUID[:], g)
	return out, nil
}
