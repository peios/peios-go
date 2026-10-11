// Package event emits and consumes KMES events.
package event

import (
	"encoding/binary"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/registry"
)

func Emit(kind string, payload []byte) error {
	if len(kind) == 0 || len(kind) > 65535 || !utf8.ValidString(kind) || uint64(len(payload)) > 0xffffffff {
		return syscall.EINVAL
	}
	var p native.Pins
	defer p.Unpin()
	_, e := native.Call(uapi.SYS_KMES_EMIT, p.Bytes([]byte(kind)), uintptr(len(kind)), p.Bytes(payload), uintptr(len(payload)))
	return e
}

type Entry struct {
	Type    string
	Payload []byte
}

// EmitBatch returns the count emitted even when the kernel reports a partial
// failure. It does not retry a partially emitted batch.
func EmitBatch(entries []Entry) (uint32, error) {
	if len(entries) == 0 || len(entries) > uapi.KMES_BATCH_MAX_ENTRIES {
		return 0, syscall.EINVAL
	}
	var p native.Pins
	defer p.Unpin()
	raw := make([]uapi.Kmes_emit_entry, len(entries))
	for i, v := range entries {
		if len(v.Type) == 0 || len(v.Type) > 65535 || !utf8.ValidString(v.Type) || uint64(len(v.Payload)) > 0xffffffff {
			return 0, syscall.EINVAL
		}
		raw[i] = uapi.Kmes_emit_entry{Event_type: uint64(p.Bytes([]byte(v.Type))), Event_type_len: uint16(len(v.Type)), Payload: uint64(p.Bytes(v.Payload)), Payload_len: uint32(len(v.Payload))}
	}
	var count uint32
	_, e := native.Call(uapi.SYS_KMES_EMIT_BATCH, p.Pointer(unsafe.Pointer(&raw[0])), uintptr(len(raw)), p.Pointer(unsafe.Pointer(&count)))
	return count, e
}

type Tier uint32

const (
	TierEssential Tier = iota
	TierStandard
	TierVerbose
	TierDebug
)

// Policy reads the current registry policy on each decision. It retains no
// handles or cache, so concurrent callers are safe and updates apply immediately.
type Policy struct{}

func OpenPolicy() *Policy { return &Policy{} }
func (p *Policy) Enabled(kind string, tier Tier) (bool, error) {
	if tier > TierDebug || kind == "" || !utf8.ValidString(kind) || strings.ContainsAny(kind, "\\/\x00") {
		return false, syscall.EINVAL
	}
	parts := strings.Split(kind, ".")
	for _, s := range parts {
		if s == "" {
			return false, syscall.EINVAL
		}
	}
	if tier == TierEssential {
		return true, nil
	}
	enabled := tier == TierStandard
	k, e := registry.Open("Machine\\Generic\\Events", registry.Read, 0)
	if e != nil {
		return enabled, nil
	}
	defer func() { k.Close() }()
	for i := 0; ; i++ {
		if v, e := k.Query("Enabled", nil); e == nil {
			if n, e := v.Uint32(); e == nil && n <= 1 {
				enabled = n == 1
			}
		}
		if i == len(parts) {
			return enabled, nil
		}
		next, e := k.Open(parts[i], registry.QueryValue, 0)
		if e != nil {
			return enabled, nil
		}
		k.Close()
		k = next
	}
}
func (p *Policy) EmitWith(kind string, tier Tier, build func() ([]byte, error)) (bool, error) {
	enabled, e := p.Enabled(kind, tier)
	if e != nil || !enabled {
		return false, e
	}
	if build == nil {
		return false, syscall.EINVAL
	}
	b, e := build()
	if e != nil {
		return false, e
	}
	if e = Emit(kind, b); e != nil {
		return false, e
	}
	return true, nil
}

// Event owns its payload and type; its contents survive the next ring read.
type Event struct {
	Timestamp, Sequence                uint64
	CPU                                uint16
	Origin                             uint8
	EffectiveToken, TrueToken, Process [16]byte
	Type                               string
	Payload                            []byte
}

func ParseEvent(b []byte) (Event, int, error) {
	var v Event
	if len(b) < 77 {
		return v, 0, syscall.EPROTO
	}
	n, h := uint64(binary.LittleEndian.Uint32(b)), uint64(binary.LittleEndian.Uint32(b[4:]))
	t := uint64(binary.LittleEndian.Uint16(b[75:]))
	if h != 77+t || n < h || n > uint64(len(b)) {
		return v, 0, syscall.EPROTO
	}
	v.Timestamp = binary.LittleEndian.Uint64(b[8:])
	v.Sequence = binary.LittleEndian.Uint64(b[16:])
	v.CPU = binary.LittleEndian.Uint16(b[24:])
	v.Origin = b[26]
	copy(v.EffectiveToken[:], b[27:43])
	copy(v.TrueToken[:], b[43:59])
	copy(v.Process[:], b[59:75])
	v.Type = string(b[77:h])
	v.Payload = append([]byte(nil), b[h:n]...)
	return v, int(n), nil
}

func (t Tier) String() string {
	switch t {
	case TierEssential:
		return "essential"
	case TierStandard:
		return "standard"
	case TierVerbose:
		return "verbose"
	case TierDebug:
		return "debug"
	}
	return "unknown"
}
