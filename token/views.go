package token

import (
	"encoding/binary"

	"github.com/peios/peios-go/security"
)

// ParseGroups decodes the count-prefixed SID/attributes query representation.
// It differs from Spec's count-in-header construction sections.
func ParseGroups(b []byte) ([]Group, error) {
	if len(b) < 4 {
		return nil, ErrSpec
	}
	n := binary.LittleEndian.Uint32(b)
	b = b[4:]
	if uint64(n) > uint64(len(b))/16 {
		return nil, ErrSpec
	}
	out := make([]Group, 0, n)
	for range n {
		if len(b) < 4 {
			return nil, ErrSpec
		}
		size := uint64(binary.LittleEndian.Uint32(b))
		b = b[4:]
		if size > uint64(len(b)) || uint64(len(b))-size < 4 {
			return nil, ErrSpec
		}
		sid, e := security.SIDFromBytes(b[:size])
		if e != nil {
			return nil, e
		}
		b = b[size:]
		out = append(out, Group{sid, binary.LittleEndian.Uint32(b)})
		b = b[4:]
	}
	if len(b) != 0 {
		return nil, ErrSpec
	}
	return out, nil
}
