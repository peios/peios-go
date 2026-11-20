// Package claimwire encodes claims in the layout the kernel's token builder
// and supplied-subject query parse, shared by the token and access packages.
package claimwire

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/peios/peios-go/security"
)

// Token encodes c in the token-builder layout: offset table, slots, indirect data,
// then name. Resource-attribute ACL encoding uses a different canonical order.
func Token(c security.Claim) ([]byte, error) {
	validated, e := c.MarshalBinary()
	if e != nil {
		return nil, e
	}
	typ := binary.LittleEndian.Uint16(validated[4:])
	scalar := typ == 1 || typ == 2 || typ == 6
	size := 4
	if scalar {
		size = 8
	}
	start := 16 + 4*len(c.Values)
	b := make([]byte, start+size*len(c.Values))
	binary.LittleEndian.PutUint16(b[4:], typ)
	binary.LittleEndian.PutUint32(b[8:], c.Flags)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(c.Values)))
	utf16z := func(s string) []byte {
		var out []byte
		for _, u := range utf16.Encode([]rune(s)) {
			out = binary.LittleEndian.AppendUint16(out, u)
		}
		return append(out, 0, 0)
	}
	for i, v := range c.Values {
		slot := start + i*size
		binary.LittleEndian.PutUint32(b[16+i*4:], uint32(slot))
		switch x := v.(type) {
		case int64:
			binary.LittleEndian.PutUint64(b[slot:], uint64(x))
		case uint64:
			binary.LittleEndian.PutUint64(b[slot:], x)
		case bool:
			if x {
				binary.LittleEndian.PutUint64(b[slot:], 1)
			}
		default:
			binary.LittleEndian.PutUint32(b[slot:], uint32(len(b)))
			switch x := v.(type) {
			case string:
				b = append(b, utf16z(x)...)
			case security.SID:
				b = append(b, x.Bytes()...)
			case []byte:
				b = binary.LittleEndian.AppendUint32(b, uint32(len(x)))
				b = append(b, x...)
			}
		}
	}
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	b = append(b, utf16z(c.Name)...)
	return b, nil
}
