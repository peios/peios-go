package security

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Claim carries one homogeneous resource attribute. Values may be int64,
// uint64, bool, string, SID, or []byte; mixing types is rejected.
type Claim struct {
	Name   string
	Flags  uint32
	Values []any
	// ValueType is required for an empty claim; zero infers it from Values.
	ValueType uint16
}

func claimType(v any) uint16 {
	switch v.(type) {
	case int64:
		return 1
	case uint64:
		return 2
	case string:
		return 3
	case SID:
		return 5
	case bool:
		return 6
	case []byte:
		return 16
	}
	return 0
}
func (c Claim) MarshalBinary() ([]byte, error) {
	if len(c.Values) > 16384 || strings.ContainsRune(c.Name, 0) || !utf8.ValidString(c.Name) {
		return nil, invalid("claim name/count")
	}
	t := c.ValueType
	if len(c.Values) > 0 {
		inferred := claimType(c.Values[0])
		if t != 0 && t != inferred {
			return nil, invalid("claim value type mismatch")
		}
		t = inferred
	}
	if t != 1 && t != 2 && t != 3 && t != 5 && t != 6 && t != 16 {
		return nil, invalid("claim value type")
	}
	b := make([]byte, 16+4*len(c.Values))
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	binary.LittleEndian.PutUint16(b[4:], t)
	binary.LittleEndian.PutUint32(b[8:], c.Flags)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(c.Values)))
	b = append(b, utf16Bytes(c.Name)...)
	b = append(b, 0, 0)
	type indirect struct {
		offset int
		data   []byte
	}
	var pointers []indirect
	for i, v := range c.Values {
		if claimType(v) != t {
			return nil, invalid("mixed claim types")
		}
		pos := len(b)
		binary.LittleEndian.PutUint32(b[16+4*i:], uint32(pos))
		var data []byte
		switch v := v.(type) {
		case int64:
			b = binary.LittleEndian.AppendUint64(b, uint64(v))
			continue
		case uint64:
			b = binary.LittleEndian.AppendUint64(b, v)
			continue
		case bool:
			var n uint64
			if v {
				n = 1
			}
			b = binary.LittleEndian.AppendUint64(b, n)
			continue
		case string:
			if strings.ContainsRune(v, 0) || !utf8.ValidString(v) {
				return nil, invalid("claim string NUL")
			}
			data = append(utf16Bytes(v), 0, 0)
		case SID:
			if !v.Valid() {
				return nil, invalid("claim SID")
			}
			data = v.Bytes()
		case []byte:
			data = binary.LittleEndian.AppendUint32(nil, uint32(len(v)))
			data = append(data, v...)
		}
		b = append(b, 0, 0, 0, 0)
		pointers = append(pointers, indirect{pos, data})
	}
	for _, p := range pointers {
		binary.LittleEndian.PutUint32(b[p.offset:], uint32(len(b)))
		b = append(b, p.data...)
	}
	return b, nil
}
func read32(b []byte, off uint64) (uint32, error) {
	if off > uint64(len(b)) || uint64(len(b))-off < 4 {
		return 0, invalid("claim offset")
	}
	return binary.LittleEndian.Uint32(b[off:]), nil
}
func readUTF16Z(b []byte, off uint64) (string, error) {
	if off >= uint64(len(b)) {
		return "", invalid("claim string offset")
	}
	for end := off; end+2 <= uint64(len(b)); end += 2 {
		if b[end] == 0 && b[end+1] == 0 {
			return utf16String(b[off:end])
		}
	}
	return "", invalid("unterminated claim string")
}
func ParseClaim(b []byte) (Claim, error) {
	var c Claim
	if len(b) < 16 {
		return c, invalid("claim header")
	}
	name, e := readUTF16Z(b, uint64(binary.LittleEndian.Uint32(b)))
	if e != nil {
		return c, e
	}
	c.Name = name
	c.Flags = binary.LittleEndian.Uint32(b[8:])
	t := binary.LittleEndian.Uint16(b[4:])
	c.ValueType = t
	n := uint64(binary.LittleEndian.Uint32(b[12:]))
	if n > (uint64(len(b))-16)/4 {
		return c, invalid("claim count")
	}
	for i := uint64(0); i < n; i++ {
		off := uint64(binary.LittleEndian.Uint32(b[16+i*4:]))
		var v any
		switch t {
		case 1, 2, 6:
			if off > uint64(len(b)) || uint64(len(b))-off < 8 {
				return c, invalid("claim integer offset")
			}
			u := binary.LittleEndian.Uint64(b[off:])
			if t == 1 {
				v = int64(u)
			} else if t == 2 {
				v = u
			} else {
				if u > 1 {
					return c, invalid("claim boolean")
				}
				v = u != 0
			}
		case 3, 5, 16:
			p, err := read32(b, off)
			if err != nil {
				return c, err
			}
			switch t {
			case 3:
				v, e = readUTF16Z(b, uint64(p))
			case 5:
				if uint64(p) > uint64(len(b)) {
					return c, invalid("claim SID offset")
				}
				v, _, e = sidPrefix(b[p:])
			case 16:
				size, err := read32(b, uint64(p))
				if err != nil {
					return c, err
				}
				end := uint64(p) + 4 + uint64(size)
				if end > uint64(len(b)) {
					return c, invalid("claim octet length")
				}
				v = append([]byte(nil), b[uint64(p)+4:end]...)
			}
		default:
			return c, invalid("claim type")
		}
		if e != nil {
			return c, e
		}
		c.Values = append(c.Values, v)
	}
	return c, nil
}
func splitCommas(s string) []string {
	var p []string
	start, depth := 0, 0
	q := false
	for i, c := range s {
		if c == '"' {
			q = !q
		}
		if q {
			continue
		}
		switch c {
		case '(', '{':
			depth++
		case ')', '}':
			depth--
		case ',':
			if depth == 0 {
				p = append(p, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(p, strings.TrimSpace(s[start:]))
}
func quoted(s string) (string, error) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' || strings.ContainsRune(s[1:len(s)-1], '"') {
		return "", invalid("quoted claim string")
	}
	return s[1 : len(s)-1], nil
}
func parseUnsigned(s string, bits int) (uint64, error) {
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		base = 0
	}
	n, e := strconv.ParseUint(s, base, bits)
	if e != nil {
		return 0, invalid("unsigned integer")
	}
	return n, nil
}
func parseClaim(s string) ([]byte, error) {
	body, rest, e := paren(strings.TrimSpace(s))
	if e != nil || rest != "" {
		return nil, invalid("claim parentheses")
	}
	p := splitCommas(body)
	if len(p) < 4 {
		return nil, invalid("claim fields")
	}
	name, e := quoted(p[0])
	if e != nil {
		return nil, e
	}
	flags, e := parseUnsigned(p[2], 32)
	if e != nil {
		return nil, e
	}
	c := Claim{Name: name, Flags: uint32(flags)}
	for _, s := range p[3:] {
		var v any
		switch strings.ToUpper(p[1]) {
		case "TI":
			v, e = parseInteger(s)
		case "TU":
			v, e = parseUnsigned(s, 64)
		case "TB":
			if s != "0" && s != "1" {
				return nil, invalid("boolean claim")
			}
			v = s == "1"
		case "TS":
			v, e = quoted(s)
		case "TD":
			if len(s) < 6 || !strings.EqualFold(s[:4], "SID(") || s[len(s)-1] != ')' {
				return nil, invalid("SID claim")
			}
			v, e = parseTrustee(s[4 : len(s)-1])
		case "TX":
			if !strings.HasPrefix(s, "#") {
				return nil, invalid("octet claim")
			}
			v, e = hex.DecodeString(s[1:])
		default:
			return nil, invalid("claim indicator")
		}
		if e != nil {
			return nil, e
		}
		c.Values = append(c.Values, v)
	}
	return c.MarshalBinary()
}
func formatClaim(b []byte) (string, error) {
	c, e := ParseClaim(b)
	if e != nil {
		return "", e
	}
	if strings.ContainsRune(c.Name, '"') {
		return "", invalid("claim cannot be represented in SDDL")
	}
	ind := map[uint16]string{1: "TI", 2: "TU", 3: "TS", 5: "TD", 6: "TB", 16: "TX"}
	s := fmt.Sprintf("(\"%s\",%s,0x%x", c.Name, ind[claimType(c.Values[0])], c.Flags)
	for _, v := range c.Values {
		s += ","
		switch v := v.(type) {
		case int64:
			s += strconv.FormatInt(v, 10)
		case uint64:
			s += strconv.FormatUint(v, 10)
		case bool:
			if v {
				s += "1"
			} else {
				s += "0"
			}
		case string:
			if strings.ContainsRune(v, '"') {
				return "", invalid("claim quote")
			}
			s += "\"" + v + "\""
		case SID:
			s += "SID(" + formatTrustee(v) + ")"
		case []byte:
			s += "#" + hex.EncodeToString(v)
		}
	}
	return s + ")", nil
}

// validateClaimWire matches the binary view contract, which permits zero-value
// claims and preserves raw boolean scalars. The higher-level Claim builder is
// intentionally typed; ACL views retain the original application bytes.
func validateClaimWire(b []byte) error {
	if len(b) < 16 {
		return invalid("claim header")
	}
	if _, e := readUTF16Z(b, uint64(binary.LittleEndian.Uint32(b))); e != nil {
		return e
	}
	n := uint64(binary.LittleEndian.Uint32(b[12:]))
	if n > (uint64(len(b))-16)/4 {
		return invalid("claim count")
	}
	typ := binary.LittleEndian.Uint16(b[4:])
	for i := uint64(0); i < n; i++ {
		off := uint64(binary.LittleEndian.Uint32(b[16+i*4:]))
		if typ == 1 || typ == 2 || typ == 6 {
			if off > uint64(len(b)) || uint64(len(b))-off < 8 {
				return invalid("claim scalar")
			}
			continue
		}
		p, e := read32(b, off)
		if e != nil {
			return e
		}
		switch typ {
		case 3:
			if _, e = readUTF16Z(b, uint64(p)); e != nil {
				return e
			}
		case 5:
			if uint64(p) >= uint64(len(b)) {
				return invalid("claim SID offset")
			}
			if _, _, e = sidPrefix(b[p:]); e != nil {
				return e
			}
		case 16:
			n, e := read32(b, uint64(p))
			if e != nil {
				return e
			}
			if uint64(p)+4+uint64(n) > uint64(len(b)) {
				return invalid("claim octets")
			}
		default:
			return invalid("claim type")
		}
	}
	return nil
}
