// Package msgpack implements the MessagePack vocabulary used by Peios events
// and audit contexts. Maps preserve order and duplicate keys. Decoded byte
// strings own their storage. Nesting is bounded (32 levels by default).
package msgpack

import (
	"encoding/binary"
	"errors"
	"math"
	"unicode/utf8"
)

type Pair struct{ Key, Value any }
type Map []Pair
type Extension struct {
	Type int8
	Data []byte
}
type Raw []byte

var ErrInvalid = errors.New("peios/msgpack: invalid or truncated value")
var ErrDepth = errors.New("peios/msgpack: nesting limit exceeded")

func Marshal(v any) ([]byte, error) { return appendValue(nil, v, 1) }
func appendSize(b []byte, n int, small byte, limit int, c8, c16, c32 byte) ([]byte, error) {
	if uint64(n) > math.MaxUint32 {
		return nil, ErrInvalid
	}
	switch {
	case n < limit:
		return append(b, small|byte(n)), nil
	case c8 != 0 && n <= 255:
		return append(b, c8, byte(n)), nil
	case n <= 65535:
		b = append(b, c16)
		return binary.BigEndian.AppendUint16(b, uint16(n)), nil
	default:
		b = append(b, c32)
		return binary.BigEndian.AppendUint32(b, uint32(n)), nil
	}
}
func appendUint(b []byte, v uint64) []byte {
	switch {
	case v <= 127:
		return append(b, byte(v))
	case v <= 255:
		return append(b, 0xcc, byte(v))
	case v <= 65535:
		return binary.BigEndian.AppendUint16(append(b, 0xcd), uint16(v))
	case v <= math.MaxUint32:
		return binary.BigEndian.AppendUint32(append(b, 0xce), uint32(v))
	default:
		return binary.BigEndian.AppendUint64(append(b, 0xcf), v)
	}
}
func appendInt(b []byte, v int64) []byte {
	switch {
	case v >= 0:
		return appendUint(b, uint64(v))
	case v >= -32:
		return append(b, byte(v))
	case v >= -128:
		return append(b, 0xd0, byte(v))
	case v >= -32768:
		return binary.BigEndian.AppendUint16(append(b, 0xd1), uint16(v))
	case v >= math.MinInt32:
		return binary.BigEndian.AppendUint32(append(b, 0xd2), uint32(v))
	default:
		return binary.BigEndian.AppendUint64(append(b, 0xd3), uint64(v))
	}
}
func appendValue(b []byte, v any, depth int) ([]byte, error) {
	if depth > 32 {
		return nil, ErrDepth
	}
	var e error
	switch x := v.(type) {
	case nil:
		return append(b, 0xc0), nil
	case bool:
		if x {
			return append(b, 0xc3), nil
		}
		return append(b, 0xc2), nil
	case int:
		return appendInt(b, int64(x)), nil
	case int8:
		return appendInt(b, int64(x)), nil
	case int16:
		return appendInt(b, int64(x)), nil
	case int32:
		return appendInt(b, int64(x)), nil
	case int64:
		return appendInt(b, x), nil
	case uint:
		return appendUint(b, uint64(x)), nil
	case uint8:
		return appendUint(b, uint64(x)), nil
	case uint16:
		return appendUint(b, uint64(x)), nil
	case uint32:
		return appendUint(b, uint64(x)), nil
	case uint64:
		return appendUint(b, x), nil
	case float32:
		return binary.BigEndian.AppendUint64(append(b, 0xcb), math.Float64bits(float64(x))), nil
	case float64:
		return binary.BigEndian.AppendUint64(append(b, 0xcb), math.Float64bits(x)), nil
	case string:
		if !utf8.ValidString(x) {
			return nil, ErrInvalid
		}
		b, e = appendSize(b, len(x), 0xa0, 32, 0xd9, 0xda, 0xdb)
		if e != nil {
			return nil, e
		}
		return append(b, x...), nil
	case []byte:
		b, e = appendSize(b, len(x), 0, 0, 0xc4, 0xc5, 0xc6)
		if e != nil {
			return nil, e
		}
		return append(b, x...), nil
	case Raw:
		if e = Validate(x, 33-depth); e != nil {
			return nil, e
		}
		return append(b, x...), nil
	case Extension:
		switch len(x.Data) {
		case 1:
			b = append(b, 0xd4)
		case 2:
			b = append(b, 0xd5)
		case 4:
			b = append(b, 0xd6)
		case 8:
			b = append(b, 0xd7)
		case 16:
			b = append(b, 0xd8)
		default:
			b, e = appendSize(b, len(x.Data), 0, 0, 0xc7, 0xc8, 0xc9)
		}
		if e != nil {
			return nil, e
		}
		b = append(b, byte(x.Type))
		return append(b, x.Data...), nil
	case []any:
		b, e = appendSize(b, len(x), 0x90, 16, 0, 0xdc, 0xdd)
		if e != nil {
			return nil, e
		}
		for _, v := range x {
			b, e = appendValue(b, v, depth+1)
			if e != nil {
				return nil, e
			}
		}
		return b, nil
	case Map:
		b, e = appendSize(b, len(x), 0x80, 16, 0, 0xde, 0xdf)
		if e != nil {
			return nil, e
		}
		for _, p := range x {
			b, e = appendValue(b, p.Key, depth+1)
			if e != nil {
				return nil, e
			}
			b, e = appendValue(b, p.Value, depth+1)
			if e != nil {
				return nil, e
			}
		}
		return b, nil
	default:
		return nil, ErrInvalid
	}
}

// Decoder advances only after successfully decoding a complete value. MaxDepth
// zero means 32. Input must remain unchanged while decoding.
type Decoder struct {
	Data     []byte
	Offset   int
	MaxDepth int
}

func (d *Decoder) Decode() (any, error) {
	lim := d.MaxDepth
	if lim == 0 {
		lim = 32
	}
	if lim < 1 || lim > 256 {
		return nil, ErrDepth
	}
	p := parser{b: d.Data, pos: d.Offset, limit: lim}
	v, e := p.value(1)
	if e == nil {
		d.Offset = p.pos
	}
	return v, e
}
func (d *Decoder) Skip() error {
	lim := d.MaxDepth
	if lim == 0 {
		lim = 32
	}
	r := Reader{Data: d.Data, Offset: d.Offset}
	e := validateOne(&r, lim)
	if e == nil {
		d.Offset = r.Offset
	}
	return e
}
func Unmarshal(b []byte) (any, error) {
	d := Decoder{Data: b}
	v, e := d.Decode()
	if e == nil && d.Offset != len(b) {
		e = ErrInvalid
	}
	return v, e
}

// Validate requires exactly one value and a depth limit in 1..256.
func Validate(b []byte, maxDepth int) error {
	r := Reader{Data: b}
	e := validateOne(&r, maxDepth)
	if e == nil && r.Remaining() != 0 {
		e = ErrInvalid
	}
	return e
}

type parser struct {
	b          []byte
	pos, limit int
}

func (p *parser) take(n uint64) ([]byte, error) {
	if p.pos < 0 || p.pos > len(p.b) || n > uint64(len(p.b)-p.pos) {
		return nil, ErrInvalid
	}
	b := p.b[p.pos : p.pos+int(n)]
	p.pos += int(n)
	return b, nil
}
func (p *parser) number(n int) (uint64, error) {
	b, e := p.take(uint64(n))
	if e != nil {
		return 0, e
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v, nil
}
func (p *parser) value(depth int) (any, error) {
	if depth > p.limit {
		return nil, ErrDepth
	}
	c, e := p.number(1)
	if e != nil {
		return nil, e
	}
	var n uint64
	var kind byte
	switch {
	case c <= 0x7f:
		return c, nil
	case c >= 0xe0:
		return int64(int8(c)), nil
	case c >= 0xa0 && c <= 0xbf:
		n = c & 31
		kind = 's'
	case c >= 0x90 && c <= 0x9f:
		n = c & 15
		kind = 'a'
	case c >= 0x80 && c <= 0x8f:
		n = c & 15
		kind = 'm'
	default:
		switch c {
		case 0xc0:
			return nil, nil
		case 0xc2:
			return false, nil
		case 0xc3:
			return true, nil
		case 0xcc, 0xcd, 0xce, 0xcf:
			n, e = p.number(1 << uint(c-0xcc))
			return n, e
		case 0xd0, 0xd1, 0xd2, 0xd3:
			width := 1 << uint(c-0xd0)
			n, e = p.number(width)
			shift := 64 - width*8
			return int64(n<<shift) >> shift, e
		case 0xca:
			n, e = p.number(4)
			return float64(math.Float32frombits(uint32(n))), e
		case 0xcb:
			n, e = p.number(8)
			return math.Float64frombits(n), e
		case 0xd9, 0xda, 0xdb:
			n, e = p.number(1 << uint(c-0xd9))
			kind = 's'
		case 0xc4, 0xc5, 0xc6:
			n, e = p.number(1 << uint(c-0xc4))
			kind = 'b'
		case 0xc7, 0xc8, 0xc9:
			n, e = p.number(1 << uint(c-0xc7))
			kind = 'x'
		case 0xd4, 0xd5, 0xd6, 0xd7, 0xd8:
			n = 1 << uint(c-0xd4)
			kind = 'x'
		case 0xdc, 0xdd:
			n, e = p.number(2 << uint(c-0xdc))
			kind = 'a'
		case 0xde, 0xdf:
			n, e = p.number(2 << uint(c-0xde))
			kind = 'm'
		default:
			return nil, ErrInvalid
		}
	}
	if e != nil {
		return nil, e
	}
	switch kind {
	case 's', 'b':
		b, e := p.take(n)
		if e != nil {
			return nil, e
		}
		if kind == 's' {
			if !utf8.Valid(b) {
				return nil, ErrInvalid
			}
			return string(b), nil
		}
		return append([]byte{}, b...), nil
	case 'x':
		t, e := p.number(1)
		if e != nil {
			return nil, e
		}
		b, e := p.take(n)
		return Extension{int8(t), append([]byte{}, b...)}, e
	case 'a', 'm':
		factor := uint64(1)
		if kind == 'm' {
			factor = 2
		}
		if n > uint64(len(p.b)-p.pos)/factor {
			return nil, ErrInvalid
		}
		if kind == 'a' {
			a := make([]any, int(n))
			for i := range a {
				a[i], e = p.value(depth + 1)
				if e != nil {
					return nil, e
				}
			}
			return a, nil
		}
		m := make(Map, int(n))
		for i := range m {
			m[i].Key, e = p.value(depth + 1)
			if e != nil {
				return nil, e
			}
			m[i].Value, e = p.value(depth + 1)
			if e != nil {
				return nil, e
			}
		}
		return m, nil
	}
	return nil, ErrInvalid
}
