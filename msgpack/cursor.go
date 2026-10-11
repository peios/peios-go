package msgpack

import (
	"math"
	"unicode/utf8"
)

// Kind describes the next wire value. Signed and unsigned integers share Int.
type Kind int

const (
	Nil Kind = iota
	Bool
	Int
	Float
	String
	Binary
	Array
	Object
	Ext
)

// Reader is a typed cursor over borrowed bytes. Reads advance only on success.
// StringBytes, Binary and Extension borrow the input; do not mutate it while in
// use. Array and Map consume only the header, permitting incremental traversal.
// Unlike Decoder, Skip is iterative and does not impose a nesting limit.
type Reader struct {
	Data   []byte
	Offset int
}

func (r *Reader) Reset(b []byte) { r.Data = b; r.Offset = 0 }
func (r *Reader) Remaining() int {
	if r.Offset < 0 || r.Offset > len(r.Data) {
		return 0
	}
	return len(r.Data) - r.Offset
}
func (r *Reader) Peek() (Kind, error) {
	if r.Offset < 0 || r.Offset >= len(r.Data) {
		return 0, ErrInvalid
	}
	c := r.Data[r.Offset]
	switch {
	case c <= 0x7f || c >= 0xe0 || c >= 0xcc && c <= 0xd3:
		return Int, nil
	case c == 0xc0:
		return Nil, nil
	case c == 0xc2 || c == 0xc3:
		return Bool, nil
	case c == 0xca || c == 0xcb:
		return Float, nil
	case c >= 0xa0 && c <= 0xbf || c >= 0xd9 && c <= 0xdb:
		return String, nil
	case c >= 0xc4 && c <= 0xc6:
		return Binary, nil
	case c >= 0x90 && c <= 0x9f || c == 0xdc || c == 0xdd:
		return Array, nil
	case c >= 0x80 && c <= 0x8f || c == 0xde || c == 0xdf:
		return Object, nil
	case c >= 0xc7 && c <= 0xc9 || c >= 0xd4 && c <= 0xd8:
		return Ext, nil
	}
	return 0, ErrInvalid
}

// leaf consumes one header and any scalar payload, never container children.
func (r *Reader) leaf(want Kind) (uint64, []byte, error) {
	k, e := r.Peek()
	if e != nil || k != want {
		return 0, nil, ErrInvalid
	}
	p := parser{b: r.Data, pos: r.Offset}
	c, _ := p.number(1)
	var n uint64
	var b []byte
	switch k {
	case Nil:
	case Bool:
		n = c - 0xc2
	case Int:
		switch {
		case c <= 0x7f:
			n = c
		case c >= 0xe0:
			n = uint64(int64(int8(c)))
		case c <= 0xcf:
			n, e = p.number(1 << uint(c-0xcc))
		default:
			width := 1 << uint(c-0xd0)
			n, e = p.number(width)
			shift := 64 - width*8
			n = uint64(int64(n<<shift) >> shift)
		}
	case Float:
		if c == 0xca {
			var v uint64
			v, e = p.number(4)
			n = math.Float64bits(float64(math.Float32frombits(uint32(v))))
		} else {
			n, e = p.number(8)
		}
	case String:
		if c <= 0xbf {
			n = c & 31
		} else {
			n, e = p.number(1 << uint(c-0xd9))
		}
	case Binary:
		n, e = p.number(1 << uint(c-0xc4))
	case Array:
		if c <= 0x9f {
			n = c & 15
		} else {
			n, e = p.number(2 << uint(c-0xdc))
		}
	case Object:
		if c <= 0x8f {
			n = c & 15
		} else {
			n, e = p.number(2 << uint(c-0xde))
		}
	case Ext:
		if c >= 0xd4 {
			n = 1 << uint(c-0xd4)
		} else {
			n, e = p.number(1 << uint(c-0xc7))
		}
	}
	if e != nil {
		return 0, nil, e
	}
	if k == String || k == Binary || k == Ext {
		size := n
		if k == Ext {
			size++
		}
		b, e = p.take(size)
		if e != nil || k == String && !utf8.Valid(b) {
			return 0, nil, ErrInvalid
		}
	}
	r.Offset = p.pos
	return n, b, nil
}
func (r *Reader) Nil() error          { _, _, e := r.leaf(Nil); return e }
func (r *Reader) Bool() (bool, error) { n, _, e := r.leaf(Bool); return n != 0, e }
func (r *Reader) Int() (int64, error) {
	start := r.Offset
	n, _, e := r.leaf(Int)
	if e != nil {
		return 0, e
	}
	c := r.Data[start]
	if (c <= 0x7f || c >= 0xcc && c <= 0xcf) && n > math.MaxInt64 {
		r.Offset = start
		return 0, ErrInvalid
	}
	return int64(n), nil
}
func (r *Reader) Uint() (uint64, error) {
	start := r.Offset
	n, _, e := r.leaf(Int)
	if e != nil {
		return 0, e
	}
	c := r.Data[start]
	if (c >= 0xe0 || c >= 0xd0 && c <= 0xd3) && int64(n) < 0 {
		r.Offset = start
		return 0, ErrInvalid
	}
	return n, nil
}
func (r *Reader) Float() (float64, error) {
	n, _, e := r.leaf(Float)
	return math.Float64frombits(n), e
}
func (r *Reader) StringBytes() ([]byte, error) { _, b, e := r.leaf(String); return b, e }
func (r *Reader) Binary() ([]byte, error)      { _, b, e := r.leaf(Binary); return b, e }
func (r *Reader) Array() (uint32, error)       { n, _, e := r.leaf(Array); return uint32(n), e }
func (r *Reader) Map() (uint32, error)         { n, _, e := r.leaf(Object); return uint32(n), e }
func (r *Reader) Extension() (Extension, error) {
	_, b, e := r.leaf(Ext)
	if e != nil {
		return Extension{}, e
	}
	return Extension{int8(b[0]), b[1:]}, nil
}
func (r *Reader) step() (uint64, error) {
	k, e := r.Peek()
	if e != nil {
		return 0, e
	}
	n, _, e := r.leaf(k)
	if k == Object {
		n *= 2
	} else if k != Array {
		n = 0
	}
	return n, e
}
func (r *Reader) Skip() error {
	c := *r
	for left := uint64(1); left > 0; {
		n, e := c.step()
		if e != nil {
			return e
		}
		left--
		// Each child needs at least one byte; this also bounds the counter.
		if n > uint64(c.Remaining()) || left > uint64(c.Remaining())-n {
			return ErrInvalid
		}
		left += n
	}
	r.Offset = c.Offset
	return nil
}

// validateOne walks without constructing decoded objects. maxDepth is 1..256.
func validateOne(r *Reader, maxDepth int) error {
	if maxDepth < 1 || maxDepth > 256 {
		return ErrDepth
	}
	c := *r
	var stack [256]uint64
	stack[0] = 1
	depth := 1
	for depth > 0 {
		if stack[depth-1] == 0 {
			depth--
			continue
		}
		stack[depth-1]--
		n, e := c.step()
		if e != nil {
			return e
		}
		if n > uint64(c.Remaining()) {
			return ErrInvalid
		}
		if n > 0 {
			if depth == maxDepth {
				return ErrDepth
			}
			stack[depth] = n
			depth++
		}
	}
	r.Offset = c.Offset
	return nil
}
