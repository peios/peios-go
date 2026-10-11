package msgpack

import (
	"bytes"
	"math"
	"testing"
)

func TestCursorContracts(t *testing.T) {
	var w Writer
	b, e := w.Array(10).Nil().Bool(true).Int(-129).Uint(math.MaxUint64).Float(1.5).String("hello").Binary([]byte("abc")).Extension(Extension{-1, []byte("xy")}).Map(1).String("n").Int(128).Array(0).Bytes()
	if e != nil {
		t.Fatal(e)
	}
	r := Reader{Data: b}
	if n, e := r.Array(); n != 10 || e != nil {
		t.Fatal(n, e)
	}
	if k, e := r.Peek(); k != Nil || e != nil {
		t.Fatal(k, e)
	}
	if e := r.Nil(); e != nil {
		t.Fatal(e)
	}
	if v, e := r.Bool(); !v || e != nil {
		t.Fatal(v, e)
	}
	pos := r.Offset
	if _, e := r.Uint(); e == nil || r.Offset != pos {
		t.Fatal("negative uint consumed")
	}
	if v, e := r.Int(); v != -129 || e != nil {
		t.Fatal(v, e)
	}
	pos = r.Offset
	if _, e := r.Int(); e == nil || r.Offset != pos {
		t.Fatal("overflow consumed")
	}
	if v, e := r.Uint(); v != math.MaxUint64 || e != nil {
		t.Fatal(v, e)
	}
	if v, e := r.Float(); v != 1.5 || e != nil {
		t.Fatal(v, e)
	}
	if v, e := r.StringBytes(); string(v) != "hello" || e != nil {
		t.Fatal(v, e)
	}
	pos = r.Offset
	v, e := r.Binary()
	if string(v) != "abc" || e != nil || &v[0] != &b[pos+2] {
		t.Fatal("not borrowed", v, e)
	}
	if v, e := r.Extension(); v.Type != -1 || string(v.Data) != "xy" || e != nil {
		t.Fatal(v, e)
	}
	if n, e := r.Map(); n != 1 || e != nil {
		t.Fatal(n, e)
	}
	if e := r.Skip(); e != nil {
		t.Fatal(e)
	}
	if v, e := r.Uint(); v != 128 || e != nil {
		t.Fatal(v, e)
	}
	if n, e := r.Array(); n != 0 || e != nil {
		t.Fatal(n, e)
	}
	if r.Remaining() != 0 {
		t.Fatal(r.Remaining())
	}
	for n := 0; n < len(b); n++ {
		rr := Reader{Data: b[:n]}
		if rr.Skip() == nil || rr.Offset != 0 {
			t.Fatalf("truncation %d", n)
		}
	}
	rr := Reader{Data: b}
	if e := rr.Skip(); e != nil || rr.Remaining() != 0 {
		t.Fatal(e)
	}
	if allocs := testing.AllocsPerRun(100, func() {
		rr.Offset = 0
		if rr.Skip() != nil {
			panic("skip")
		}
	}); allocs != 0 {
		t.Fatal("skip allocated", allocs)
	}
}
func TestCursorDeepAndWriterErrors(t *testing.T) {
	deep := append(bytes.Repeat([]byte{0x91}, 10000), 0xc0)
	r := Reader{Data: deep}
	if e := r.Skip(); e != nil || r.Remaining() != 0 {
		t.Fatal(e)
	}
	for _, depth := range []int{0, 1, 32, 256, 257} {
		for _, n := range []int{0, 1, 31, 32, 255, 256} {
			b := append(bytes.Repeat([]byte{0x91}, n), 0xc0)
			if got := Validate(b, depth) == nil; got != (depth >= 1 && depth <= 256 && n < depth) {
				t.Fatal(depth, n, got)
			}
		}
	}
	var w Writer
	if _, e := w.Array(1).Bytes(); e == nil || w.Err() == nil {
		t.Fatal("incomplete accepted")
	}
	w.Nil()
	if _, e := w.Bytes(); e == nil {
		t.Fatal("sticky error lost")
	}
	w.Reset()
	if _, e := w.String("\xff").Bytes(); e == nil {
		t.Fatal("utf8 accepted")
	}
	w.Reset()
	if _, e := w.Raw([]byte{0x91}).Raw([]byte{0xc0}).Bytes(); e != nil {
		t.Fatal(e)
	}
	w.Reset()
	if _, e := w.Raw(deep[:256]).Nil().Bytes(); e == nil {
		t.Fatal("excess depth")
	}
}
func FuzzCursor(f *testing.F) {
	for _, b := range [][]byte{{0xc0}, {0x91, 0xc0}, {0xa1, 'x'}, {0xcf, 255, 255, 255, 255, 255, 255, 255, 255}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r := Reader{Data: b}
		e := r.Skip()
		if e != nil && r.Offset != 0 {
			t.Fatal("failed skip advanced")
		}
		for k := Nil; k <= Ext; k++ {
			rr := Reader{Data: b}
			_, _, e := rr.leaf(k)
			if e != nil && rr.Offset != 0 {
				t.Fatal("failed leaf advanced")
			}
		}
		if Validate(b, 256) == nil && (e != nil || r.Remaining() != 0) {
			t.Fatal("validation/skip disagreement")
		}
	})
}
