package msgpack

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestRoundTripAndOwnership(t *testing.T) {
	values := []any{nil, true, false, int64(-33), int64(math.MinInt64), uint64(math.MaxUint64), 1.5, "λ", []byte{0, 255}, Extension{-3, []byte{1, 2}}, []any{}, Map{{"same", uint64(1)}, {"same", uint64(2)}}}
	for _, v := range values {
		b, e := Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		got, e := Unmarshal(b)
		if e != nil || !reflect.DeepEqual(got, v) {
			t.Fatalf("%#v => %#v %v", v, got, e)
		}
		again, e := Marshal(got)
		if e != nil || !bytes.Equal(b, again) {
			t.Fatal(e)
		}
		for i := range b {
			b[i] = 0
		}
		if !reflect.DeepEqual(got, v) {
			t.Fatal("decoded value aliases input")
		}
	}
}
func TestDecoderRollbackAndLimits(t *testing.T) {
	d := Decoder{Data: []byte{0x92, 1}}
	if _, e := d.Decode(); e == nil || d.Offset != 0 {
		t.Fatal("truncation advanced decoder")
	}
	d.Data = append(d.Data, 2)
	if _, e := d.Decode(); e != nil || d.Offset != 3 {
		t.Fatal(e)
	}
	if Validate([]byte{0xc0, 0xc0}, 32) == nil {
		t.Fatal("trailing value")
	}
	v := append(bytes.Repeat([]byte{0x91}, 32), 0)
	if !errors.Is(Validate(v, 32), ErrDepth) {
		t.Fatal("depth")
	}
	if _, e := Marshal(Raw{0xc1}); e == nil {
		t.Fatal("raw invalid")
	}
}
func FuzzMessagePack(f *testing.F) {
	for _, b := range [][]byte{{0x80}, {0x92, 0xa1, 'a', 0xd0, 0xdf}, {0xc7, 0, 1}, {0xdf, 255, 255, 255, 255}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d := Decoder{Data: b}
		v, e := d.Decode()
		if e != nil {
			if d.Offset != 0 {
				t.Fatal("failed parse advanced")
			}
			return
		}
		out, e := Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = Validate(out, 32); e != nil {
			t.Fatal(e)
		}
	})
}
