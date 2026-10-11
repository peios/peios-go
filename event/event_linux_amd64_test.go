package event

import (
	"encoding/binary"
	"testing"
)

func TestEventFramingAndOwnership(t *testing.T) {
	b := make([]byte, 82)
	binary.LittleEndian.PutUint32(b, 82)
	binary.LittleEndian.PutUint32(b[4:], 80)
	binary.LittleEndian.PutUint16(b[75:], 3)
	copy(b[77:], "a.b")
	copy(b[80:], []byte{0xc0, 0xc1})
	ev, n, e := ParseEvent(b)
	if e != nil || n != 82 || ev.Type != "a.b" {
		t.Fatalf("%+v %d %v", ev, n, e)
	}
	b[80] = 0
	if ev.Payload[0] != 0xc0 {
		t.Fatal("borrowed event payload")
	}
	for i := 0; i < len(b); i++ {
		if _, _, e := ParseEvent(b[:i]); e == nil {
			t.Fatal("accepted incomplete event")
		}
	}
	binary.LittleEndian.PutUint32(b[4:], 76)
	if _, _, e := ParseEvent(b); e == nil {
		t.Fatal("accepted invalid header")
	}
}
