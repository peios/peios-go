package registry

import (
	"encoding/binary"
	"testing"
)

func TestNotificationAndBatchBounds(t *testing.T) {
	record := make([]byte, 9)
	binary.LittleEndian.PutUint32(record, 9)
	binary.LittleEndian.PutUint16(record[4:], 1)
	binary.LittleEndian.PutUint16(record[6:], 1)
	record[8] = 'x'
	v, e := ParseNotifications(record)
	if e != nil || len(v) != 1 || v[0].Name != "x" {
		t.Fatal(v, e)
	}
	for i := 1; i < len(record); i++ {
		if _, e := ParseNotifications(record[:i]); e == nil {
			t.Fatal(i)
		}
	}
	batch := binary.LittleEndian.AppendUint32(nil, 1)
	batch = append(batch, 'x')
	batch = binary.LittleEndian.AppendUint32(batch, 4)
	batch = binary.LittleEndian.AppendUint32(batch, 4)
	batch = binary.LittleEndian.AppendUint32(batch, 42)
	values, e := parseValues(batch, 1)
	if e != nil || len(values) != 1 {
		t.Fatal(values, e)
	}
	for i := 0; i < len(batch); i++ {
		if _, e := parseValues(batch[:i], 1); e == nil {
			t.Fatal(i)
		}
	}
	if GenericMapping().Execute != 0 {
		t.Fatal("registry has no execute rights")
	}
}
func FuzzRegistryRecords(f *testing.F) {
	f.Add([]byte{}, uint32(0))
	f.Fuzz(func(t *testing.T, b []byte, n uint32) { ParseNotifications(b); parseValues(b, n) })
}
