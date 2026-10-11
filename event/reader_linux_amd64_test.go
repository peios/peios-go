package event

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func fixtureReader() *Reader {
	r := &Reader{f: new(os.File), data: make([]byte, 8192+512), capacity: 256, generation: 1}
	binary.LittleEndian.PutUint64(r.data[32:], 1)
	return r
}
func record(sequence uint64) []byte {
	b := make([]byte, 78)
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	binary.LittleEndian.PutUint32(b[4:], 77)
	binary.LittleEndian.PutUint64(b[16:], sequence)
	b[77] = 0x80
	return b
}
func putRecord(r *Reader, pos uint64, b []byte) {
	for i, v := range b {
		offset := int((pos + uint64(i)) & (r.capacity - 1))
		r.data[8192+offset] = v
		r.data[8192+int(r.capacity)+offset] = v
	}
	binary.LittleEndian.PutUint64(r.data[64:], pos+uint64(len(b)))
}
func TestReaderWrapLossAndOwnership(t *testing.T) {
	r := fixtureReader()
	r.position = 240
	r.last = 3
	binary.LittleEndian.PutUint64(r.data[72:], 240)
	putRecord(r, 240, record(7))
	e, ok, err := r.Next()
	if err != nil || !ok || e.Sequence != 7 || r.Lost() != 3 {
		t.Fatal(e, ok, err, r.Lost())
	}
	for i := 8192; i < len(r.data); i++ {
		r.data[i] = 0
	}
	if e.Payload[0] != 0x80 {
		t.Fatal("event aliases ring")
	}
	if _, ok, e := r.Next(); ok || e != nil {
		t.Fatal(ok, e)
	}
	putRecord(r, 400, record(9))
	binary.LittleEndian.PutUint64(r.data[72:], 400)
	if e, ok, err = r.Next(); err != nil || !ok || e.Sequence != 9 || r.Lost() != 4 {
		t.Fatal(e, ok, err)
	}
	r.data[8192+int(r.position&255)] = 1
	binary.LittleEndian.PutUint64(r.data[64:], r.position+1)
	if _, _, e := r.Next(); e != syscall.EPROTO {
		t.Fatal(e)
	}
}
func TestWaitCancellationAndFinalRecheck(t *testing.T) {
	r := fixtureReader()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if e := r.Wait(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	done := make(chan error, 1)
	go func() { done <- r.Wait(ctx2) }()
	time.Sleep(time.Millisecond)
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&r.data[64])), 1)
	atomic.AddUint32((*uint32)(unsafe.Pointer(&r.data[128])), 1)
	syscall.Syscall6(syscall.SYS_FUTEX, uintptr(unsafe.Pointer(&r.data[128])), 1, 1, 0, 0, 0)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func FuzzRingEventAt(f *testing.F) {
	f.Add(record(1), uint64(0), uint64(78), uint64(0))
	f.Fuzz(func(t *testing.T, b []byte, pos, write, tail uint64) {
		data := make([]byte, 8192+512)
		copy(data[8192:], b)
		copy(data[8448:], data[8192:8448])
		binary.LittleEndian.PutUint64(data[64:], write)
		binary.LittleEndian.PutUint64(data[72:], tail)
		r := Ring{data: data, capacity: 256}
		v, n, e := r.EventAt(pos)
		if e == nil && (n < 77 || n > 256 || pos < tail || pos >= write || len(v.Payload) > int(n)) {
			t.Fatal("invalid success", n)
		}
	})
}
