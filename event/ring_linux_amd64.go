package event

import (
	"context"
	"encoding/binary"
	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// AttachFile returns an owned attachment fd and its data capacity. MapRing may
// map it independently; closing the file does not release existing mappings.
func AttachFile(cpu uint32) (*os.File, uint64, error) {
	var capacity uint64
	var p native.Pins
	defer p.Unpin()
	fd, e := native.Call(uapi.SYS_KMES_ATTACH, uintptr(cpu), p.Pointer(unsafe.Pointer(&capacity)))
	if e != nil {
		return nil, 0, e
	}
	return native.File(fd, "peios.kmes"), capacity, nil
}

// Ring owns only a mapping. Callers own their absolute byte cursor and handle
// lapping and generation changes using Metadata. Methods are safe with Close.
// Unlike Reader, Ring never advances a cursor or automatically reattaches.
type Ring struct {
	mu       sync.Mutex
	data     []byte
	capacity uint64
}
type RingMetadata struct{ Capacity, WritePosition, TailPosition, Generation uint64 }

func MapRing(f syscall.Conn, capacity uint64) (*Ring, error) {
	if capacity == 0 || capacity&(capacity-1) != 0 || capacity > uint64((int(^uint(0)>>1)-8192)/2) {
		return nil, syscall.EINVAL
	}
	var data []byte
	e := native.WithFD(f, func(fd int) error {
		var e error
		data, e = syscall.Mmap(fd, 0, 8192+2*int(capacity), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		return e
	})
	if e != nil {
		return nil, e
	}
	if string(data[:8]) != "KMESRING" || binary.LittleEndian.Uint32(data[8:]) != 1 || binary.LittleEndian.Uint64(data[16:]) != capacity {
		syscall.Munmap(data)
		return nil, syscall.EINVAL
	}
	return &Ring{data: data, capacity: capacity}, nil
}
func (r *Ring) load(off int) uint64 {
	return atomic.LoadUint64((*uint64)(unsafe.Pointer(&r.data[off])))
}

// Metadata uses atomic loads. Fields are individually current, not an atomic
// snapshot of a producer transaction; recheck after copying an event.
func (r *Ring) Metadata() (RingMetadata, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.data == nil {
		return RingMetadata{}, syscall.EBADF
	}
	return RingMetadata{r.capacity, r.load(64), r.load(72), r.load(32)}, nil
}
func (r *Ring) SetNeedWake(on bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.data == nil {
		return syscall.EBADF
	}
	var v uint32
	if on {
		v = 1
	}
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&r.data[4096])), v)
	return nil
}

// EventAt returns an owned event and its wire size at position. EAGAIN means
// the position is empty, lapped or changed while copying; EPROTO is corruption.
// A generation change requires a fresh attachment and mapping.
func (r *Ring) EventAt(position uint64) (Event, uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.data == nil {
		return Event{}, 0, syscall.EBADF
	}
	generation := r.load(32)
	write := r.load(64)
	tail := r.load(72)
	if position < tail || position >= write {
		return Event{}, 0, syscall.EAGAIN
	}
	if r.capacity < 77 {
		return Event{}, 0, syscall.EPROTO
	}
	off := 8192 + int(position&(r.capacity-1))
	n := uint64(binary.LittleEndian.Uint32(r.data[off:]))
	if n < 77 || n > r.capacity || n > write-position {
		if r.load(72) > position || r.load(32) != generation {
			return Event{}, 0, syscall.EAGAIN
		}
		return Event{}, 0, syscall.EPROTO
	}
	b := append([]byte(nil), r.data[off:off+int(n)]...)
	if r.load(72) > position || r.load(32) != generation {
		return Event{}, 0, syscall.EAGAIN
	}
	v, size, e := ParseEvent(b)
	return v, uint64(size), e
}

// Wait waits for writes beyond position or a generation change. A deadline
// supplies a timeout; a canceled context supplies a nonblocking readiness check.
// Readiness wins over cancellation. Recheck Metadata and drain after success.
func (r *Ring) Wait(ctx context.Context, position uint64) error {
	r.mu.Lock()
	if r.data == nil {
		r.mu.Unlock()
		return syscall.EBADF
	}
	generation := r.load(32)
	r.mu.Unlock()
	for {
		ready, e := r.waitStep(ctx, position, generation)
		if e != nil {
			return e
		}
		if ready {
			return nil
		}
	}
}
func (r *Ring) waitStep(ctx context.Context, position, generation uint64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.data == nil {
		return false, syscall.EBADF
	}
	if r.load(64) != position || r.load(32) != generation {
		return true, nil
	}
	if e := ctx.Err(); e != nil {
		return false, e
	}
	wake := (*uint32)(unsafe.Pointer(&r.data[4096]))
	atomic.StoreUint32(wake, 1)
	defer atomic.StoreUint32(wake, 0)
	counter := (*uint32)(unsafe.Pointer(&r.data[128]))
	observed := atomic.LoadUint32(counter)
	if r.load(64) != position || r.load(32) != generation {
		return true, nil
	}
	duration := 50 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline); left < duration {
			duration = left
		}
		if duration <= 0 {
			return false, context.DeadlineExceeded
		}
	}
	ts := syscall.NsecToTimespec(int64(duration))
	_, _, errno := syscall.Syscall6(syscall.SYS_FUTEX, uintptr(unsafe.Pointer(counter)), 0, uintptr(observed), uintptr(unsafe.Pointer(&ts)), 0, 0)
	if errno != 0 && errno != syscall.EAGAIN && errno != syscall.EINTR && errno != syscall.ETIMEDOUT {
		return false, errno
	}
	return false, nil
}
func (r *Ring) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.data == nil {
		return syscall.EBADF
	}
	e := syscall.Munmap(r.data)
	if e == nil {
		r.data = nil
	}
	return e
}
