package event

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
)

// Reader owns a KMES attachment and mapping for one CPU. It starts at the
// oldest surviving event, follows resizes, and counts observed sequence gaps.
// Events own their bytes. Methods and Close are safe to call concurrently.
type Reader struct {
	mu                                         sync.Mutex
	cpu                                        uint32
	f                                          *os.File
	data                                       []byte
	capacity, position, generation, last, lost uint64
}

func SlotCount() (uint32, error) {
	var n uint64
	var p native.Pins
	defer p.Unpin()
	_, e := native.Call(uapi.SYS_KMES_ATTACH, uapi.KMES_ATTACH_QUERY_SLOTS, p.Pointer(unsafe.Pointer(&n)))
	if e != nil {
		return 0, e
	}
	if n > 1<<20 {
		return 0, syscall.EOVERFLOW
	}
	return uint32(n), nil
}
func Attach(cpu uint32) (*Reader, error) {
	r := &Reader{cpu: cpu}
	if e := r.attach(); e != nil {
		return nil, e
	}
	return r, nil
}

// AttachAll walks the kernel's slot count, including slots after offline holes.
// A hard error closes every attachment already opened.
func AttachAll() ([]*Reader, error) {
	n, e := SlotCount()
	if e != nil {
		return nil, e
	}
	var out []*Reader
	for cpu := uint32(0); cpu < n; cpu++ {
		r, e := Attach(cpu)
		if e == syscall.EINVAL || e == syscall.ENODEV {
			continue
		}
		if e != nil {
			for _, r := range out {
				r.Close()
			}
			return nil, e
		}
		out = append(out, r)
	}
	return out, nil
}
func (r *Reader) attach() error {
	var capacity uint64
	var p native.Pins
	defer p.Unpin()
	fd, e := native.Call(uapi.SYS_KMES_ATTACH, uintptr(r.cpu), p.Pointer(unsafe.Pointer(&capacity)))
	if e != nil {
		return e
	}
	f := native.File(fd, "peios.kmes")
	if capacity == 0 || capacity&(capacity-1) != 0 || capacity > (1<<30) {
		f.Close()
		return syscall.EOVERFLOW
	}
	data, e := syscall.Mmap(int(fd), 0, 8192+int(capacity)*2, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if e != nil {
		f.Close()
		return e
	}
	if string(data[:8]) != "KMESRING" || binary.LittleEndian.Uint32(data[8:]) != 1 || binary.LittleEndian.Uint32(data[12:]) != r.cpu || binary.LittleEndian.Uint64(data[16:]) != capacity || binary.LittleEndian.Uint64(data[24:]) != 8192 {
		syscall.Munmap(data)
		f.Close()
		return syscall.EPROTO
	}
	old, oldf := r.data, r.f
	r.data, r.f, r.capacity = data, f, capacity
	r.position = r.load64(72)
	r.generation = r.load64(32)
	if old != nil {
		syscall.Munmap(old)
	}
	if oldf != nil {
		oldf.Close()
	}
	return nil
}
func (r *Reader) load64(off int) uint64 {
	return atomic.LoadUint64((*uint64)(unsafe.Pointer(&r.data[off])))
}
func (r *Reader) Close() error {
	if r == nil {
		return syscall.EBADF
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return syscall.EBADF
	}
	e := errors.Join(syscall.Munmap(r.data), r.f.Close())
	r.data = nil
	r.f = nil
	return e
}
func (r *Reader) CPU() uint32  { return r.cpu }
func (r *Reader) Lost() uint64 { r.mu.Lock(); defer r.mu.Unlock(); return r.lost }
func (r *Reader) Next() (Event, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return Event{}, false, syscall.EBADF
	}
	for tries := 0; tries < 64; tries++ {
		if r.load64(32) != r.generation {
			if e := r.attach(); e != nil {
				return Event{}, false, e
			}
			continue
		}
		write := r.load64(64)
		if write == r.position {
			return Event{}, false, nil
		}
		tail := r.load64(72)
		if r.position < tail {
			r.position = tail
			continue
		}
		if write < r.position {
			return Event{}, false, syscall.EPROTO
		}
		off := 8192 + int(r.position&(r.capacity-1))
		n := uint64(binary.LittleEndian.Uint32(r.data[off:]))
		if n < 77 || n > r.capacity || n > write-r.position {
			if r.load64(72) > r.position {
				continue
			}
			return Event{}, false, syscall.EPROTO
		}
		b := append([]byte(nil), r.data[off:off+int(n)]...)
		if r.load64(72) > r.position || r.load64(32) != r.generation {
			continue
		}
		v, size, e := ParseEvent(b)
		if e != nil {
			return Event{}, false, e
		}
		if r.last != 0 && v.Sequence > r.last && v.Sequence-r.last > 1 {
			r.lost += v.Sequence - r.last - 1
		}
		r.last = v.Sequence
		r.position += uint64(size)
		return v, true, nil
	}
	return Event{}, false, syscall.EAGAIN
}

// Wait blocks until this reader may have events, or ctx expires. A 50ms upper
// bound on each futex wait permits concurrent Close and cancellation without
// unmapping memory beneath a sleeping syscall. Call Next to drain after Wait.
func (r *Reader) Wait(ctx context.Context) error {
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		ready, e := r.waitStep()
		if e != nil {
			return e
		}
		if ready {
			return nil
		}
	}
}
func (r *Reader) waitStep() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return false, syscall.EBADF
	}
	if r.load64(32) != r.generation || r.load64(64) != r.position {
		return true, nil
	}
	wake := (*uint32)(unsafe.Pointer(&r.data[4096]))
	atomic.StoreUint32(wake, 1)
	defer atomic.StoreUint32(wake, 0)
	counter := (*uint32)(unsafe.Pointer(&r.data[128]))
	observed := atomic.LoadUint32(counter)
	// Counter must be captured before the final condition check: a producer
	// between the check and sleep then makes FUTEX_WAIT return EAGAIN.
	if r.load64(64) != r.position || r.load64(32) != r.generation {
		return true, nil
	}
	timeout := syscall.NsecToTimespec(int64(50 * time.Millisecond))
	_, _, errno := syscall.Syscall6(syscall.SYS_FUTEX, uintptr(unsafe.Pointer(counter)), 0, uintptr(observed), uintptr(unsafe.Pointer(&timeout)), 0, 0)
	if errno != 0 && errno != syscall.EAGAIN && errno != syscall.EINTR && errno != syscall.ETIMEDOUT {
		return false, errno
	}
	return r.load64(64) != r.position || r.load64(32) != r.generation, nil
}
