// Package source hosts LCS registry sources. Registration uses the current
// Peios UAPI; requests and responses use the message-oriented RSI protocol.
package source

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
)

const Path = "/dev/pkm_registry"

type Hive struct {
	Name    string
	Root    GUID
	Private bool
	Scope   GUID
}
type Source struct{ f *os.File }

func Open(hives []Hive, maxSequence uint64) (*Source, error) {
	f, e := os.OpenFile(Path, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	s := &Source{f}
	if e = s.register(hives, maxSequence); e != nil {
		f.Close()
		return nil, e
	}
	return s, nil
}
func (s *Source) Close() error {
	if s == nil || s.f == nil {
		return syscall.EBADF
	}
	return s.f.Close()
}
func (s *Source) register(hives []Hive, maxSequence uint64) error {
	if len(hives) == 0 || len(hives) > 65536 {
		return syscall.EINVAL
	}
	return native.WithFD(s.f, func(fd int) error {
		var p native.Pins
		defer p.Unpin()
		entries := make([]uapi.Reg_src_hive_entry, len(hives))
		for i, h := range hives {
			if len(h.Name) > 65535 {
				return syscall.EINVAL
			}
			entries[i] = uapi.Reg_src_hive_entry{Name_len: uint32(len(h.Name)), Name_ptr: uint64(p.Bytes([]byte(h.Name))), Root_guid: h.Root, Scope_guid: h.Scope}
			if h.Private {
				entries[i].Flags = uapi.RSI_HIVE_PRIVATE
			}
		}
		a := uapi.Reg_src_register_args{Hive_count: uint32(len(entries)), Max_sequence: maxSequence, Hives_ptr: uint64(p.Pointer(unsafe.Pointer(&entries[0])))}
		return native.Ioctl(fd, uapi.REG_SRC_REGISTER, unsafe.Pointer(&a))
	})
}

type Handler func(context.Context, RequestHeader, []byte) (uint32, []byte)

// Serve processes up to concurrency requests at once and serializes whole
// response writes. Handlers must return on cancellation. Serve takes exclusive
// ownership of the source for its duration and closes it on return or cancel,
// interrupting reads and failing pending kernel requests. Handler panics become
// storage errors. Transport errors are returned, never merely logged.
func (s *Source) Serve(ctx context.Context, concurrency int, handler Handler) (result error) {
	if s == nil || s.f == nil {
		return syscall.EBADF
	}
	if concurrency < 1 || concurrency > 1024 || handler == nil {
		return syscall.EINVAL
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	var workers sync.WaitGroup

	var writeMu sync.Mutex
	sem := make(chan struct{}, concurrency)
	fail := make(chan error, 1)
	defer func() {
		cancel()
		s.Close()
		workers.Wait()
		if result == nil {
			select {
			case result = <-fail:
			default:
			}
		}
	}()
	report := func(e error) {
		select {
		case fail <- e:
		default:
		}
		cancel()
	}
	buf := make([]byte, MaxRequestSize)
	for {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			select {
			case e := <-fail:
				return e
			default:
				return ctx.Err()
			}
		}
		n, e := s.f.Read(buf)
		if e != nil {
			<-sem
			select {
			case e := <-fail:
				return e
			default:
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(e, io.EOF) {
				return nil
			}
			return e
		}
		hdr, payload, e := ParseRequest(buf[:n])
		if e != nil {
			<-sem
			return e
		}
		payload = append([]byte(nil), payload...)
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-sem }()
			status, response := invoke(ctx, handler, hdr, payload)
			writeMu.Lock()
			e := WriteResponse(s.f, hdr.RequestID, hdr.OpCode, status, response)
			writeMu.Unlock()
			if e != nil {
				report(e)
			}
		}()
	}
}
func invoke(ctx context.Context, h Handler, header RequestHeader, payload []byte) (status uint32, response []byte) {
	defer func() {
		if recover() != nil {
			status = StatusStorageError
			response = nil
		}
	}()
	return h(ctx, header, payload)
}
