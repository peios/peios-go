package source

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestServeCancelAndPanic(t *testing.T) {
	fds, e := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	s := &Source{os.NewFile(uintptr(fds[0]), "source-test")}
	peer := os.NewFile(uintptr(fds[1]), "kernel-test")
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- s.Serve(ctx, 2, func(context.Context, RequestHeader, []byte) (uint32, []byte) { panic("test") })
	}()
	req := make([]byte, 22)
	binary.LittleEndian.PutUint32(req, 22)
	binary.LittleEndian.PutUint64(req[4:], 7)
	binary.LittleEndian.PutUint16(req[12:], OpFlush)
	if _, e = peer.Write(req); e != nil {
		t.Fatal(e)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 128)
	n, e := peer.Read(b)
	if e != nil || n != 18 || binary.LittleEndian.Uint32(b[14:]) != StatusStorageError {
		t.Fatal(n, e, b[:n])
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not cancel")
	}
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }
func TestResponseShortWrite(t *testing.T) {
	if e := WriteResponse(shortWriter{}, 1, OpFlush, StatusOK, nil); e != io.ErrShortWrite {
		t.Fatal(e)
	}
}
func FuzzRequest(f *testing.F) {
	b := make([]byte, 22)
	binary.LittleEndian.PutUint32(b, 22)
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		h, p, e := ParseRequest(b)
		if e != nil {
			return
		}
		if int(h.TotalLen) != len(b) || len(p) != len(b)-22 {
			t.Fatal("framing")
		}
		d := NewDecoder(p)
		DecodeCreateKeyRequest(d)
		d = NewDecoder(p)
		DecodeSetValueRequest(d)
	})
}
