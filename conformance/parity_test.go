package conformance

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/peios/peios-go/event"
	"github.com/peios/peios-go/msgpack"
	"github.com/peios/peios-go/security"
	"github.com/peios/peios-go/socket"
	"github.com/peios/peios-go/token"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func cursorResult(op string, b []byte) string {
	r := msgpack.Reader{Data: b}
	k, e := r.Peek()
	if e != nil {
		k = -1
	}
	v := ""
	switch op {
	case "nil":
		e = r.Nil()
	case "bool":
		var x bool
		x, e = r.Bool()
		if x {
			v = "1"
		} else {
			v = "0"
		}
	case "int":
		var x int64
		x, e = r.Int()
		v = fmt.Sprint(x)
	case "uint":
		var x uint64
		x, e = r.Uint()
		v = fmt.Sprint(x)
	case "float":
		var x float64
		x, e = r.Float()
		v = fmt.Sprintf("%016x", math.Float64bits(x))
	case "str":
		var x []byte
		x, e = r.StringBytes()
		v = hex.EncodeToString(x)
	case "bin":
		var x []byte
		x, e = r.Binary()
		v = hex.EncodeToString(x)
	case "ext":
		var x msgpack.Extension
		x, e = r.Extension()
		v = fmt.Sprintf("%d:%x", x.Type, x.Data)
	case "array":
		var x uint32
		x, e = r.Array()
		v = fmt.Sprint(x)
	case "map":
		var x uint32
		x, e = r.Map()
		v = fmt.Sprint(x)
	case "skip":
		e = r.Skip()
	}
	if e != nil {
		return fmt.Sprintf("%d error %d", k, r.Remaining())
	}
	return strings.TrimSpace(fmt.Sprintf("%d ok %d %s", k, r.Remaining(), v))
}
func referenceText(t *testing.T, drivers []string, mode, arg, want string) {
	t.Helper()
	for _, d := range drivers {
		b, e := exec.Command(d, mode, arg).CombinedOutput()
		if e != nil || strings.TrimSpace(string(b)) != want {
			t.Fatalf("%s %s %s: Go=%q reference=%q err=%v", d, mode, arg, want, b, e)
		}
	}
}
func TestMessagePackCursorParity(t *testing.T) {
	ds := references(t)
	cases := [][]byte{{}, {0xc1}, {0xd9, 1, 255}, {0xdd, 255, 255, 255, 255}, {0xdf, 255, 255, 255, 255}, append(bytes.Repeat([]byte{0x91}, 300), 0xc0)}
	for _, v := range []any{nil, true, false, int64(-129), int64(math.MinInt64), uint64(math.MaxUint64), uint64(128), 1.5, math.NaN(), "héllo", []byte("abc"), msgpack.Extension{Type: -128, Data: []byte("xy")}, []any{nil, msgpack.Map{{Key: "x", Value: 1}}}} {
		b, e := msgpack.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		for n := 0; n <= len(b); n++ {
			cases = append(cases, b[:n])
		}
	}
	// Every lead byte, including noncanonical numeric forms and truncated headers.
	for c := 0; c < 256; c++ {
		cases = append(cases, []byte{byte(c), 0, 0, 0, 0, 0, 0, 0, 0})
	}
	for i, b := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			for _, op := range []string{"nil", "bool", "int", "uint", "float", "str", "bin", "ext", "array", "map", "skip"} {
				referenceText(t, ds, "mp-cursor", op+"|"+hex.EncodeToString(b), cursorResult(op, b))
			}
		})
	}
	var w msgpack.Writer
	b, e := w.Array(10).Nil().Bool(true).Int(-129).Uint(math.MaxUint64).Float(1.5).String("hello").Binary([]byte("abc")).Extension(msgpack.Extension{Type: -1, Data: []byte("xy")}).Map(1).String("n").Int(128).Array(0).Bytes()
	if e != nil {
		t.Fatal(e)
	}
	compareBytes(t, "mp-fixture", "", b)
	for _, depth := range []int{0, 1, 32, 256, 257} {
		for _, n := range []int{0, 1, 31, 32, 255, 256} {
			b := append(bytes.Repeat([]byte{0x91}, n), 0xc0)
			want := "ok"
			if msgpack.Validate(b, depth) != nil {
				want = "error"
			}
			referenceText(t, ds, "mp-depth", fmt.Sprintf("%d|%x", depth, b), want)
		}
	}
}
func TestSecurityBinaryParity(t *testing.T) {
	ds := references(t)
	for _, s := range []string{"O:SYG:BAD:(A;;FA;;;WD)", "D:", "O:SY", "D:(OA;;GR;00112233-4455-6677-8899-aabbccddeeff;;WD)", "D:(XA;;GA;;;WD;(@User.Level == 1))", "D:(FL;;GA;;;WD;(@User.Level == 1))", "S:(RA;;;;;WD;(\"Bytes\",TX,0x0,#aabb))"} {
		d, e := security.ParseSDDL(s)
		if e != nil {
			t.Fatal(e)
		}
		sd, e := d.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		cases := [][]byte{sd}
		for i := range sd {
			b := bytes.Clone(sd)
			b[i] ^= 0xff
			cases = append(cases, b)
		}
		for n := 0; n < len(sd); n++ {
			cases = append(cases, sd[:n])
		}
		for i, b := range cases {
			t.Run(fmt.Sprintf("sd/%s/%d", s, i), func(t *testing.T) {
				want := "ok"
				if _, e := security.ParseDescriptor(b); e != nil {
					want = "error"
				}
				referenceText(t, ds, "sd-validate", hex.EncodeToString(b), want)
			})
		}
		if d.DACL == nil {
			continue
		}
		acl, _ := d.DACL.MarshalBinary()
		cases = [][]byte{acl}
		for i := range acl {
			b := bytes.Clone(acl)
			b[i] ^= 0xff
			cases = append(cases, b)
		}
		// ACLs may have reserved trailing allocation space; probe accepted bounds.
		b := append(bytes.Clone(acl), 0, 0, 0, 0)
		binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
		cases = append(cases, b)
		for i, b := range cases {
			t.Run(fmt.Sprintf("acl/%s/%d", s, i), func(t *testing.T) {
				want := "ok"
				if _, e := security.ParseACL(b); e != nil {
					want = "error"
				}
				referenceText(t, ds, "acl-validate", hex.EncodeToString(b), want)
			})
		}
	}
}

func TestRingReferenceAPIs(t *testing.T) {
	ds := references(t)
	b := make([]byte, 8192+512)
	copy(b, "KMESRING")
	binary.LittleEndian.PutUint32(b[8:], 1)
	binary.LittleEndian.PutUint64(b[16:], 256)
	binary.LittleEndian.PutUint64(b[24:], 8192)
	binary.LittleEndian.PutUint64(b[32:], 7)
	binary.LittleEndian.PutUint64(b[72:], 240)
	record := make([]byte, 80)
	binary.LittleEndian.PutUint32(record, 80)
	binary.LittleEndian.PutUint32(record[4:], 79)
	binary.LittleEndian.PutUint64(record[16:], 42)
	binary.LittleEndian.PutUint16(record[75:], 2)
	copy(record[77:], "go")
	record[79] = 0xc0
	for i, c := range record {
		off := (240 + i) & 255
		b[8192+off] = c
		b[8192+256+off] = c
	}
	binary.LittleEndian.PutUint64(b[64:], 320)
	name := filepath.Join(t.TempDir(), "ring")
	if e := os.WriteFile(name, b, 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(name, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	r, e := event.MapRing(f, 256)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	m, e := r.Metadata()
	if e != nil {
		t.Fatal(e)
	}
	v, n, e := r.EventAt(m.TailPosition)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = r.Wait(ctx, m.TailPosition); e != nil {
		t.Fatal(e)
	}
	want := fmt.Sprintf("%d %d %d %d %d %d 1 %x", m.Capacity, m.TailPosition, m.WritePosition, m.Generation, n, v.Sequence, v.Payload)
	referenceText(t, ds, "ring", name, want)
	if _, _, e = r.EventAt(m.TailPosition - 1); e != syscall.EAGAIN {
		t.Fatal(e)
	}
	if _, _, e = r.EventAt(m.WritePosition); e != syscall.EAGAIN {
		t.Fatal(e)
	}
	if e = r.Wait(ctx, m.WritePosition); e != context.Canceled {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Metadata(); e != syscall.EBADF {
		t.Fatal(e)
	}
	if len(v.Payload) != 1 || v.Payload[0] != 0xc0 {
		t.Fatal("event lost after unmap")
	}
}

func TestSocketReferenceAPIs(t *testing.T) {
	ds := references(t)
	for count := 0; count <= 3; count++ {
		fds, e := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
		if e != nil {
			t.Fatal(e)
		}
		a, b := os.NewFile(uintptr(fds[0]), "sender"), os.NewFile(uintptr(fds[1]), "receiver")
		f, e := os.Open("/dev/null")
		if e != nil {
			t.Fatal(e)
		}
		payload := []byte("hello")
		buf := make([]byte, 1)
		cap := count
		if count == 3 {
			payload = nil
			buf = nil
			cap = 2
		}
		sent, e := socket.Send(a, payload, nil, []syscall.Conn{f, f}, 0)
		if e != nil {
			t.Fatal(e)
		}
		m, e := socket.ReceivePartial(b, buf, cap, 0)
		if e != nil {
			t.Fatal(e)
		}
		flags := 0
		if m.Flags&syscall.MSG_TRUNC != 0 {
			flags |= 1
		}
		if m.Flags&syscall.MSG_CTRUNC != 0 {
			flags |= 2
		}
		want := fmt.Sprintf("%d %d %d %d", sent, m.N, len(m.Files), flags)
		m.Close()
		a.Close()
		b.Close()
		f.Close()
		referenceText(t, ds, "socket", fmt.Sprint(count), want)
	}
}
func TestTokenBuilderBoundaries(t *testing.T) {
	ds := references(t)
	sid, _ := security.ParseSID("SY")
	for _, n := range []int{0, 1024, 1025, 3266, 3267} {
		spec := token.Spec{User: sid}
		for i := 0; i < n; i++ {
			spec.Groups = append(spec.Groups, token.Group{SID: sid, Attributes: 7})
		}
		b, e := spec.MarshalBinary()
		if e != nil {
			referenceText(t, ds, "token-extra", fmt.Sprint(n), "error")
		} else {
			compareBytes(t, "token-extra", fmt.Sprint(n), b)
		}
	}
	spec := token.Spec{User: sid}
	for _, typ := range []uint16{1, 2, 3, 5, 6, 16} {
		spec.UserClaims = append(spec.UserClaims, security.Claim{Name: "empty", ValueType: typ})
	}
	b, e := spec.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	compareBytes(t, "token-extra", "empty", b)
}
