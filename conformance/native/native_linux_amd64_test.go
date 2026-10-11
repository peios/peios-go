package native_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/peios/peios-go/event"
	"github.com/peios/peios-go/file"
	"github.com/peios/peios-go/registry"
	"github.com/peios/peios-go/security"
	"github.com/peios/peios-go/token"
)

func guest(t *testing.T) {
	t.Helper()
	if os.Getenv("PEIOS_NATIVE_TEST") != "1" {
		t.Skip("requires disposable Peios kernel guest")
	}
}
func TestTokenAgainstBothReferenceAPIs(t *testing.T) {
	guest(t)
	tok, e := token.OpenSelf(0, token.Query|token.Duplicate)
	if e != nil {
		t.Fatal(e)
	}
	defer tok.Close()
	sid, e := tok.UserSID()
	if e != nil {
		t.Fatal(e)
	}
	if !sid.Valid() {
		t.Fatal("invalid SID")
	}
	for _, env := range []string{"PEIOS_C_ORACLE", "PEIOS_RUST_ORACLE"} {
		driver := os.Getenv(env)
		if driver == "" {
			t.Fatal("missing reference", env)
		}
		out, e := exec.Command(driver, "native-user", "").CombinedOutput()
		if e != nil {
			t.Fatalf("%s: %v %s", driver, e, out)
		}
		if strings.TrimSpace(string(out)) != hex.EncodeToString(sid.Bytes()) {
			t.Fatalf("reference mismatch %s vs %x", out, sid.Bytes())
		}
	}
	if _, e = tok.Statistics(); e != nil {
		t.Fatal(e)
	}
	if _, e = tok.Privileges(); e != nil {
		t.Fatal(e)
	}
	imp, e := tok.Duplicate(token.Query|token.Impersonate, token.Impersonation, token.LevelImpersonation)
	if e != nil {
		t.Fatal(e)
	}
	defer imp.Close()
	e = imp.Impersonate(func() error {
		self, e := token.OpenSelf(0, token.Query)
		if e != nil {
			return e
		}
		defer self.Close()
		s, e := self.UserSID()
		if e == nil && s != sid {
			t.Error("impersonation SID changed")
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = tok.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = tok.UserSID(); e == nil {
		t.Fatal("closed token accepted")
	}
}
func TestFileCreationAndDescriptors(t *testing.T) {
	guest(t)
	d, e := security.ParseSDDL("O:SYG:SYD:P(A;;FA;;;SY)")
	if e != nil {
		t.Fatal(e)
	}
	sd, e := d.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	// The dedicated VM mounts an empty tmpfs, with no inherited root SD.
	if e = file.SetDescriptorAt(file.CurrentDirectory, "/tmp", security.InfoOwner|security.InfoGroup|security.InfoDACL, sd, 0); e != nil {
		t.Fatal(e)
	}
	dir := "/tmp/sdk-fixture"
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(dir)
	// A new tmpfs root has no stored parent SD. Seed only this fixture.
	if e = file.SetDescriptorAt(file.CurrentDirectory, dir, security.InfoOwner|security.InfoGroup|security.InfoDACL, sd, 0); e != nil {
		t.Fatal(e)
	}
	path := dir + "/sdk-file"
	f, _, e := file.Open(path, file.OpenOptions{Access: file.ReadData | file.WriteData | security.ReadControl | security.WriteDAC, Disposition: file.CreateNew, Descriptor: sd})
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	defer os.Remove(path)
	if _, e = f.Write([]byte("peios-go")); e != nil {
		t.Fatal(e)
	}
	if _, e = f.Seek(0, 0); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 8)
	if _, e = f.Read(b); e != nil || string(b) != "peios-go" {
		t.Fatalf("read %q %v", b, e)
	}
	got, e := file.GetDescriptor(f, security.InfoOwner|security.InfoGroup|security.InfoDACL)
	if e != nil {
		t.Fatal(e)
	}
	for _, env := range []string{"PEIOS_C_ORACLE", "PEIOS_RUST_ORACLE"} {
		out, e := exec.Command(os.Getenv(env), "native-file", path).CombinedOutput()
		if e != nil || strings.TrimSpace(string(out)) != hex.EncodeToString(got) {
			t.Fatalf("file reference %s: %v %s", env, e, out)
		}
	}
	parsed, e := security.ParseDescriptor(got)
	if e != nil {
		t.Fatal(e)
	}
	if parsed.DACL == nil || len(parsed.DACL.ACEs) != 1 {
		t.Fatalf("unexpected DACL %+v", parsed)
	}
	if e = file.SetDescriptor(f, security.InfoDACL, sd); e != nil {
		t.Fatal(e)
	}
	got, e = file.GetDescriptorAt(file.CurrentDirectory, path, security.InfoDACL, 0)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e = security.ParseDescriptor(got)
	if e != nil {
		t.Fatal(e)
	}
	acl, _ := parsed.DACL.MarshalBinary()
	want, _ := d.DACL.MarshalBinary()
	if !bytes.Equal(acl, want) {
		t.Fatal("DACL changed")
	}
	if _, _, e = file.Open(path, file.OpenOptions{Access: file.ReadData, Disposition: file.CreateNew}); !errors.Is(e, syscall.EEXIST) {
		t.Fatalf("create existing: %v", e)
	}
}
func TestRegistryBoundary(t *testing.T) {
	guest(t)
	k, e := registry.Open("MissingSDKHive\\Missing", registry.Read, 0)
	if k != nil {
		k.Close()
		t.Fatal("unexpected key")
	}
	if !errors.Is(e, syscall.ENOENT) {
		t.Fatalf("registry missing hive: %v", e)
	}
	tx, e := registry.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	if _, e = tx.Status(); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); !errors.Is(e, syscall.EINVAL) {
		t.Fatalf("unbound transaction commit must fail EINVAL: %v", e)
	}
}
func TestEventEmission(t *testing.T) {
	guest(t)
	if e := event.Emit("peios-go.conformance", []byte{0x80}); e != nil {
		t.Fatal(e)
	}
	n, e := event.EmitBatch([]event.Entry{{Type: "peios-go.conformance", Payload: []byte{0x80}}, {Type: "peios-go.conformance", Payload: []byte{0x80}}})
	if e != nil || n != 2 {
		t.Fatalf("batch %d %v", n, e)
	}
	p := event.OpenPolicy()
	if enabled, e := p.Enabled("peios-go.conformance", event.TierEssential); e != nil || !enabled {
		t.Fatal(enabled, e)
	}
}

func TestPeerToken(t *testing.T) {
	guest(t)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: "@peios-go-peer", Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	type dialResult struct {
		conn *net.UnixConn
		err  error
	}
	ch := make(chan dialResult, 1)
	go func() { c, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr)); ch <- dialResult{c, e} }()
	accepted, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	defer accepted.Close()
	dial := <-ch
	if dial.err != nil {
		t.Fatal(dial.err)
	}
	defer dial.conn.Close()
	peer, e := token.OpenPeer(accepted)
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	if sid, e := peer.UserSID(); e != nil || !sid.Valid() {
		t.Fatal(sid, e)
	}
}
