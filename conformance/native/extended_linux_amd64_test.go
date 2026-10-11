package native_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/peios/peios-go/access"
	"github.com/peios/peios-go/event"
	"github.com/peios/peios-go/process"
	"github.com/peios/peios-go/security"
	"github.com/peios/peios-go/socket"
	"github.com/peios/peios-go/token"
)

func TestAccessDecisions(t *testing.T) {
	guest(t)
	for _, s := range []string{"O:SYG:SYD:(A;;0x1;;;SY)", "O:SYG:SYD:(D;;0x1;;;SY)", "O:SYG:SYD:"} {
		d, e := security.ParseSDDL(s)
		if e != nil {
			t.Fatal(e)
		}
		sd, _ := d.MarshalBinary()
		audit, _ := access.AuditContext("service", []access.Field{{Name: "name", Value: "sdk"}})
		req := access.Request{Descriptor: sd, Desired: 1, Mapping: security.GenericMapping{Read: 1, Write: 2, Execute: 4, All: 7}, AuditContext: audit}
		r, e := access.Check(req)
		if e != nil && !errors.Is(e, syscall.EACCES) {
			t.Fatal(e)
		}
		allowed := 0
		if e == nil {
			allowed = 1
		}
		want := fmt.Sprintf("%d %d", allowed, r.Granted)
		for _, env := range []string{"PEIOS_C_ORACLE", "PEIOS_RUST_ORACLE"} {
			b, e := exec.Command(os.Getenv(env), "native-access", s).CombinedOutput()
			if e != nil || strings.TrimSpace(string(b)) != want {
				t.Fatalf("%s Go %s ref %s (%v)", s, want, b, e)
			}
		}
		req.ObjectTree = []access.ObjectType{{Level: 0, GUID: security.GUID{1}}}
		nodes, e := access.CheckList(req)
		if e != nil || len(nodes) != 1 || nodes[0].Granted != r.Granted {
			t.Fatalf("list %v %v", nodes, e)
		}
	}
}
func TestTokenConstructionAndTransforms(t *testing.T) {
	guest(t)
	self, e := token.OpenSelf(0, token.Query|token.Duplicate)
	if e != nil {
		t.Fatal(e)
	}
	defer self.Close()
	sid, e := self.UserSID()
	if e != nil {
		t.Fatal(e)
	}
	priv, e := self.Privileges()
	if e != nil {
		t.Fatal(e)
	}
	session, e := (token.SessionSpec{User: sid, LogonType: 5, AuthPackage: "peios-go"}).Create()
	if e != nil {
		t.Fatal(e)
	}
	// Closing every derived token permits destruction of this isolated session.
	func() {
		spec := token.Spec{User: sid, Type: token.Primary, Level: token.LevelImpersonation, IntegrityRID: 16384, SessionID: session, PrivilegesPresent: priv.Present, PrivilegesEnabled: priv.Enabled, DefaultDACL: &security.ACL{ACEs: []security.ACE{{Type: security.Allow, Mask: security.GenericAll, SID: sid}}}}
		tok, e := spec.Create()
		if e != nil {
			t.Fatal(e)
		}
		defer tok.Close()
		if got, e := tok.UserSID(); e != nil || got != sid {
			t.Fatal(got, e)
		}
		if _, e = tok.Integrity(); e != nil {
			t.Fatal(e)
		}
		if _, e = tok.Type(); e != nil {
			t.Fatal(e)
		}
		if _, e = tok.ImpersonationLevel(); e != nil {
			t.Fatal(e)
		}
		if e = tok.ResetPrivileges(); e != nil {
			t.Fatal(e)
		}
		if e = tok.ResetGroups(); e != nil {
			t.Fatal(e)
		}
		if _, e = tok.AdjustPrivileges([]token.PrivilegeAdjustment{{LUID: uint32(bits.TrailingZeros64(priv.Present)), Attributes: 0}}); e != nil {
			t.Fatal(e)
		}
		if e = tok.AdjustDefaults(nil, 0xffff, 0xffff); e != nil {
			t.Fatal(e)
		}
		restricted, e := tok.Restrict(token.Restriction{DeletePrivileges: priv.Present})
		if e != nil {
			t.Fatal(e)
		}
		p, e := restricted.Privileges()
		if err := token.Link(tok, restricted, session); err != nil {
			t.Fatal("link", err)
		}
		linked, err := tok.Linked()
		if err != nil {
			t.Fatal("linked", err)
		}
		linked.Close()
		restricted.Close()
		if e != nil || p.Present != 0 {
			t.Fatal(p, e)
		}
		if groups, e := tok.GroupList(token.Groups); e != nil || len(groups) == 0 {
			t.Fatal("group query", groups, e)
		}
		if e = tok.SetInteractivityScope(42); e != nil {
			t.Fatal(e)
		}
		if n, e := tok.InteractivityScope(); e != nil || n != 42 {
			t.Fatal(n, e)
		}
		sessions, e := token.ListSessions()
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, s := range sessions {
			if s.ID == session && s.User == sid && s.AuthPackage == "peios-go" {
				found = true
			}
		}
		if !found {
			t.Fatal("created session absent")
		}
	}()
	if e = token.DestroyEmptySession(session); !errors.Is(e, syscall.ENOENT) {
		t.Fatal("last token must destroy session", e)
	}
	empty, e := (token.SessionSpec{User: sid, LogonType: 5, AuthPackage: "empty"}).Create()
	if e != nil {
		t.Fatal(e)
	}
	if e = token.DestroyEmptySession(empty); e != nil {
		t.Fatal(e)
	}
}
func TestProcessSecurity(t *testing.T) {
	guest(t)
	b, e := process.ReadSecurityBlock(0)
	if e != nil {
		t.Fatal(e)
	}
	if b.GUID == ([16]byte{}) {
		t.Fatal("nil process GUID")
	}
	if e = process.SetMitigations(nil, 0); e != nil {
		t.Fatal(e)
	}
	after, e := process.ReadSecurityBlock(os.Getpid())
	if e != nil || after != b {
		t.Fatal(after, e)
	}
	if e = process.SetMitigations(nil, 0xffffffff); e == nil {
		t.Fatal("unknown mitigation bits accepted")
	}
}
func TestSocketMessageIdentity(t *testing.T) {
	guest(t)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: "@sdk-message", Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	if e = socket.Restamp(listener); e != nil {
		t.Fatal(e)
	}
	client, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	server.SetDeadline(time.Now().Add(3 * time.Second))
	if e = socket.SetImpersonationLevel(client, token.LevelImpersonation); e != nil {
		t.Fatal(e)
	}
	if level, e := socket.ImpersonationLevel(client); e != nil || level != token.LevelImpersonation {
		t.Fatal(level, e)
	}
	pidfd, e := socket.PeerPIDFD(server)
	if e != nil {
		t.Fatal(e)
	}
	pidfd.Close()
	tok, e := token.OpenSelf(0, token.Query|token.Duplicate|token.Impersonate)
	if e != nil {
		t.Fatal(e)
	}
	defer tok.Close()
	f, e := os.Open("/proc/self/psb")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	n, e := socket.Send(client, []byte("x"), tok, []syscall.Conn{f}, 0)
	if e != nil || n != 1 {
		t.Fatal(n, e)
	}
	buf := make([]byte, 32)
	m, e := socket.Receive(server, buf, 1, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	if m.N != 1 || buf[0] != 'x' || m.Token == nil || len(m.Files) != 1 {
		t.Fatalf("message %+v", m)
	}
	want, _ := tok.UserSID()
	got, e := m.Token.UserSID()
	if e != nil || got != want {
		t.Fatal(got, e)
	}
	if _, e = m.Files[0].Read(buf); e != nil {
		t.Fatal(e)
	}
	if e = socket.SetPassToken(client, true); e != nil {
		t.Fatal(e)
	}
	if _, e = socket.Send(client, []byte("y"), nil, nil, 0); e != nil {
		t.Fatal(e)
	}
	m2, e := socket.Receive(server, buf, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer m2.Close()
	if m2.Token == nil {
		t.Fatal("automatic identity missing")
	}
}
func TestEventConsumption(t *testing.T) {
	guest(t)
	rs, e := event.AttachAll()
	if e != nil || len(rs) == 0 {
		t.Fatal(len(rs), e)
	}
	defer func() {
		for _, r := range rs {
			r.Close()
		}
	}()
	for _, r := range rs {
		for {
			_, ok, e := r.Next()
			if e != nil {
				t.Fatal(e)
			}
			if !ok {
				break
			}
		}
	}
	if e = event.Emit("peios-go.reader-test", []byte{0x81, 0xa1, 'n', 42}); e != nil {
		t.Fatal(e)
	}
	found := false
	for _, r := range rs {
		for {
			v, ok, e := r.Next()
			if e != nil {
				t.Fatal(e)
			}
			if !ok {
				break
			}
			if v.Type == "peios-go.reader-test" {
				found = true
				if !bytes.Equal(v.Payload, []byte{0x81, 0xa1, 'n', 42}) {
					t.Fatal(v)
				}
			}
		}
	}
	if !found {
		t.Fatal("emitted event missing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = rs[0].Wait(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	rs[0].Close()
	if _, _, e = rs[0].Next(); !errors.Is(e, syscall.EBADF) {
		t.Fatal(e)
	}
}

func TestLowLevelRingAndIdentityThread(t *testing.T) {
	guest(t)
	slots, e := event.SlotCount()
	if e != nil {
		t.Fatal(e)
	}
	var rings []*event.Ring
	defer func() {
		for _, r := range rings {
			r.Close()
		}
	}()
	for cpu := uint32(0); cpu < slots; cpu++ {
		f, cap, e := event.AttachFile(cpu)
		if e == syscall.EINVAL || e == syscall.ENODEV {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		r, e := event.MapRing(f, cap)
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
		rings = append(rings, r)
		if e = r.SetNeedWake(true); e != nil {
			t.Fatal(e)
		}
		if e = r.SetNeedWake(false); e != nil {
			t.Fatal(e)
		}
	}
	if len(rings) == 0 {
		t.Fatal("no ring")
	}
	if e = event.Emit("peios-go.low-level", []byte{0xc0}); e != nil {
		t.Fatal(e)
	}
	found := false
	for _, r := range rings {
		meta, e := r.Metadata()
		if e != nil {
			t.Fatal(e)
		}
		for pos := meta.TailPosition; pos < meta.WritePosition; {
			v, n, e := r.EventAt(pos)
			if e != nil {
				t.Fatal(e)
			}
			pos += n
			if v.Type == "peios-go.low-level" {
				found = true
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if e = r.Wait(ctx, meta.WritePosition); e != nil && e != context.Canceled {
			t.Fatal(e)
		}
	}
	if !found {
		t.Fatal("low-level event absent")
	}
	self, e := token.OpenSelf(0, token.Query|token.Duplicate)
	if e != nil {
		t.Fatal(e)
	}
	defer self.Close()
	imp, e := self.Duplicate(token.Query|token.Impersonate, token.Impersonation, token.LevelImpersonation)
	if e != nil {
		t.Fatal(e)
	}
	defer imp.Close()
	var expired *token.IdentityThread
	if e = token.WithIdentityThread(func(scope *token.IdentityThread) error {
		expired = scope
		for i := 0; i < 3; i++ {
			if e := scope.Impersonate(imp); e != nil {
				return e
			}
			tok, e := token.OpenSelf(0, token.Query)
			if e != nil {
				return e
			}
			tok.Close()
			if e = scope.Revert(); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = expired.Revert(); e != syscall.EPERM {
		t.Fatal("expired identity scope", e)
	}
	sessions, e := token.OpenSessions()
	if e != nil {
		t.Fatal(e)
	}
	defer sessions.Close()
	for {
		_, e := sessions.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	// Exercise both pidfd token opens while the current thread is stable.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fd, _, errno := syscall.Syscall(434, uintptr(os.Getpid()), 0, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	pidfd := os.NewFile(fd, "self-pidfd")
	defer pidfd.Close()
	proc, e := token.OpenProcess(pidfd, token.Query)
	if e != nil {
		t.Fatal(e)
	}
	proc.Close()
	thread, e := token.OpenThread(pidfd, syscall.Gettid(), token.Query)
	if e != nil {
		t.Fatal(e)
	}
	thread.Close()
}
