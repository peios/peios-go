package native_test

import (
	"bytes"
	"fmt"
	"github.com/peios/peios-go/file"
	"github.com/peios/peios-go/security"
	"github.com/peios/peios-go/token"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func nativeReferenceText(t *testing.T, mode, arg, want string) {
	t.Helper()
	for _, env := range []string{"PEIOS_C_ORACLE", "PEIOS_RUST_ORACLE"} {
		out, e := exec.Command(os.Getenv(env), mode, arg).CombinedOutput()
		if e != nil || strings.TrimSpace(string(out)) != strings.TrimSpace(want) {
			t.Fatalf("%s %s: Go=%s ref=%s error=%v", env, mode, want, out, e)
		}
	}
}

func TestTokenGUID(t *testing.T) {
	guest(t)
	tok, err := token.OpenSelf(0, token.Query)
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Close()
	guid, err := tok.GUID()
	if err != nil || guid == [16]byte{} {
		t.Fatalf("GUID: %x %v", guid, err)
	}
	raw, err := tok.Query(token.GUIDClass)
	if err != nil || !bytes.Equal(raw, guid[:]) {
		t.Fatalf("raw query: %x %v", raw, err)
	}
	denied, err := token.OpenSelf(0, token.QuerySource)
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	if _, err = denied.GUID(); err != syscall.EACCES {
		t.Fatalf("query without right: %v", err)
	}
	nativeReferenceText(t, "native-guid", "", "ok")
}
func TestSysVDescriptors(t *testing.T) {
	guest(t)
	info := security.InfoOwner | security.InfoGroup | security.InfoDACL
	for index, kind := range []file.SysVKind{file.SysVSharedMemory, file.SysVMessageQueue, file.SysVSemaphore} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			var id uintptr
			var e syscall.Errno
			switch index {
			case 0:
				id, _, e = syscall.Syscall(syscall.SYS_SHMGET, 0, 4096, 01000|0600)
			case 1:
				id, _, e = syscall.Syscall(syscall.SYS_MSGGET, 0, 01000|0600, 0)
			case 2:
				id, _, e = syscall.Syscall(syscall.SYS_SEMGET, 0, 1, 01000|0600)
			}
			if e != 0 {
				t.Fatal(e)
			}
			defer func() {
				switch index {
				case 0:
					syscall.Syscall(syscall.SYS_SHMCTL, id, 0, 0)
				case 1:
					syscall.Syscall(syscall.SYS_MSGCTL, id, 0, 0)
				case 2:
					syscall.Syscall6(syscall.SYS_SEMCTL, id, 0, 0, 0, 0, 0)
				}
			}()
			sd, err := file.GetSysVDescriptor(kind, int(id), info)
			if err != nil {
				t.Fatal(err)
			}
			if err = file.SetSysVDescriptor(kind, int(id), security.InfoDACL, sd); err != nil {
				t.Fatal(err)
			}
			again, err := file.GetSysVDescriptor(kind, int(id), info)
			if err != nil || !bytes.Equal(sd, again) {
				t.Fatal(err)
			}
			nativeReferenceText(t, "native-sysv", fmt.Sprintf("%d|%d", index, id), fmt.Sprintf("%x", sd))
		})
	}
}
func TestMountPolicies(t *testing.T) {
	guest(t)
	path := "/tmp/sdk-policy"
	if e := os.MkdirAll(path, 0700); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(path)
	if e := syscall.Mount("tmpfs", path, "tmpfs", 0, ""); e != nil {
		t.Fatal(e)
	}
	defer syscall.Unmount(path, 0)
	fd, e := syscall.Open(path, 0x200000|syscall.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	d, e := security.ParseSDDL("O:SYG:SYD:(A;;FA;;;SY)")
	if e != nil {
		t.Fatal(e)
	}
	sd, e := d.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []uint32{file.MountDenyMissing, file.MountSynthesizeEphemeral, file.MountSynthesizePersistent} {
		want := file.MountPolicy{Policy: kind}
		if kind == file.MountSynthesizeEphemeral || kind == file.MountSynthesizePersistent {
			want.Template = sd
		}
		if e = file.SetMountPolicy(f, want); e != nil {
			t.Fatalf("policy %d: %v", kind, e)
		}
		got, e := file.GetMountPolicy(f)
		if e != nil || got.Policy != kind || !bytes.Equal(got.Template, want.Template) {
			t.Fatal(got, e)
		}
		nativeReferenceText(t, "native-mount", path, fmt.Sprintf("%d %d %d %x", got.Policy, got.Flags, got.Generation, got.Template))
	}
}
func TestPrimaryInstallation(t *testing.T) {
	guest(t)
	if os.Getenv("PEIOS_INSTALL_CHILD") == "1" {
		tok, e := token.OpenSelf(token.Real, token.Query|token.Duplicate)
		if e != nil {
			t.Fatal(e)
		}
		defer tok.Close()
		sid, e := tok.UserSID()
		if e != nil {
			t.Fatal(e)
		}
		next, e := tok.Duplicate(token.AllAccess, token.Primary, token.LevelImpersonation)
		if e != nil {
			t.Fatal(e)
		}
		defer next.Close()
		if e = next.Install(); e != nil {
			t.Fatal(e)
		}
		installed, e := token.OpenSelf(token.Real, token.Query)
		if e != nil {
			t.Fatal(e)
		}
		defer installed.Close()
		got, e := installed.UserSID()
		if e != nil || got != sid {
			t.Fatal(got, e)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPrimaryInstallation$", "-test.v")
	cmd.Env = append(os.Environ(), "PEIOS_INSTALL_CHILD=1")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("%s: %v", b, e)
	}
}
