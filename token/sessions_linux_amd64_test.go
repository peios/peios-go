package token

import (
	"io"
	"syscall"
	"testing"
)

func TestSessionSnapshotContinuesAfterBadLine(t *testing.T) {
	good := "logon_session_id=4 user_sid=010100000000000512000000 logon_type=5 auth_package= created_at=12"
	r := SessionReader{text: "bad\n" + good + "\n"}
	if _, e := r.Next(); e != syscall.EPROTO {
		t.Fatal(e)
	}
	s, e := r.Next()
	if e != nil || s.ID != 4 || s.User.String() != "S-1-5-18" {
		t.Fatal(s, e)
	}
	if _, e = r.Next(); e != io.EOF {
		t.Fatal(e)
	}
	r.Close()
	if _, e = r.Next(); e != syscall.EBADF {
		t.Fatal(e)
	}
}
