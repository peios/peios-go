package token

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/security"
)

type SessionSpec struct {
	LogonType   uint8
	AuthPackage string
	User        security.SID
}

func (s SessionSpec) Create() (uint64, error) {
	sid := s.User.Bytes()
	if !s.User.Valid() || !utf8.ValidString(s.AuthPackage) || strings.ContainsRune(s.AuthPackage, 0) || len(s.AuthPackage)+len(sid)+7 > uapi.KACS_LOGON_SESSION_SPEC_MAX_BYTES {
		return 0, syscall.EINVAL
	}
	b := binary.LittleEndian.AppendUint16([]byte{s.LogonType}, uint16(len(s.AuthPackage)))
	b = append(b, s.AuthPackage...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(sid)))
	b = append(b, sid...)
	var p native.Pins
	defer p.Unpin()
	n, e := native.Call(uapi.SYS_KACS_CREATE_LOGON_SESSION, p.Bytes(b), uintptr(len(b)))
	return uint64(n), e
}
func DestroyEmptySession(id uint64) error {
	_, e := native.Call(uapi.SYS_KACS_DESTROY_EMPTY_LOGON_SESSION, uintptr(id))
	return e
}

type Session struct {
	ID, CreatedAt uint64
	LogonType     uint32
	User          security.SID
	AuthPackage   string
}

func ListSessions() ([]Session, error) {
	b, e := os.ReadFile("/sys/kernel/security/kacs/sessions")
	if e != nil {
		return nil, e
	}
	return parseSessions(string(b))
}
func parseSessions(text string) ([]Session, error) {
	var out []Session
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		fields := map[string]string{}
		for _, f := range strings.Fields(line) {
			k, v, ok := strings.Cut(f, "=")
			if ok {
				fields[k] = v
			}
		}
		id, e1 := strconv.ParseUint(fields["logon_session_id"], 10, 64)
		created, e2 := strconv.ParseUint(fields["created_at"], 10, 64)
		kind, e3 := strconv.ParseUint(fields["logon_type"], 10, 32)
		sid, e4 := hex.DecodeString(fields["user_sid"])
		user, e5 := security.SIDFromBytes(sid)
		pkg, e6 := hex.DecodeString(fields["auth_package"])
		_, present := fields["auth_package"]
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || !present {
			return nil, syscall.EPROTO
		}
		out = append(out, Session{id, created, uint32(kind), user, string(pkg)})
	}
	return out, nil
}

// SessionReader walks the snapshot taken by OpenSessions. Next returns owned
// values and io.EOF at the end. A malformed line returns EPROTO but is consumed,
// so the next call can continue. It holds no fd after OpenSessions returns.
// Calls must be serialized by the owner.
type SessionReader struct {
	text   string
	closed bool
}

func OpenSessions() (*SessionReader, error) {
	b, e := os.ReadFile("/sys/kernel/security/kacs/sessions")
	if e != nil {
		return nil, e
	}
	return &SessionReader{text: string(b)}, nil
}
func (r *SessionReader) Next() (Session, error) {
	if r == nil || r.closed {
		return Session{}, syscall.EBADF
	}
	for r.text != "" {
		line, rest, _ := strings.Cut(r.text, "\n")
		r.text = rest
		if line == "" {
			continue
		}
		values, e := parseSessions(line)
		if e != nil {
			return Session{}, e
		}
		return values[0], nil
	}
	return Session{}, io.EOF
}
func (r *SessionReader) Close() error {
	if r == nil || r.closed {
		return syscall.EBADF
	}
	r.text = ""
	r.closed = true
	return nil
}
