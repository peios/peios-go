// Package access provides Peios access checks and portable audit contexts.
package access

import (
	"errors"

	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/msgpack"
)

var ErrAuditContext = errors.New("peios/access: invalid audit context")

type Field struct {
	Name  string
	Value any
}

func segment(s string) bool {
	if len(s) == 0 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	dash := false
	for _, c := range s {
		if c == '-' {
			if dash {
				return false
			}
			dash = true
			continue
		}
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
		dash = false
	}
	return !dash
}

// AuditContext encodes ordered scalar fields. An empty field list emits only
// kind. No identity is inferred or inserted by the library.
func AuditContext(kind string, fields []Field) ([]byte, error) {
	if !segment(kind) {
		return nil, ErrAuditContext
	}
	m := msgpack.Map{{Key: "kind", Value: kind}}
	if len(fields) > 0 {
		f := msgpack.Map{}
		seen := map[string]bool{}
		for _, x := range fields {
			if !segment(x.Name) || seen[x.Name] {
				return nil, ErrAuditContext
			}
			seen[x.Name] = true
			switch x.Value.(type) {
			case string, bool, []byte, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
			default:
				return nil, ErrAuditContext
			}
			f = append(f, msgpack.Pair{Key: x.Name, Value: x.Value})
		}
		m = append(m, msgpack.Pair{Key: kind, Value: f})
	}
	b, e := msgpack.Marshal(m)
	if e != nil {
		return nil, e
	}
	if e := ValidateAuditContext(b); e != nil {
		return nil, e
	}
	return b, nil
}
func ValidateAuditContext(b []byte) error {
	if len(b) == 0 || len(b) > uapi.KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN {
		return ErrAuditContext
	}
	if msgpack.Validate(b, 31) != nil {
		return ErrAuditContext
	}
	v, e := msgpack.Unmarshal(b)
	if e != nil {
		return ErrAuditContext
	}
	m, ok := v.(msgpack.Map)
	if !ok || len(m) < 1 || len(m) > 2 {
		return ErrAuditContext
	}
	kind := ""
	for _, p := range m {
		if p.Key == "kind" {
			s, ok := p.Value.(string)
			if !ok || kind != "" || !segment(s) {
				return ErrAuditContext
			}
			kind = s
		}
	}
	if kind == "" {
		return ErrAuditContext
	}
	for _, p := range m {
		if p.Key == "kind" {
			continue
		}
		if p.Key != kind {
			return ErrAuditContext
		}
		fields, ok := p.Value.(msgpack.Map)
		if !ok || len(fields) == 0 {
			return ErrAuditContext
		}
		for _, f := range fields {
			s, ok := f.Key.(string)
			if !ok || !segment(s) {
				return ErrAuditContext
			}
		}
	}
	return nil
}
