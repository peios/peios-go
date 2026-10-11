package access

import (
	"testing"

	"github.com/peios/peios-go/msgpack"
)

func TestAuditValidation(t *testing.T) {
	if _, e := AuditContext("kind", []Field{{Name: "name", Value: "sdk"}}); e == nil {
		t.Fatal("kind field collision")
	}
	for _, name := range []string{"", "Service", "service-", "service--name", "x.y", "9x"} {
		if _, e := AuditContext(name, nil); e == nil {
			t.Fatal(name)
		}
	}
	if _, e := AuditContext("kind", []Field{{"x", 1}, {"x", 2}}); e == nil {
		t.Fatal("duplicate")
	}
	b, e := AuditContext("service", []Field{{Name: "name", Value: "sdk"}})
	if e != nil || ValidateAuditContext(b) != nil {
		t.Fatal(e)
	}
	for _, v := range []any{nil, msgpack.Map{{Key: "kind", Value: "service"}, {Key: "other", Value: msgpack.Map{{Key: "name", Value: "sdk"}}}}, msgpack.Map{{Key: "kind", Value: "service"}, {Key: "service", Value: msgpack.Map{}}}, msgpack.Map{{Key: "kind", Value: "service"}, {Key: "kind", Value: "other"}}} {
		b, e = msgpack.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if ValidateAuditContext(b) == nil {
			t.Fatal(v)
		}
	}
}
func FuzzAudit(f *testing.F) {
	b, _ := AuditContext("service", []Field{{Name: "name", Value: "test"}})
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) { ValidateAuditContext(b) })
}
