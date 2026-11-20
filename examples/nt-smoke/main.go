// Command nt-smoke is a runtime smoke test of the PEI-1745 API: the file
// package's sharing, query, special attributes, locks, rename, delete-pending
// and leases, supplied-subject access checks, and a registry read
// transaction. Run it as SYSTEM on a Peios kernel, in a directory on a
// managed mount; it prints PASS or FAIL per check and a summary line. Build a
// static binary with CGO_ENABLED=0 go build ./examples/nt-smoke.
//
// Usage: nt-smoke [DIRECTORY]   (default /srv/go)
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/peios/peios-go/access"
	"github.com/peios/peios-go/file"
	"github.com/peios/peios-go/registry"
	"github.com/peios/peios-go/security"
)

func main() {
	dir := "/srv/go"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	os.MkdirAll(dir, 0700)
	a, b, c := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")
	os.Remove(b)
	os.WriteFile(a, []byte("hello"), 0600)
	checks, failures := 0, 0
	check := func(ok bool, what string) {
		checks++
		if !ok {
			failures++
			fmt.Println("FAIL", what)
		} else {
			fmt.Println("PASS", what)
		}
	}

	f, _, err := file.Open(a, file.OpenOptions{Access: file.ReadData | file.ReadAttributes | file.WriteAttributes | 0x10000, Disposition: file.OpenExisting, Flags: file.SpecifyShare, Share: file.ShareRead})
	if err != nil {
		panic(err)
	}
	info, err := file.Query(f)
	check(err == nil && info.Share == file.ShareRead && info.Access&0x10000 != 0, "query")
	_, _, err = file.Open(a, file.OpenOptions{Access: file.WriteData, Disposition: file.OpenExisting})
	var oe *file.OpenError
	check(errors.As(err, &oe) && oe.Failure == file.SharingViolation, fmt.Sprintf("sharing violation (%v)", err))

	sa, err := file.GetSpecialAttributes(f)
	check(err == nil && sa == (file.SpecialAttributes{}), "no special attributes")
	at := time.Unix(1000000000, 5)
	check(file.SetCreatedAt(f, at) == nil && file.SetReadOnlyAt(file.CurrentDirectory, a, true, 0) == nil, "set both")
	sa, err = file.GetSpecialAttributesAt(file.CurrentDirectory, a, 0)
	check(err == nil && sa.ReadOnly && sa.CreatedAt.Equal(at), "read-only and Created At")
	ct, err := file.CreationTime(f)
	check(err == nil && ct.Equal(at), "creation time is Created At")
	os.WriteFile(c, []byte("copy"), 0600)
	check(file.SetSpecialAttributesAt(file.CurrentDirectory, c, sa, 0) == nil, "copy to another file")
	got, _ := file.GetSpecialAttributesAt(file.CurrentDirectory, c, 0)
	check(got.ReadOnly && got.CreatedAt.Equal(at), "copied exactly")
	check(file.SetSpecialAttributesAt(file.CurrentDirectory, c, file.SpecialAttributes{}, 0) == nil, "clear the copy")
	ct, err = file.CreationTimeAt(file.CurrentDirectory, c, 0)
	check(err == nil && !ct.Equal(at) && ct.After(time.Unix(1700000000, 0)), "creation time falls back to birth time")
	check(file.SetReadOnly(f, false) == nil, "read-only cleared")

	check(file.Lock(f, file.LockExclusive, 0, 4, true, 0) == nil, "lock")
	check(file.Unlock(f, 0, 4) == nil, "unlock")
	check(file.Unlock(f, 0, 4) != nil, "unlock twice fails")
	check(file.Rename(f, file.CurrentDirectory, b, 0) == nil, "rename")
	_, eb := os.Stat(b)
	_, ea := os.Stat(a)
	check(eb == nil && ea != nil, "renamed")
	check(file.SetDeleteDisposition(f, file.DeleteWhenClosed) == nil, "delete-pending")
	f.Close()
	_, eb = os.Stat(b)
	check(eb != nil, "last close removes it")

	m, err := file.NewLeaseManager(2*time.Second, true)
	check(err == nil, "lease manager")
	key := file.LeaseKey{5}
	g, _, err := file.Open(c, file.OpenOptions{Access: file.ReadData, Disposition: file.OpenExisting, LeaseManager: m, LeaseKey: key})
	check(err == nil, "open under a lease key")
	st, err := file.RequestLease(g, m, key, file.LeaseRead|file.LeaseHandle)
	check(err == nil && st == file.LeaseRead|file.LeaseHandle, "lease granted")
	_, err = m.ReadBreaks(4)
	check(err != nil, "no break pending")
	g.Close()
	m.Close()
	os.Remove(c)
	// Supplied-subject checks: no token, facts only.
	sd := func(sddl string) []byte {
		d, e := security.ParseSDDL(sddl)
		if e != nil {
			panic(e)
		}
		b, e := d.MarshalBinary()
		if e != nil {
			panic(e)
		}
		return b
	}
	user, _ := security.ParseSID("S-1-5-21-1-2-3-1000")
	admins, _ := security.ParseSID("S-1-5-32-544")
	req := func(text string) access.Request {
		return access.Request{Descriptor: sd(text), Desired: 0x1, Mapping: file.GenericMapping()}
	}
	byGroup := req("O:SYG:SYD:(A;;FA;;;BA)")
	r, e := access.CheckSubject(byGroup, access.SuppliedSubject{User: user}, 0)
	check(e == nil && r.Decision == access.SubjectMissingContext && r.Missing&access.MissingGroups != 0, fmt.Sprintf("unknown groups: missing context (%+v %v)", r, e))
	r, e = access.CheckSubject(byGroup, access.SuppliedSubject{User: user, Groups: []access.SubjectGroup{{SID: admins, Attributes: 0x7}}}, 0)
	check(e == nil && r.Decision == access.SubjectGranted && r.Granted&0x1 != 0, fmt.Sprintf("member of the group: granted (%+v %v)", r, e))
	r, e = access.CheckSubject(byGroup, access.SuppliedSubject{User: user, Groups: []access.SubjectGroup{}}, 0)
	check(e == nil && r.Decision == access.SubjectDenied, fmt.Sprintf("known no groups: denied (%+v %v)", r, e))
	r, e = access.CheckSubjectEx(req("O:SYG:SYD:(A;;FA;;;S-1-5-21-1-2-3-1000)"), access.SuppliedSubject{User: user, Groups: []access.SubjectGroup{}}, 0, access.SubjectNoAudit)
	check(e == nil && r.Decision == access.SubjectGranted, fmt.Sprintf("the user's own ACE: granted (%+v %v)", r, e))
	byClaim := req(`O:SYG:SYD:(XA;;FA;;;S-1-5-21-1-2-3-1000;(@User.dept == "eng"))`)
	eng := &access.SuppliedClaims{Values: []security.Claim{{Name: "dept", Values: []any{"eng"}}}}
	r, e = access.CheckSubject(byClaim, access.SuppliedSubject{User: user, Groups: []access.SubjectGroup{}, UserClaims: eng}, 0)
	check(e == nil && r.Decision == access.SubjectGranted, fmt.Sprintf("claim matches: granted (%+v %v)", r, e))
	sales := &access.SuppliedClaims{Values: []security.Claim{{Name: "Dept", Values: []any{"sales"}}}}
	r, e = access.CheckSubject(byClaim, access.SuppliedSubject{User: user, Groups: []access.SubjectGroup{}, UserClaims: sales}, 0)
	check(e == nil && r.Decision == access.SubjectDenied, fmt.Sprintf("claim differs: denied (%+v %v)", r, e))
	r, e = access.CheckSubject(byClaim, access.SuppliedSubject{User: user, Groups: []access.SubjectGroup{}}, 0)
	check(e == nil && r.Decision == access.SubjectMissingContext && r.Missing&access.MissingUserClaims != 0, fmt.Sprintf("claims unknown: missing context (%+v %v)", r, e))
	r, e = access.CheckSubject(byClaim, access.SuppliedSubject{User: user, Groups: []access.SubjectGroup{}, UserClaims: &access.SuppliedClaims{Absent: []string{"dept"}}}, 0)
	check(e == nil && r.Decision == access.SubjectDenied, fmt.Sprintf("claim known absent: denied (%+v %v)", r, e))
	_, e = access.CheckSubject(byGroup, access.SuppliedSubject{User: user, Groups: []access.SubjectGroup{{SID: admins}, {SID: admins}}}, 0)
	check(e != nil, "duplicate groups are refused")

	// Registry read transaction.
	tx, e := registry.BeginRead()
	check(e == nil, "begin a read transaction")
	if e == nil {
		k, e := registry.OpenTransacted("Machine", registry.Read, 0, tx)
		check(e == nil, fmt.Sprintf("open within it (%v)", e))
		if e == nil {
			info, e := k.InfoTransacted(tx)
			check(e == nil && info.Subkeys > 0, fmt.Sprintf("key info within it (%+v %v)", info, e))
			d, e := k.GetDescriptorTransacted(security.InfoOwner|security.InfoDACL, tx)
			check(e == nil && len(d) > 0, fmt.Sprintf("descriptor within it (%v)", e))
			k.Close()
		}
		tx.Close()
	}
	fmt.Printf("GOSMOKE %d/%d passed\n", checks-failures, checks)
}
