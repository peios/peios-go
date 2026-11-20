package file

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
)

// ShareAccess is the access other opens may have while an open lasts. It is
// read only with SpecifyShare in OpenOptions.Flags; without it an open shares
// read, write and delete, as a plain open(2) does.
type ShareAccess uint32

const (
	ShareRead   ShareAccess = uapi.KACS_FILE_SHARE_READ
	ShareWrite  ShareAccess = uapi.KACS_FILE_SHARE_WRITE
	ShareDelete ShareAccess = uapi.KACS_FILE_SHARE_DELETE

	// SpecifyShare makes OpenOptions.Share the open's sharing.
	SpecifyShare Flags = uapi.KACS_OPEN_SHARE_ACCESS
	// PinAncestors keeps the directories above the file from being renamed
	// or removed while the open lasts. It needs SeLockParentagePrivilege.
	PinAncestors Flags = uapi.KACS_OPEN_PIN_ANCESTORS
)

// Failure names why a native open failed, where its errno alone cannot say.
type Failure uint32

const (
	SharingViolation Failure = uapi.KACS_STATUS_SHARING_VIOLATION
	DeletePending    Failure = uapi.KACS_STATUS_DELETE_PENDING
	CannotDelete     Failure = uapi.KACS_STATUS_CANNOT_DELETE
)

// OpenError is the error of a native open that reported a Failure. It wraps
// the errno, so errors.Is(err, syscall.EBUSY) still holds.
type OpenError struct {
	Errno   syscall.Errno
	Failure Failure
}

func (e *OpenError) Error() string {
	name := map[Failure]string{SharingViolation: "sharing violation", DeletePending: "delete pending", CannotDelete: "cannot delete"}[e.Failure]
	return fmt.Sprintf("%v (%s)", e.Errno, name)
}
func (e *OpenError) Unwrap() error { return e.Errno }

// openError attaches the Failure the kernel reported, if any.
func openError(e error, status uint32) error {
	var errno syscall.Errno
	switch Failure(status) {
	case SharingViolation, DeletePending, CannotDelete:
		if errors.As(e, &errno) {
			return &OpenError{Errno: errno, Failure: Failure(status)}
		}
	}
	return e
}

// OpenInfo is what an open was granted, read back with Query.
type OpenInfo struct {
	Access          Access
	Share           ShareAccess
	DeletePending   bool
	DeleteOnClose   bool
	AncestorsPinned bool
}

// Query reads back what f's open was granted: its access, its sharing and
// its file's delete state.
func Query(f syscall.Conn) (out OpenInfo, e error) {
	e = native.WithFD(f, func(fd int) error {
		var info uapi.Kacs_open_info
		var p native.Pins
		defer p.Unpin()
		if _, err := native.Call(uapi.SYS_KACS_QUERY_OPEN, uintptr(fd), p.Pointer(unsafe.Pointer(&info)), unsafe.Sizeof(info)); err != nil {
			return err
		}
		out = OpenInfo{
			Access:          Access(info.Granted_access),
			Share:           ShareAccess(info.Share_access),
			DeletePending:   info.Flags&uapi.KACS_OPEN_INFO_DELETE_PENDING != 0,
			DeleteOnClose:   info.Flags&uapi.KACS_OPEN_INFO_DELETE_ON_CLOSE != 0,
			AncestorsPinned: info.Flags&uapi.KACS_OPEN_INFO_ANCESTORS_PINNED != 0,
		}
		return nil
	})
	return
}

// DeleteDisposition is a delete disposition, as NT's
// FILE_DISPOSITION_INFORMATION_EX.
type DeleteDisposition uint32

const (
	// DeleteWhenClosed marks the file to be deleted when its last open
	// closes; without it, SetDeleteDisposition clears the mark.
	DeleteWhenClosed DeleteDisposition = uapi.KACS_DISPOSITION_DELETE
	// DeletePOSIX, with DeleteWhenClosed, removes the name at once.
	DeletePOSIX DeleteDisposition = uapi.KACS_DISPOSITION_POSIX_SEMANTICS
	// DeleteOnThisClose sets or clears this open's delete-on-close instead.
	DeleteOnThisClose DeleteDisposition = uapi.KACS_DISPOSITION_ON_CLOSE
	// DeleteIgnoreReadOnly deletes a read-only file; it needs WriteAttributes.
	DeleteIgnoreReadOnly DeleteDisposition = uapi.KACS_DISPOSITION_IGNORE_READONLY
)

// SetDeleteDisposition sets or clears f's file's delete disposition. The open
// needs DELETE.
func SetDeleteDisposition(f syscall.Conn, d DeleteDisposition) error {
	return native.WithFD(f, func(fd int) error {
		_, e := native.Call(uapi.SYS_KACS_SET_DISPOSITION, uintptr(fd), uintptr(d))
		return e
	})
}

// RenameFlags are rename flags, as NT's FILE_RENAME_INFORMATION_EX.
type RenameFlags uint32

const (
	RenameReplace        RenameFlags = uapi.KACS_RENAME_REPLACE_IF_EXISTS
	RenamePOSIX          RenameFlags = uapi.KACS_RENAME_POSIX_SEMANTICS
	RenameIgnoreReadOnly RenameFlags = uapi.KACS_RENAME_IGNORE_READONLY
)

// Rename moves the link f's open names to path, relative to dirfd
// (CurrentDirectory for the cwd). The open needs DELETE.
func Rename(f syscall.Conn, dirfd int, path string, flags RenameFlags) error {
	return native.WithFD(f, func(fd int) error {
		var p native.Pins
		defer p.Unpin()
		s, e := p.String(path)
		if e != nil {
			return e
		}
		_, e = native.Call(uapi.SYS_KACS_RENAME, uintptr(fd), uintptr(dirfd), s, uintptr(flags))
		return e
	})
}

// LockKind is the kind of an NT byte-range lock.
type LockKind uint32

const (
	// LockShared keeps everyone, this open included, from writing the range.
	LockShared LockKind = uapi.KACS_LOCK_SHARED
	// LockExclusive keeps every other open from reading or writing it.
	LockExclusive LockKind = uapi.KACS_LOCK_EXCLUSIVE
)

func lockCall(f syscall.Conn, args uapi.Kacs_lock_args) error {
	return native.WithFD(f, func(fd int) error {
		var p native.Pins
		defer p.Unpin()
		_, e := native.Call(uapi.SYS_KACS_LOCK, uintptr(fd), p.Pointer(unsafe.Pointer(&args)), unsafe.Sizeof(args))
		return e
	})
}

// Lock takes an NT byte-range lock over length bytes from offset. A
// conflicting lock waits unless failImmediately, when it fails with EAGAIN;
// give a waiting lock a cookie so that another goroutine can CancelLock it.
func Lock(f syscall.Conn, kind LockKind, offset, length uint64, failImmediately bool, cookie uint64) error {
	args := uapi.Kacs_lock_args{Offset: offset, Length: length, Op: uint32(kind), Cookie: cookie}
	if failImmediately {
		args.Flags = uapi.KACS_LOCK_FAIL_IMMEDIATELY
	}
	return lockCall(f, args)
}

// Unlock releases the lock f's open holds over exactly length bytes from
// offset.
func Unlock(f syscall.Conn, offset, length uint64) error {
	return lockCall(f, uapi.Kacs_lock_args{Offset: offset, Length: length, Op: uapi.KACS_LOCK_UNLOCK})
}

// CancelLock cancels f's open's waiting lock request named by cookie.
func CancelLock(f syscall.Conn, cookie uint64) error {
	return lockCall(f, uapi.Kacs_lock_args{Op: uapi.KACS_LOCK_CANCEL, Cookie: cookie})
}

// LeaseKey names a lease holder to its LeaseManager.
type LeaseKey [16]byte

// LeaseState is a lease's caching state.
type LeaseState uint32

const (
	LeaseRead   LeaseState = uapi.KACS_LEASE_READ
	LeaseHandle LeaseState = uapi.KACS_LEASE_HANDLE
	LeaseWrite  LeaseState = uapi.KACS_LEASE_WRITE
)

// LeaseManager receives the break notices for the leases held under it. Its
// File is pollable.
type LeaseManager struct{ *os.File }

// NewLeaseManager creates a lease manager. breakTimeout bounds how long a
// break waits for acknowledgement before the kernel completes it (zero for the
// default of 35 seconds); nonblocking makes ReadBreaks fail with EAGAIN rather
// than wait.
func NewLeaseManager(breakTimeout time.Duration, nonblocking bool) (*LeaseManager, error) {
	flags := uintptr(uapi.KACS_LEASE_MANAGER_CLOEXEC)
	if nonblocking {
		flags |= uapi.KACS_LEASE_MANAGER_NONBLOCK
	}
	ms := breakTimeout.Milliseconds()
	if ms > 0xffffffff {
		ms = 0xffffffff
	}
	fd, e := native.Call(uapi.SYS_KACS_CREATE_LEASE_MANAGER, flags, uintptr(ms))
	if e != nil {
		return nil, e
	}
	return &LeaseManager{native.File(fd, "lease-manager")}, nil
}

// LeaseBreak is a break notice read from a LeaseManager.
type LeaseBreak struct {
	Key      LeaseKey
	Dev, Ino uint64
	Current  LeaseState
	New      LeaseState
	// Reason is the KACS_LEASE_BREAK_* operation that broke the lease.
	Reason uint32
	// Epoch counts the lease's breaks, so a stale acknowledgement can be told
	// apart.
	Epoch uint32
}

// ReadBreaks reads up to max pending break notices.
func (m *LeaseManager) ReadBreaks(max int) (out []LeaseBreak, e error) {
	if max < 1 {
		return nil, syscall.EINVAL
	}
	raw := make([]uapi.Kacs_lease_break, max)
	e = native.WithFD(m.File, func(fd int) error {
		var p native.Pins
		defer p.Unpin()
		size := unsafe.Sizeof(raw[0])
		n, err := native.Call(syscall.SYS_READ, uintptr(fd), p.Pointer(unsafe.Pointer(&raw[0])), uintptr(max)*size)
		if err != nil {
			return err
		}
		for _, b := range raw[:n/size] {
			out = append(out, LeaseBreak{Key: b.Lease_key, Dev: b.Dev, Ino: b.Ino, Current: LeaseState(b.Current_state), New: LeaseState(b.New_state), Reason: b.Reason, Epoch: b.Epoch})
		}
		return nil
	})
	return
}

func leaseCall(f syscall.Conn, m *LeaseManager, key LeaseKey, state LeaseState, flags uint32) (granted LeaseState, e error) {
	if m == nil {
		return 0, syscall.EINVAL
	}
	e = native.WithFD(m.File, func(mfd int) error {
		return native.WithFD(f, func(fd int) error {
			args := uapi.Kacs_lease_args{Lease_key: key, State: uint32(state), Flags: flags}
			var p native.Pins
			defer p.Unpin()
			if _, err := native.Call(uapi.SYS_KACS_LEASE, uintptr(fd), uintptr(mfd), p.Pointer(unsafe.Pointer(&args)), unsafe.Sizeof(args)); err != nil {
				return err
			}
			granted = LeaseState(args.State)
			return nil
		})
	})
	return
}

// RequestLease requests a lease on f's file under m and key, returning the
// state granted, which may be less than state.
func RequestLease(f syscall.Conn, m *LeaseManager, key LeaseKey, state LeaseState) (LeaseState, error) {
	return leaseCall(f, m, key, state, 0)
}

// AcknowledgeLeaseBreak acknowledges a break of the lease held under m and
// key, settling on state, which may be no more than the break's new state.
func AcknowledgeLeaseBreak(f syscall.Conn, m *LeaseManager, key LeaseKey, state LeaseState) (LeaseState, error) {
	return leaseCall(f, m, key, state, uapi.KACS_LEASE_ACKNOWLEDGE)
}

// SpecialAttributes are a file's read-only flag and its settable Created At.
// A zero CreatedAt means Created At is unset.
type SpecialAttributes struct {
	ReadOnly  bool
	CreatedAt time.Time
}

// The *xattrat syscalls, which the generated tables predate.
const (
	sysSetxattrat = 463
	sysGetxattrat = 464
	sattrName     = "security.peios.sattr"
)

type xattrArgs struct {
	Value uint64
	Size  uint32
	Flags uint32
}

func getSattr(dirfd int, path string, flags Flags) (uapi.Kacs_sattr, error) {
	var v uapi.Kacs_sattr
	var p native.Pins
	defer p.Unpin()
	s, e := p.String(path)
	if e != nil {
		return v, e
	}
	name, e := p.String(sattrName)
	if e != nil {
		return v, e
	}
	args := xattrArgs{Value: uint64(p.Pointer(unsafe.Pointer(&v))), Size: uint32(unsafe.Sizeof(v))}
	n, e := native.Call(sysGetxattrat, uintptr(dirfd), s, uintptr(flags), name, p.Pointer(unsafe.Pointer(&args)), unsafe.Sizeof(args))
	if errors.Is(e, syscall.ENODATA) {
		// A file storing none: not read-only, no Created At.
		return uapi.Kacs_sattr{Version: uapi.KACS_SATTR_VERSION, Valid: uapi.KACS_SATTR_VALID_ATTRIBUTES | uapi.KACS_SATTR_VALID_CREATED_AT}, nil
	}
	if e == nil && n != unsafe.Sizeof(v) {
		e = syscall.EIO
	}
	return v, e
}

// setSattr writes the fields valid names. Created At is set exactly when
// a.CreatedAt is not zero; the kernel takes that as a time with no flag and an
// unset as KACS_SATTR_CREATED_AT_CLEAR.
func setSattr(dirfd int, path string, flags Flags, a SpecialAttributes, valid uint32) error {
	v := uapi.Kacs_sattr{Version: uapi.KACS_SATTR_VERSION, Valid: valid}
	if a.ReadOnly {
		v.Attributes = uapi.KACS_SATTR_READONLY
	}
	if valid&uapi.KACS_SATTR_VALID_CREATED_AT != 0 {
		if a.CreatedAt.IsZero() {
			v.Flags = uapi.KACS_SATTR_CREATED_AT_CLEAR
		} else {
			v.Created_at_sec = a.CreatedAt.Unix()
			v.Created_at_nsec = uint32(a.CreatedAt.Nanosecond())
		}
	}
	var p native.Pins
	defer p.Unpin()
	s, e := p.String(path)
	if e != nil {
		return e
	}
	name, e := p.String(sattrName)
	if e != nil {
		return e
	}
	args := xattrArgs{Value: uint64(p.Pointer(unsafe.Pointer(&v))), Size: uint32(unsafe.Sizeof(v))}
	_, e = native.Call(sysSetxattrat, uintptr(dirfd), s, uintptr(flags), name, p.Pointer(unsafe.Pointer(&args)), unsafe.Sizeof(args))
	return e
}

func fromSattr(v uapi.Kacs_sattr) SpecialAttributes {
	a := SpecialAttributes{ReadOnly: v.Attributes&uapi.KACS_SATTR_READONLY != 0}
	if v.Flags&uapi.KACS_SATTR_CREATED_AT_SET != 0 {
		a.CreatedAt = time.Unix(v.Created_at_sec, int64(v.Created_at_nsec))
	}
	return a
}

const validAll = uapi.KACS_SATTR_VALID_ATTRIBUTES | uapi.KACS_SATTR_VALID_CREATED_AT

// GetSpecialAttributesAt reads a file's special attributes by path. flags
// accepts NoFollow.
func GetSpecialAttributesAt(dirfd int, path string, flags Flags) (SpecialAttributes, error) {
	v, e := getSattr(dirfd, path, flags)
	return fromSattr(v), e
}

// GetSpecialAttributes reads the special attributes of f's file.
func GetSpecialAttributes(f syscall.Conn) (a SpecialAttributes, e error) {
	e = native.WithFD(f, func(fd int) error { var err error; a, err = GetSpecialAttributesAt(fd, "", EmptyPath); return err })
	return
}

// SetSpecialAttributesAt sets both special attributes of a file by path, as
// when copying them from another file.
func SetSpecialAttributesAt(dirfd int, path string, a SpecialAttributes, flags Flags) error {
	return setSattr(dirfd, path, flags, a, validAll)
}

// SetSpecialAttributes sets both special attributes of f's file.
func SetSpecialAttributes(f syscall.Conn, a SpecialAttributes) error {
	return native.WithFD(f, func(fd int) error { return setSattr(fd, "", EmptyPath, a, validAll) })
}

// SetReadOnlyAt makes a file read-only, or not, by path, leaving Created At
// alone.
func SetReadOnlyAt(dirfd int, path string, readOnly bool, flags Flags) error {
	return setSattr(dirfd, path, flags, SpecialAttributes{ReadOnly: readOnly}, uapi.KACS_SATTR_VALID_ATTRIBUTES)
}

// SetReadOnly makes f's file read-only, or not, leaving Created At alone.
func SetReadOnly(f syscall.Conn, readOnly bool) error {
	return native.WithFD(f, func(fd int) error { return SetReadOnlyAt(fd, "", readOnly, EmptyPath) })
}

// SetCreatedAtAt sets a file's Created At by path, or unsets it with a zero
// time, leaving read-only alone.
func SetCreatedAtAt(dirfd int, path string, t time.Time, flags Flags) error {
	return setSattr(dirfd, path, flags, SpecialAttributes{CreatedAt: t}, uapi.KACS_SATTR_VALID_CREATED_AT)
}

// SetCreatedAt sets the Created At of f's file, or unsets it with a zero time.
func SetCreatedAt(f syscall.Conn, t time.Time) error {
	return native.WithFD(f, func(fd int) error { return SetCreatedAtAt(fd, "", t, EmptyPath) })
}

// statx's mask and birth-time fields in the kernel's 256-byte struct statx.
const (
	statxBtime        = 0x800
	statxBtimeSecOff  = 80
	statxBtimeNsecOff = 88
	sysStatx          = 332
)

// CreationTimeAt is a file's creation date by path: its Created At if set,
// else its birth time. It fails with ENODATA if the file has neither.
func CreationTimeAt(dirfd int, path string, flags Flags) (time.Time, error) {
	a, e := GetSpecialAttributesAt(dirfd, path, flags)
	if e != nil {
		return time.Time{}, e
	}
	if !a.CreatedAt.IsZero() {
		return a.CreatedAt, nil
	}
	var buf [256]byte
	var p native.Pins
	defer p.Unpin()
	s, e := p.String(path)
	if e != nil {
		return time.Time{}, e
	}
	if _, e = native.Call(sysStatx, uintptr(dirfd), s, uintptr(flags), statxBtime, p.Pointer(unsafe.Pointer(&buf))); e != nil {
		return time.Time{}, e
	}
	if *(*uint32)(unsafe.Pointer(&buf[0]))&statxBtime == 0 {
		return time.Time{}, syscall.ENODATA
	}
	sec := *(*int64)(unsafe.Pointer(&buf[statxBtimeSecOff]))
	nsec := *(*uint32)(unsafe.Pointer(&buf[statxBtimeNsecOff]))
	return time.Unix(sec, int64(nsec)), nil
}

// CreationTime is the creation date of f's file.
func CreationTime(f syscall.Conn) (t time.Time, e error) {
	e = native.WithFD(f, func(fd int) error { var err error; t, err = CreationTimeAt(fd, "", EmptyPath); return err })
	return
}
