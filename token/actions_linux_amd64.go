package token

import (
	"encoding/binary"
	"os"
	"syscall"
	"unsafe"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/security"
)

// TakeFile transfers ownership of an existing token file to a Token. The caller
// must no longer close or use f. The kernel validates its type on operations.
func TakeFile(f *os.File) *Token { return &Token{f: f} }
func (s Spec) Create() (*Token, error) {
	b, e := s.MarshalBinary()
	if e != nil {
		return nil, e
	}
	return Create(b)
}

type PrivilegeAdjustment struct{ LUID, Attributes uint32 }
type GroupAdjustment struct {
	Index  uint32
	Enable bool
}

func (t *Token) AdjustPrivileges(entries []PrivilegeAdjustment) (previous uint64, e error) {
	if uint64(len(entries)) > 0xffffffff {
		return 0, syscall.EINVAL
	}
	e = native.WithFD(t, func(fd int) error {
		var p native.Pins
		defer p.Unpin()
		a := uapi.Kacs_adjust_privs_args{Count: uint32(len(entries))}
		if len(entries) > 0 {
			a.Data_ptr = uint64(p.Pointer(unsafe.Pointer(&entries[0])))
		}
		err := native.Ioctl(fd, uapi.KACS_IOC_ADJUST_PRIVS, unsafe.Pointer(&a))
		previous = a.Previous_enabled
		return err
	})
	return
}
func (t *Token) ResetPrivileges() error {
	_, e := t.AdjustPrivileges([]PrivilegeAdjustment{{Attributes: uapi.KACS_PRIVILEGE_RESET_ALL_DEFAULTS}})
	return e
}
func (t *Token) AdjustGroups(entries []GroupAdjustment) (previous [16]uint64, e error) {
	if uint64(len(entries)) > 0xffffffff {
		return previous, syscall.EINVAL
	}
	e = native.WithFD(t, func(fd int) error {
		var p native.Pins
		defer p.Unpin()
		v := make([]uapi.Kacs_group_entry, len(entries))
		for i, x := range entries {
			v[i].Index = x.Index
			if x.Enable {
				v[i].Enable = 1
			}
		}
		a := uapi.Kacs_adjust_groups_args{Count: uint32(len(v))}
		if len(v) > 0 {
			a.Data_ptr = uint64(p.Pointer(unsafe.Pointer(&v[0])))
		}
		err := native.Ioctl(fd, uapi.KACS_IOC_ADJUST_GROUPS, unsafe.Pointer(&a))
		previous = a.Previous_state
		return err
	})
	return
}
func (t *Token) ResetGroups() error {
	_, e := t.AdjustGroups([]GroupAdjustment{{Index: 0xffffffff}})
	return e
}

type Restriction struct {
	DeletePrivileges uint64
	DenyGroupIndices []uint32
	SIDs             []security.SID
	Flags            uint32
}

func (t *Token) Restrict(r Restriction) (out *Token, e error) {
	if uint64(len(r.DenyGroupIndices))*4+uint64(len(r.SIDs))*68 > 0xffffffff {
		return nil, syscall.EINVAL
	}
	var b []byte
	for _, i := range r.DenyGroupIndices {
		b = binary.LittleEndian.AppendUint32(b, i)
	}
	for _, sid := range r.SIDs {
		if !sid.Valid() {
			return nil, syscall.EINVAL
		}
		b = append(b, sid.Bytes()...)
	}
	e = native.WithFD(t, func(fd int) error {
		var p native.Pins
		defer p.Unpin()
		a := uapi.Kacs_restrict_args{Privs_to_delete: r.DeletePrivileges, Num_deny_indices: uint32(len(r.DenyGroupIndices)), Num_restrict_sids: uint32(len(r.SIDs)), Data_len: uint32(len(b)), Flags: r.Flags, Data_ptr: uint64(p.Bytes(b)), Result_fd: -1}
		if err := native.Ioctl(fd, uapi.KACS_IOC_RESTRICT, unsafe.Pointer(&a)); err != nil {
			return err
		}
		if a.Result_fd < 0 {
			return syscall.EPROTO
		}
		out = TakeFile(native.File(uintptr(a.Result_fd), "peios.restricted-token"))
		return nil
	})
	return
}

// AdjustDefaults leaves the DACL unchanged for nil, clears it for a non-nil
// empty slice, and replaces it otherwise. Index 0xffff means unchanged.
func (t *Token) AdjustDefaults(dacl []byte, owner, group uint16) error {
	return native.WithFD(t, func(fd int) error {
		if uint64(len(dacl)) > 0xffffffff {
			return syscall.EINVAL
		}
		var p native.Pins
		defer p.Unpin()
		ptr := p.Bytes(dacl)
		if dacl != nil && len(dacl) == 0 {
			dummy := byte(0)
			ptr = p.Pointer(unsafe.Pointer(&dummy))
		}
		a := uapi.Kacs_adjust_default_args{Dacl_ptr: uint64(ptr), Dacl_len: uint32(len(dacl)), Owner_index: owner, Group_index: group}
		return native.Ioctl(fd, uapi.KACS_IOC_ADJUST_DEFAULT, unsafe.Pointer(&a))
	})
}
func Link(elevated, filtered *Token, session uint64) error {
	return native.WithFD(elevated, func(ef int) error {
		return native.WithFD(filtered, func(ff int) error {
			a := uapi.Kacs_link_tokens_args{Elevated_fd: int32(ef), Filtered_fd: int32(ff), Logon_session_id: session}
			return native.Ioctl(ef, uapi.KACS_IOC_LINK_TOKENS, unsafe.Pointer(&a))
		})
	})
}
func (t *Token) SID(class Class) (security.SID, error) {
	b, e := t.Query(class)
	if e != nil {
		return security.SID{}, e
	}
	return security.SIDFromBytes(b)
}
func (t *Token) Integrity() (uint32, error) {
	s, e := t.SID(IntegrityLevel)
	if e != nil {
		return 0, e
	}
	b := s.Bytes()
	if len(b) != 12 || b[7] != 16 {
		return 0, syscall.EPROTO
	}
	return binary.LittleEndian.Uint32(b[8:]), nil
}
func (t *Token) Type() (Type, error) { n, e := t.Uint32(TokenType); return Type(n), e }
func (t *Token) ImpersonationLevel() (ImpersonationLevel, error) {
	n, e := t.Uint32(ImpersonationLevelClass)
	return ImpersonationLevel(n), e
}
func (t *Token) InteractivityScope() (uint32, error) { return t.Uint32(InteractivityScope) }
func GenericMapping() security.GenericMapping {
	return security.GenericMapping{Read: 0x20008, Write: 0x400e0, Execute: 0x4, All: 0xf01ff}
}

func (t *Token) GroupList(class Class) ([]Group, error) {
	b, e := t.Query(class)
	if e != nil {
		return nil, e
	}
	return ParseGroups(b)
}
