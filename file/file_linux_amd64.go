// Package file opens Peios file objects and reads and writes their descriptors.
// Native operations require Linux/amd64 with the Peios kernel ABI.
package file

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/security"
)

type Access = security.AccessMask
type Disposition uint32
type Options uint32
type Flags uint32
type Status uint32

const (
	ReadData          Access      = uapi.KACS_FILE_READ_DATA
	ListDirectory     Access      = uapi.KACS_FILE_READ_DATA
	WriteData         Access      = uapi.KACS_FILE_WRITE_DATA
	AppendData        Access      = uapi.KACS_FILE_APPEND_DATA
	Execute           Access      = uapi.KACS_FILE_EXECUTE
	Traverse          Access      = uapi.KACS_FILE_EXECUTE
	ReadAttributes    Access      = uapi.KACS_FILE_READ_ATTRIBUTES
	WriteAttributes   Access      = uapi.KACS_FILE_WRITE_ATTRIBUTES
	ReadEA            Access      = uapi.KACS_FILE_READ_EA
	WriteEA           Access      = uapi.KACS_FILE_WRITE_EA
	DeleteChild       Access      = uapi.KACS_FILE_DELETE_CHILD
	OpenExisting      Disposition = uapi.KACS_DISPOSITION_OPEN
	CreateNew         Disposition = uapi.KACS_DISPOSITION_CREATE
	OpenOrCreate      Disposition = uapi.KACS_DISPOSITION_OPEN_IF
	Overwrite         Disposition = uapi.KACS_DISPOSITION_OVERWRITE
	OverwriteOrCreate Disposition = uapi.KACS_DISPOSITION_OVERWRITE_IF
	Supersede         Disposition = uapi.KACS_DISPOSITION_SUPERSEDE
	Directory         Options     = uapi.KACS_CREATE_OPT_DIRECTORY
	DeleteOnClose     Options     = uapi.KACS_CREATE_OPT_DELETE_ON_CLOSE
	NoFollow          Flags       = 0x100
	EmptyPath         Flags       = 0x1000
	Opened            Status      = uapi.KACS_STATUS_OPENED
	Created           Status      = uapi.KACS_STATUS_CREATED
	Overwritten       Status      = uapi.KACS_STATUS_OVERWRITTEN
	Superseded        Status      = uapi.KACS_STATUS_SUPERSEDED
	CurrentDirectory              = -100
)

func GenericMapping() security.GenericMapping {
	return security.GenericMapping{Read: 0x120089, Write: 0x120116, Execute: 0x1200a0, All: 0x1f01ff}
}

type OpenOptions struct {
	Access      Access
	Disposition Disposition
	Options     Options
	Flags       Flags
	Descriptor  []byte
}

// OpenAt returns an ordinary Go file and the kernel's opened/created status.
// dirfd is borrowed and must remain open for this call; -100 means cwd.
func OpenAt(dirfd int, path string, o OpenOptions) (*os.File, Status, error) {
	if uint64(len(o.Descriptor)) > 0xffffffff {
		return nil, 0, syscall.EINVAL
	}
	var pins native.Pins
	defer pins.Unpin()
	p, e := pins.String(path)
	if e != nil {
		return nil, 0, e
	}
	how := uapi.Kacs_open_how{Desired_access: uint32(o.Access), Create_disposition: uint32(o.Disposition), Create_options: uint32(o.Options), Flags: uint32(o.Flags), Sd_ptr: uint64(pins.Bytes(o.Descriptor)), Sd_len: uint32(len(o.Descriptor))}
	var status uint32
	fd, e := native.Call(uapi.SYS_KACS_OPEN, uintptr(dirfd), p, pins.Pointer(unsafe.Pointer(&how)), unsafe.Sizeof(how), pins.Pointer(unsafe.Pointer(&status)))
	if e != nil {
		return nil, 0, &os.PathError{Op: "peios.open", Path: path, Err: e}
	}
	return native.File(fd, path), Status(status), nil
}
func Open(path string, o OpenOptions) (*os.File, Status, error) {
	return OpenAt(CurrentDirectory, path, o)
}
func GetDescriptorAt(dirfd int, path string, info security.SecurityInformation, flags Flags) ([]byte, error) {
	var pins native.Pins
	defer pins.Unpin()
	p, e := pins.String(path)
	if e != nil {
		return nil, e
	}
	return native.Buffer(func(b []byte) (uint32, error) {
		var data native.Pins
		defer data.Unpin()
		n, e := native.Call(uapi.SYS_KACS_GET_SD, uintptr(dirfd), p, uintptr(info), data.Bytes(b), uintptr(len(b)), uintptr(flags))
		if n > 0xffffffff {
			return 0, syscall.EOVERFLOW
		}
		return uint32(n), e
	})
}
func SetDescriptorAt(dirfd int, path string, info security.SecurityInformation, sd []byte, flags Flags) error {
	if len(sd) == 0 || uint64(len(sd)) > 0xffffffff {
		return syscall.EINVAL
	}
	var pins native.Pins
	defer pins.Unpin()
	p, e := pins.String(path)
	if e != nil {
		return e
	}
	_, e = native.Call(uapi.SYS_KACS_SET_SD, uintptr(dirfd), p, uintptr(info), pins.Bytes(sd), uintptr(len(sd)), uintptr(flags))
	return e
}
func GetDescriptor(f syscall.Conn, info security.SecurityInformation) (b []byte, e error) {
	e = native.WithFD(f, func(fd int) error { var err error; b, err = GetDescriptorAt(fd, "", info, 0x1000); return err })
	return
}
func SetDescriptor(f syscall.Conn, info security.SecurityInformation, sd []byte) error {
	return native.WithFD(f, func(fd int) error { return SetDescriptorAt(fd, "", info, sd, 0x1000) })
}

type MountPolicy struct {
	Policy, Flags, Generation uint32
	Template                  []byte
}

func GetMountPolicy(f syscall.Conn) (out MountPolicy, e error) {
	e = native.WithFD(f, func(fd int) error {
		b, err := native.Buffer(func(b []byte) (uint32, error) {
			var p native.Pins
			defer p.Unpin()
			a := uapi.Kacs_mount_policy_args{Template_sd_ptr: uint64(p.Bytes(b)), Template_sd_len: uint32(len(b))}
			_, e := native.Call(uapi.SYS_KACS_GET_MOUNT_POLICY, uintptr(fd), p.Pointer(unsafe.Pointer(&a)), unsafe.Sizeof(a))
			out.Policy = a.Policy
			out.Flags = a.Flags
			out.Generation = a.Generation
			return a.Template_sd_len, e
		})
		out.Template = b
		return err
	})
	return
}
func SetMountPolicy(f syscall.Conn, v MountPolicy) error {
	return native.WithFD(f, func(fd int) error {
		if uint64(len(v.Template)) > 0xffffffff {
			return syscall.EINVAL
		}
		var p native.Pins
		defer p.Unpin()
		a := uapi.Kacs_mount_policy_args{Policy: v.Policy, Flags: v.Flags, Template_sd_ptr: uint64(p.Bytes(v.Template)), Template_sd_len: uint32(len(v.Template))}
		_, e := native.Call(uapi.SYS_KACS_SET_MOUNT_POLICY, uintptr(fd), p.Pointer(unsafe.Pointer(&a)), unsafe.Sizeof(a))
		return e
	})
}

// SysVKind selects an IPC object in the caller's IPC namespace.
type SysVKind uint32

const (
	SysVSharedMemory SysVKind = uapi.KACS_SD_AT_SYSV_SHM
	SysVMessageQueue SysVKind = uapi.KACS_SD_AT_SYSV_MSG
	SysVSemaphore    SysVKind = uapi.KACS_SD_AT_SYSV_SEM
)

func GetSysVDescriptor(kind SysVKind, id int, info security.SecurityInformation) ([]byte, error) {
	return native.Buffer(func(b []byte) (uint32, error) {
		var p native.Pins
		defer p.Unpin()
		n, e := native.Call(uapi.SYS_KACS_GET_SD, uintptr(id), 0, uintptr(info), p.Bytes(b), uintptr(len(b)), uintptr(kind))
		if n > 0xffffffff {
			return 0, syscall.EOVERFLOW
		}
		return uint32(n), e
	})
}
func SetSysVDescriptor(kind SysVKind, id int, info security.SecurityInformation, sd []byte) error {
	if len(sd) == 0 || uint64(len(sd)) > 0xffffffff {
		return syscall.EINVAL
	}
	var p native.Pins
	defer p.Unpin()
	_, e := native.Call(uapi.SYS_KACS_SET_SD, uintptr(id), 0, uintptr(info), p.Bytes(sd), uintptr(len(sd)), uintptr(kind))
	return e
}

const (
	MountUnmanaged            uint32 = uapi.KACS_MOUNT_POLICY_UNMANAGED
	MountDenyMissing          uint32 = uapi.KACS_MOUNT_POLICY_DENY_MISSING
	MountSynthesizeEphemeral  uint32 = uapi.KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL
	MountSynthesizePersistent uint32 = uapi.KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT
)
