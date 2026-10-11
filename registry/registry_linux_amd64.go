// Package registry provides native LCS keys, values, watches and transactions.
package registry

import (
	"encoding/binary"
	"errors"
	"os"
	"syscall"
	"unsafe"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/security"
)

type Access = security.AccessMask
type ValueType uint32

const (
	Read           Access    = uapi.KEY_READ
	Write          Access    = uapi.KEY_WRITE
	AllAccess      Access    = uapi.KEY_ALL_ACCESS
	QueryValue     Access    = uapi.KEY_QUERY_VALUE
	SetValue       Access    = uapi.KEY_SET_VALUE
	Notify         Access    = uapi.KEY_NOTIFY
	OpenLink       uint32    = uapi.REG_OPEN_LINK
	Binary         ValueType = uapi.REG_BINARY
	DWORD          ValueType = uapi.REG_DWORD
	QWORD          ValueType = uapi.REG_QWORD
	String         ValueType = uapi.REG_SZ
	ExpandString   ValueType = uapi.REG_EXPAND_SZ
	MultiString    ValueType = uapi.REG_MULTI_SZ
	NotifyValue    uint32    = uapi.REG_NOTIFY_VALUE
	NotifySubkey   uint32    = uapi.REG_NOTIFY_SUBKEY
	NotifySecurity uint32    = uapi.REG_NOTIFY_SD
	AnySequence    uint64    = 0
)

type Key struct{ f *os.File }

func (k *Key) SyscallConn() (syscall.RawConn, error) {
	if k == nil || k.f == nil {
		return nil, syscall.EBADF
	}
	return k.f.SyscallConn()
}
func (k *Key) Close() error {
	if k == nil || k.f == nil {
		return syscall.EBADF
	}
	return k.f.Close()
}
func openAt(parent int, path string, access Access, flags uint32) (*Key, error) {
	var p native.Pins
	defer p.Unpin()
	ptr, e := p.String(path)
	if e != nil {
		return nil, e
	}
	fd, e := native.Call(uapi.SYS_REG_OPEN_KEY, uintptr(parent), ptr, uintptr(access), uintptr(flags))
	if e != nil {
		return nil, e
	}
	return &Key{native.File(fd, "registry:"+path)}, nil
}
func Open(path string, access Access, flags uint32) (*Key, error) {
	return openAt(-1, path, access, flags)
}
func (k *Key) Open(path string, access Access, flags uint32) (out *Key, e error) {
	e = native.WithFD(k, func(fd int) error { var err error; out, err = openAt(fd, path, access, flags); return err })
	return
}

type Transaction struct{ f *os.File }

func (t *Transaction) SyscallConn() (syscall.RawConn, error) {
	if t == nil || t.f == nil {
		return nil, syscall.EBADF
	}
	return t.f.SyscallConn()
}
func (t *Transaction) Close() error {
	if t == nil || t.f == nil {
		return syscall.EBADF
	}
	return t.f.Close()
}
func Begin() (*Transaction, error) {
	fd, e := native.Call(uapi.SYS_REG_BEGIN_TRANSACTION)
	if e != nil {
		return nil, e
	}
	return &Transaction{native.File(fd, "registry.transaction")}, nil
}
func (t *Transaction) Commit() error {
	return native.WithFD(t, func(fd int) error { return native.Ioctl(fd, uapi.REG_IOC_COMMIT, nil) })
}

type TransactionStatus struct {
	State         uint32
	TerminalError syscall.Errno
}

func (t *Transaction) Status() (out TransactionStatus, e error) {
	e = native.WithFD(t, func(fd int) error {
		var a uapi.Reg_txn_status_args
		e := native.Ioctl(fd, uapi.REG_IOC_TXN_STATUS, unsafe.Pointer(&a))
		out = TransactionStatus{a.State, syscall.Errno(a.Terminal_errno)}
		return e
	})
	return
}
func withTxn(t *Transaction, fn func(int) error) error {
	if t == nil {
		return fn(-1)
	}
	return native.WithFD(t, fn)
}

type CreateOptions struct {
	Access      Access
	Flags       uint32
	Layer       string
	Transaction *Transaction
}

func Create(path string, o CreateOptions) (out *Key, disposition uint32, e error) {
	return createAt(-1, path, o)
}
func (k *Key) Create(path string, o CreateOptions) (out *Key, disposition uint32, e error) {
	e = native.WithFD(k, func(fd int) error { var err error; out, disposition, err = createAt(fd, path, o); return err })
	return
}
func createAt(parent int, path string, o CreateOptions) (out *Key, disposition uint32, e error) {
	e = withTxn(o.Transaction, func(tx int) error {
		var p native.Pins
		defer p.Unpin()
		ptr, err := p.String(path)
		if err != nil {
			return err
		}
		var layer uintptr
		if o.Layer != "" {
			layer, err = p.String(o.Layer)
			if err != nil {
				return err
			}
		}
		a := uapi.Reg_create_key_args{Parent_fd: int32(parent), Path_ptr: uint64(ptr), Desired_access: uint32(o.Access), Flags: o.Flags, Layer_ptr: uint64(layer), Txn_fd: int32(tx), Disposition_ptr: uint64(p.Pointer(unsafe.Pointer(&disposition)))}
		fd, err := native.Call(uapi.SYS_REG_CREATE_KEY, p.Pointer(unsafe.Pointer(&a)))
		if err != nil {
			return err
		}
		out = &Key{native.File(fd, "registry:"+path)}
		return nil
	})
	return
}

// Value owns the effective value's data and layer metadata.
type Value struct {
	Type     ValueType
	Data     []byte
	Layer    string
	Sequence uint64
}

func (v Value) Uint32() (uint32, error) {
	if v.Type != DWORD || len(v.Data) != 4 {
		return 0, syscall.EINVAL
	}
	return binary.LittleEndian.Uint32(v.Data), nil
}
func (v Value) Uint64() (uint64, error) {
	if v.Type != QWORD || len(v.Data) != 8 {
		return 0, syscall.EINVAL
	}
	return binary.LittleEndian.Uint64(v.Data), nil
}
func (k *Key) Query(name string, tx *Transaction) (out Value, e error) {
	e = native.WithFD(k, func(fd int) error {
		return withTxn(tx, func(txfd int) error {
			var p native.Pins
			defer p.Unpin()
			nameBytes := []byte(name)
			nameptr := p.Bytes(nameBytes)
			var data, layer []byte
			for tries := 0; tries < 8; tries++ {
				var buffers native.Pins
				a := uapi.Reg_query_value_args{Name_len: uint32(len(nameBytes)), Name_ptr: uint64(nameptr), Txn_fd: int32(txfd), Data_len: uint32(len(data)), Data_ptr: uint64(buffers.Bytes(data)), Layer_buf_len: uint32(len(layer)), Layer_ptr: uint64(buffers.Bytes(layer))}
				err := native.Ioctl(fd, uapi.REG_IOC_QUERY_VALUE, unsafe.Pointer(&a))
				buffers.Unpin()
				if err == nil {
					if int(a.Data_len) > len(data) || int(a.Layer_len) > len(layer) {
						return syscall.EPROTO
					}
					out = Value{ValueType(a.Type), data[:a.Data_len], string(layer[:a.Layer_len]), a.Sequence}
					return nil
				}
				if !errors.Is(err, syscall.ERANGE) {
					return err
				}
				if a.Data_len > 16*1024*1024 || a.Layer_len > 65536 {
					return syscall.EOVERFLOW
				}
				data = make([]byte, a.Data_len)
				layer = make([]byte, a.Layer_len)
			}
			return syscall.EAGAIN
		})
	})
	return
}

// WriteOptions selects a target layer and optional transaction. ExpectedSequence
// nil permits any version; a pointer requests compare-and-set.
type WriteOptions struct {
	Layer            string
	Transaction      *Transaction
	ExpectedSequence *uint64
}

func (k *Key) Set(name string, v Value, o WriteOptions) error {
	return native.WithFD(k, func(fd int) error {
		return withTxn(o.Transaction, func(tx int) error {
			if uint64(len(v.Data)) > 0xffffffff {
				return syscall.EINVAL
			}
			var p native.Pins
			defer p.Unpin()
			seq := AnySequence
			if o.ExpectedSequence != nil {
				seq = *o.ExpectedSequence
			}
			a := uapi.Reg_set_value_args{Name_len: uint32(len(name)), Name_ptr: uint64(p.Bytes([]byte(name))), Type: uint32(v.Type), Data_len: uint32(len(v.Data)), Data_ptr: uint64(p.Bytes(v.Data)), Layer_len: uint32(len(o.Layer)), Layer_ptr: uint64(p.Bytes([]byte(o.Layer))), Txn_fd: int32(tx), Expected_seq: seq}
			return native.Ioctl(fd, uapi.REG_IOC_SET_VALUE, unsafe.Pointer(&a))
		})
	})
}
func (k *Key) DeleteValue(name string, o WriteOptions) error {
	if o.ExpectedSequence != nil {
		return syscall.EINVAL
	}
	return native.WithFD(k, func(fd int) error {
		return withTxn(o.Transaction, func(tx int) error {
			var p native.Pins
			defer p.Unpin()
			a := uapi.Reg_delete_value_args{Name_len: uint32(len(name)), Name_ptr: uint64(p.Bytes([]byte(name))), Layer_len: uint32(len(o.Layer)), Layer_ptr: uint64(p.Bytes([]byte(o.Layer))), Txn_fd: int32(tx)}
			return native.Ioctl(fd, uapi.REG_IOC_DELETE_VALUE, unsafe.Pointer(&a))
		})
	})
}
func (k *Key) Delete(o WriteOptions) error {
	if o.ExpectedSequence != nil {
		return syscall.EINVAL
	}
	return native.WithFD(k, func(fd int) error {
		return withTxn(o.Transaction, func(tx int) error {
			var p native.Pins
			defer p.Unpin()
			a := uapi.Reg_delete_key_args{Layer_len: uint32(len(o.Layer)), Layer_ptr: uint64(p.Bytes([]byte(o.Layer))), Txn_fd: int32(tx)}
			return native.Ioctl(fd, uapi.REG_IOC_DELETE_KEY, unsafe.Pointer(&a))
		})
	})
}
func (k *Key) Flush() error {
	return native.WithFD(k, func(fd int) error { return native.Ioctl(fd, uapi.REG_IOC_FLUSH, nil) })
}

// Notify arms notifications on this key's existing fd. ReadNotifications reads
// its queue; arming does not allocate another fd.
func (k *Key) Notify(filter uint32, subtree bool) error {
	return native.WithFD(k, func(fd int) error {
		a := uapi.Reg_notify_args{Filter: filter}
		if subtree {
			a.Subtree = 1
		}
		return native.Ioctl(fd, uapi.REG_IOC_NOTIFY, unsafe.Pointer(&a))
	})
}

func (k *Key) ReadNotifications(buf []byte) (int, error) {
	if k == nil || k.f == nil {
		return 0, syscall.EBADF
	}
	return k.f.Read(buf)
}
func (k *Key) GetDescriptor(info security.SecurityInformation) (out []byte, e error) {
	e = native.WithFD(k, func(fd int) error {
		var err error
		out, err = native.Buffer(func(b []byte) (uint32, error) {
			var p native.Pins
			defer p.Unpin()
			a := uapi.Reg_get_security_args{Security_info: uint32(info), Sd_len: uint32(len(b)), Sd_ptr: uint64(p.Bytes(b))}
			e := native.Ioctl(fd, uapi.REG_IOC_GET_SECURITY, unsafe.Pointer(&a))
			return a.Sd_len, e
		})
		return err
	})
	return
}
func (k *Key) SetDescriptor(info security.SecurityInformation, sd []byte, tx *Transaction) error {
	return native.WithFD(k, func(fd int) error {
		return withTxn(tx, func(txfd int) error {
			if uint64(len(sd)) > 0xffffffff {
				return syscall.EINVAL
			}
			var p native.Pins
			defer p.Unpin()
			a := uapi.Reg_set_security_args{Security_info: uint32(info), Sd_len: uint32(len(sd)), Sd_ptr: uint64(p.Bytes(sd)), Txn_fd: int32(txfd)}
			return native.Ioctl(fd, uapi.REG_IOC_SET_SECURITY, unsafe.Pointer(&a))
		})
	})
}

const (
	CreateSubkey     Access = uapi.KEY_CREATE_SUB_KEY
	EnumerateSubkeys Access = uapi.KEY_ENUMERATE_SUB_KEYS
	CreateLink       Access = uapi.KEY_CREATE_LINK
	Volatile         uint32 = uapi.REG_OPTION_VOLATILE
	Link             uint32 = uapi.REG_OPTION_CREATE_LINK
	CreatedNew       uint32 = uapi.REG_CREATED_NEW
	OpenedExisting   uint32 = uapi.REG_OPENED_EXISTING
	NotifyAll        uint32 = uapi.REG_NOTIFY_ALL
)
