package registry

import (
	"encoding/binary"
	"syscall"
	"unsafe"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/security"
)

const Tombstone ValueType = uapi.REG_TOMBSTONE

func GenericMapping() security.GenericMapping {
	return security.GenericMapping{Read: uapi.KEY_READ, Write: uapi.KEY_WRITE, Execute: 0, All: uapi.KEY_ALL_ACCESS}
}

type NamedValue struct {
	Name  string
	Value Value
}
type KeyInfo struct {
	Name                                                                       string
	LastWriteTime                                                              uint64
	Subkeys, Values, MaxSubkeyName, MaxValueName, MaxValueData, DescriptorSize uint32
	Volatile, Symlink                                                          bool
	Generation                                                                 uint64
}

func (k *Key) Info() (out KeyInfo, e error) {
	e = native.WithFD(k, func(fd int) error {
		b, err := native.Buffer(func(b []byte) (uint32, error) {
			var p native.Pins
			defer p.Unpin()
			a := uapi.Reg_query_key_info_args{Name_len: uint32(len(b)), Name_ptr: uint64(p.Bytes(b))}
			err := native.Ioctl(fd, uapi.REG_IOC_QUERY_KEY_INFO, unsafe.Pointer(&a))
			if err == nil {
				out = KeyInfo{LastWriteTime: a.Last_write_time, Subkeys: a.Subkey_count, Values: a.Value_count, MaxSubkeyName: a.Max_subkey_name_len, MaxValueName: a.Max_value_name_len, MaxValueData: a.Max_value_data_size, DescriptorSize: a.Sd_size, Volatile: a.Volatile_key != 0, Symlink: a.Symlink != 0, Generation: a.Hive_generation}
			}
			return a.Name_len, err
		})
		if err != nil {
			return err
		}
		out.Name = string(b)
		return nil
	})
	return
}
func (k *Key) Subkey(index uint32, tx *Transaction) (out KeyInfo, e error) {
	e = native.WithFD(k, func(fd int) error {
		return withTxn(tx, func(txfd int) error {
			b, err := native.Buffer(func(b []byte) (uint32, error) {
				var p native.Pins
				defer p.Unpin()
				a := uapi.Reg_enum_subkey_args{Index: index, Name_len: uint32(len(b)), Name_ptr: uint64(p.Bytes(b)), Txn_fd: int32(txfd)}
				err := native.Ioctl(fd, uapi.REG_IOC_ENUM_SUBKEYS, unsafe.Pointer(&a))
				if err == nil {
					out = KeyInfo{LastWriteTime: a.Last_write_time, Subkeys: a.Subkey_count, Values: a.Value_count}
				}
				return a.Name_len, err
			})
			if err != nil {
				return err
			}
			out.Name = string(b)
			return nil
		})
	})
	return
}
func (k *Key) ValueAt(index uint32, tx *Transaction) (out NamedValue, e error) {
	e = native.WithFD(k, func(fd int) error {
		return withTxn(tx, func(txfd int) error {
			var name, data []byte
			for tries := 0; tries < 8; tries++ {
				var p native.Pins
				a := uapi.Reg_enum_value_args{Index: index, Name_len: uint32(len(name)), Name_ptr: uint64(p.Bytes(name)), Data_len: uint32(len(data)), Data_ptr: uint64(p.Bytes(data)), Txn_fd: int32(txfd)}
				err := native.Ioctl(fd, uapi.REG_IOC_ENUM_VALUES, unsafe.Pointer(&a))
				p.Unpin()
				if err == nil {
					if int(a.Name_len) > len(name) || int(a.Data_len) > len(data) {
						return syscall.EPROTO
					}
					out = NamedValue{string(name[:a.Name_len]), Value{Type: ValueType(a.Type), Data: data[:a.Data_len]}}
					return nil
				}
				if err != syscall.ERANGE {
					return err
				}
				if a.Name_len > 65536 || a.Data_len > 16*1024*1024 {
					return syscall.EOVERFLOW
				}
				if int(a.Name_len) <= len(name) && int(a.Data_len) <= len(data) {
					return syscall.EPROTO
				}
				name = make([]byte, a.Name_len)
				data = make([]byte, a.Data_len)
			}
			return syscall.EAGAIN
		})
	})
	return
}

// Values obtains a single effective-view batch (unlike a sequence of indexed
// reads, which can observe changes between calls).
func (k *Key) Values(tx *Transaction) (out []NamedValue, e error) {
	e = native.WithFD(k, func(fd int) error {
		return withTxn(tx, func(txfd int) error {
			var count uint32
			b, err := native.Buffer(func(b []byte) (uint32, error) {
				var p native.Pins
				defer p.Unpin()
				a := uapi.Reg_query_values_batch_args{Buf_len: uint32(len(b)), Buf_ptr: uint64(p.Bytes(b)), Txn_fd: int32(txfd)}
				err := native.Ioctl(fd, uapi.REG_IOC_QUERY_VALUES_BATCH, unsafe.Pointer(&a))
				count = a.Count
				return a.Buf_len, err
			})
			if err != nil {
				return err
			}
			out, err = parseValues(b, count)
			return err
		})
	})
	return
}
func parseValues(b []byte, count uint32) ([]NamedValue, error) {
	if uint64(count) > uint64(len(b))/12 {
		return nil, syscall.EPROTO
	}
	out := make([]NamedValue, 0, count)
	take := func(n uint32) ([]byte, bool) {
		if uint64(n) > uint64(len(b)) {
			return nil, false
		}
		v := b[:n]
		b = b[n:]
		return v, true
	}
	word := func() (uint32, bool) {
		v, ok := take(4)
		if !ok {
			return 0, false
		}
		return binary.LittleEndian.Uint32(v), true
	}
	for range count {
		n, ok := word()
		if !ok {
			return nil, syscall.EPROTO
		}
		name, ok := take(n)
		if !ok {
			return nil, syscall.EPROTO
		}
		typ, ok := word()
		if !ok {
			return nil, syscall.EPROTO
		}
		n, ok = word()
		if !ok {
			return nil, syscall.EPROTO
		}
		data, ok := take(n)
		if !ok {
			return nil, syscall.EPROTO
		}
		out = append(out, NamedValue{string(name), Value{Type: ValueType(typ), Data: append([]byte{}, data...)}})
	}
	if len(b) != 0 {
		return nil, syscall.EPROTO
	}
	return out, nil
}
func (k *Key) Hide(o WriteOptions) error {
	if o.ExpectedSequence != nil {
		return syscall.EINVAL
	}
	return native.WithFD(k, func(fd int) error {
		return withTxn(o.Transaction, func(tx int) error {
			var p native.Pins
			defer p.Unpin()
			a := uapi.Reg_hide_key_args{Layer_len: uint32(len(o.Layer)), Layer_ptr: uint64(p.Bytes([]byte(o.Layer))), Txn_fd: int32(tx)}
			return native.Ioctl(fd, uapi.REG_IOC_HIDE_KEY, unsafe.Pointer(&a))
		})
	})
}
func (k *Key) BlanketTombstone(set bool, o WriteOptions) error {
	if o.ExpectedSequence != nil {
		return syscall.EINVAL
	}
	return native.WithFD(k, func(fd int) error {
		return withTxn(o.Transaction, func(tx int) error {
			var p native.Pins
			defer p.Unpin()
			a := uapi.Reg_blanket_tombstone_args{Layer_len: uint32(len(o.Layer)), Layer_ptr: uint64(p.Bytes([]byte(o.Layer))), Txn_fd: int32(tx)}
			if set {
				a.Set = 1
			}
			return native.Ioctl(fd, uapi.REG_IOC_BLANKET_TOMBSTONE, unsafe.Pointer(&a))
		})
	})
}
func (k *Key) Backup(output syscall.Conn) error {
	return native.WithFD(k, func(fd int) error {
		return native.WithFD(output, func(dest int) error {
			a := uapi.Reg_backup_args{Output_fd: int32(dest)}
			return native.Ioctl(fd, uapi.REG_IOC_BACKUP, unsafe.Pointer(&a))
		})
	})
}
func (k *Key) Restore(input syscall.Conn) error {
	return native.WithFD(k, func(fd int) error {
		return native.WithFD(input, func(src int) error {
			a := uapi.Reg_restore_args{Input_fd: int32(src)}
			return native.Ioctl(fd, uapi.REG_IOC_RESTORE, unsafe.Pointer(&a))
		})
	})
}
