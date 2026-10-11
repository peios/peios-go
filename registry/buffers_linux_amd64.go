package registry

import (
	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"os"
	"syscall"
	"unsafe"
)

// TakeFile transfers an existing key fd (for example one received over a
// socket) into a Key. The caller must stop using/closing f. The kernel checks
// its object type and authority on subsequent operations.
func TakeFile(f *os.File) *Key { return &Key{f: f} }

// TakeTransactionFile transfers ownership of an existing transaction fd.
func TakeTransactionFile(f *os.File) *Transaction { return &Transaction{f: f} }

// ValueBufferResult describes QueryInto output, including required lengths on
// ERANGE. No internal allocation ceiling applies to caller-supplied buffers.
type ValueBufferResult struct {
	Type                    ValueType
	Sequence                uint64
	DataLength, LayerLength uint32
}

func (k *Key) QueryInto(name string, tx *Transaction, data, layer []byte) (out ValueBufferResult, e error) {
	if uint64(len(name)) > 0xffffffff || uint64(len(data)) > 0xffffffff || uint64(len(layer)) > 0xffffffff {
		return out, syscall.EINVAL
	}
	e = native.WithFD(k, func(fd int) error {
		return withTxn(tx, func(tfd int) error {
			var p native.Pins
			defer p.Unpin()
			a := uapi.Reg_query_value_args{Name_len: uint32(len(name)), Name_ptr: uint64(p.Bytes([]byte(name))), Txn_fd: int32(tfd), Data_ptr: uint64(p.Bytes(data)), Data_len: uint32(len(data)), Layer_ptr: uint64(p.Bytes(layer)), Layer_buf_len: uint32(len(layer))}
			err := native.Ioctl(fd, uapi.REG_IOC_QUERY_VALUE, unsafe.Pointer(&a))
			out = ValueBufferResult{ValueType(a.Type), a.Sequence, a.Data_len, a.Layer_len}
			return err
		})
	})
	return
}

// ValuesInto reads packed effective values without allocating decoded objects.
// Nil probes size. ERANGE reports needed; count is meaningful on success. Each record is
// [name length:u32][name][type:u32][data length:u32][data], little-endian.
func (k *Key) ValuesInto(tx *Transaction, buf []byte) (needed, count uint32, e error) {
	if uint64(len(buf)) > 0xffffffff {
		return 0, 0, syscall.EINVAL
	}
	e = native.WithFD(k, func(fd int) error {
		return withTxn(tx, func(tfd int) error {
			var p native.Pins
			defer p.Unpin()
			a := uapi.Reg_query_values_batch_args{Txn_fd: int32(tfd), Buf_ptr: uint64(p.Bytes(buf)), Buf_len: uint32(len(buf))}
			err := native.Ioctl(fd, uapi.REG_IOC_QUERY_VALUES_BATCH, unsafe.Pointer(&a))
			needed, count = a.Buf_len, a.Count
			return err
		})
	})
	return
}

type EnumBufferResult struct {
	Type                   ValueType
	NameLength, DataLength uint32
}

// ValueAtInto enumerates one value into caller-owned buffers. Nil buffers probe
// size; required lengths are returned on ERANGE. index is dense over values.
func (k *Key) ValueAtInto(index uint32, tx *Transaction, name, data []byte) (out EnumBufferResult, e error) {
	if uint64(len(name)) > 0xffffffff || uint64(len(data)) > 0xffffffff {
		return out, syscall.EINVAL
	}
	e = native.WithFD(k, func(fd int) error {
		return withTxn(tx, func(tfd int) error {
			var p native.Pins
			defer p.Unpin()
			a := uapi.Reg_enum_value_args{Index: index, Txn_fd: int32(tfd), Name_len: uint32(len(name)), Name_ptr: uint64(p.Bytes(name)), Data_len: uint32(len(data)), Data_ptr: uint64(p.Bytes(data))}
			err := native.Ioctl(fd, uapi.REG_IOC_ENUM_VALUES, unsafe.Pointer(&a))
			out = EnumBufferResult{ValueType(a.Type), a.Name_len, a.Data_len}
			return err
		})
	})
	return
}
