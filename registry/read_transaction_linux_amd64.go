package registry

import (
	"unsafe"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
)

// BeginRead begins a bounded, single-hive read-only transaction. The first
// read fixes the hive's data and layer selection; mutations through it fail
// with EROFS. Use it with the *Transacted reads, value reads and enumeration,
// and close it as soon as the configuration has been copied.
func BeginRead() (*Transaction, error) {
	fd, e := native.Call(uapi.SYS_REG_BEGIN_READ_TRANSACTION)
	if e != nil {
		return nil, e
	}
	return &Transaction{native.File(fd, "registry.read-transaction")}, nil
}

// OpenTransacted opens path within a read transaction, or as Open does with a
// nil tx.
func OpenTransacted(path string, access Access, flags uint32, tx *Transaction) (*Key, error) {
	return openTransactedAt(-1, path, access, flags, tx)
}

// OpenTransacted opens path below k within a read transaction, or as Open
// does with a nil tx.
func (k *Key) OpenTransacted(path string, access Access, flags uint32, tx *Transaction) (out *Key, e error) {
	e = native.WithFD(k, func(fd int) error {
		var err error
		out, err = openTransactedAt(fd, path, access, flags, tx)
		return err
	})
	return
}

func openTransactedAt(parent int, path string, access Access, flags uint32, tx *Transaction) (out *Key, e error) {
	if tx == nil {
		return openAt(parent, path, access, flags)
	}
	e = native.WithFD(tx, func(txfd int) error {
		var p native.Pins
		defer p.Unpin()
		ptr, err := p.String(path)
		if err != nil {
			return err
		}
		fd, err := native.Call(uapi.SYS_REG_OPEN_KEY_TRANSACTED, uintptr(parent), ptr, uintptr(access), uintptr(flags), uintptr(txfd))
		if err != nil {
			return err
		}
		out = &Key{native.File(fd, "registry:"+path)}
		return nil
	})
	return
}

// readIoctl issues a read ioctl live, or wrapped for the transaction txfd.
// args must be pinned by p.
func readIoctl(fd, txfd int, live, transacted uintptr, args unsafe.Pointer, p *native.Pins) error {
	if txfd == -1 {
		return native.Ioctl(fd, live, args)
	}
	request := uapi.Reg_read_transacted_args{Args_ptr: uint64(p.Pointer(args)), Txn_fd: int32(txfd)}
	return native.Ioctl(fd, transacted, unsafe.Pointer(&request))
}
