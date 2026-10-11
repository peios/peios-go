package registry

import (
	"bytes"
	"encoding/binary"
	"syscall"

	"github.com/peios/peios-go/internal/uapi"
)

type WatchType uint16

const (
	WatchValueSet        WatchType = uapi.REG_WATCH_VALUE_SET
	WatchValueDeleted    WatchType = uapi.REG_WATCH_VALUE_DELETED
	WatchSubkeyCreated   WatchType = uapi.REG_WATCH_SUBKEY_CREATED
	WatchSubkeyDeleted   WatchType = uapi.REG_WATCH_SUBKEY_DELETED
	WatchSecurityChanged WatchType = uapi.REG_WATCH_SD_CHANGED
	WatchKeyDeleted      WatchType = uapi.REG_WATCH_KEY_DELETED
	WatchOverflow        WatchType = uapi.REG_WATCH_OVERFLOW
)

type WatchEvent struct {
	Type WatchType
	Name string
	Path []string
}

// ParseNotifications decodes complete records. Unknown event types are retained;
// an overflow record tells callers to refresh their view from a snapshot.
func ParseNotifications(b []byte) ([]WatchEvent, error) {
	var out []WatchEvent
	for len(b) > 0 {
		if len(b) < 8 {
			return nil, syscall.EPROTO
		}
		n := uint64(binary.LittleEndian.Uint32(b))
		nameLen := uint64(binary.LittleEndian.Uint16(b[6:]))
		if n < 8 || n > uint64(len(b)) || nameLen > n-8 {
			return nil, syscall.EPROTO
		}
		name := b[8 : 8+nameLen]
		if bytes.IndexByte(name, 0) >= 0 {
			return nil, syscall.EPROTO
		}
		v := WatchEvent{Type: WatchType(binary.LittleEndian.Uint16(b[4:])), Name: string(name)}
		extra := b[8+nameLen : n]
		if len(extra) > 0 {
			if len(extra) < 2 {
				return nil, syscall.EPROTO
			}
			depth := binary.LittleEndian.Uint16(extra)
			extra = extra[2:]
			for range depth {
				if len(extra) < 2 {
					return nil, syscall.EPROTO
				}
				size := int(binary.LittleEndian.Uint16(extra))
				extra = extra[2:]
				if size > len(extra) || bytes.IndexByte(extra[:size], 0) >= 0 {
					return nil, syscall.EPROTO
				}
				v.Path = append(v.Path, string(extra[:size]))
				extra = extra[size:]
			}
			if len(extra) != 0 {
				return nil, syscall.EPROTO
			}
		}
		out = append(out, v)
		b = b[n:]
	}
	return out, nil
}
func (k *Key) ReadWatchEvents(buffer []byte) ([]WatchEvent, error) {
	n, e := k.ReadNotifications(buffer)
	if e != nil {
		return nil, e
	}
	return ParseNotifications(buffer[:n])
}
