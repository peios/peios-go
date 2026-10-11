package registry

import (
	"encoding/binary"
	"sort"
	"strings"
	"syscall"

	"github.com/peios/peios-go/security"
)

const LayersPath = `Machine\System\Registry\Layers`

type Layer struct {
	Name       string
	Precedence uint32
	Enabled    bool
	Owner      security.SID
	Malformed  bool
}

func layerPath(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "/\\\x00") {
		return "", syscall.EINVAL
	}
	return LayersPath + `\` + name, nil
}
func ReadLayer(name string) (out Layer, e error) {
	path, e := layerPath(name)
	if e != nil {
		return out, e
	}
	out = Layer{Name: name, Enabled: true}
	if strings.EqualFold(name, "base") {
		return out, nil
	}
	k, e := Open(path, QueryValue, 0)
	if e != nil {
		return out, e
	}
	defer k.Close()
	for _, field := range []string{"Precedence", "Enabled", "Owner"} {
		v, e := k.Query(field, nil)
		if e == syscall.ENOENT {
			continue
		}
		if e != nil {
			return out, e
		}
		if field == "Owner" {
			s, err := security.SIDFromBytes(v.Data)
			if err != nil || v.Type != Binary {
				out.Malformed = true
			} else {
				out.Owner = s
			}
			continue
		}
		n, e := v.Uint32()
		if e != nil || field == "Enabled" && n > 1 {
			out.Malformed = true
			continue
		}
		if field == "Enabled" {
			out.Enabled = n != 0
		} else {
			out.Precedence = n
		}
	}
	return out, nil
}
func ListLayers() ([]Layer, error) {
	out := []Layer{{Name: "base", Enabled: true}}
	k, e := Open(LayersPath, Read, 0)
	if e == syscall.ENOENT {
		return out, nil
	}
	if e != nil {
		return nil, e
	}
	defer k.Close()
	for i := uint32(0); ; i++ {
		info, e := k.Subkey(i, nil)
		if e == syscall.ENOENT {
			break
		}
		if e != nil {
			return nil, e
		}
		if strings.EqualFold(info.Name, "base") {
			continue
		}
		l, e := ReadLayer(info.Name)
		if e != nil {
			return nil, e
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Precedence != out[j].Precedence {
			return out[i].Precedence > out[j].Precedence
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}
func CreateLayer(name string, precedence uint32, enabled bool) error {
	if _, e := layerPath(name); e != nil {
		return e
	}
	if strings.EqualFold(name, "base") {
		return syscall.EINVAL
	}
	tx, e := Begin()
	if e != nil {
		return e
	}
	defer tx.Close()
	parent, e := Open(`Machine\System`, AllAccess, 0)
	if e != nil {
		return e
	}
	defer func() { parent.Close() }()
	for _, part := range []string{"Registry", "Layers"} {
		next, _, e := parent.Create(part, CreateOptions{Access: AllAccess, Transaction: tx})
		if e != nil {
			return e
		}
		parent.Close()
		parent = next
	}
	k, disp, e := parent.Create(name, CreateOptions{Access: SetValue, Transaction: tx})
	if e != nil {
		return e
	}
	defer k.Close()
	if disp == 2 {
		return syscall.EEXIST
	}
	on := uint32(0)
	if enabled {
		on = 1
	}
	for _, p := range []struct {
		name string
		n    uint32
	}{{"Precedence", precedence}, {"Enabled", on}} {
		if e = k.Set(p.name, Value{Type: DWORD, Data: binary.LittleEndian.AppendUint32(nil, p.n)}, WriteOptions{Transaction: tx}); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func SetLayerPrecedence(name string, n uint32) error {
	return setLayer(name, "Precedence", Value{Type: DWORD, Data: binary.LittleEndian.AppendUint32(nil, n)})
}
func SetLayerEnabled(name string, on bool) error {
	n := uint32(0)
	if on {
		n = 1
	}
	return setLayer(name, "Enabled", Value{Type: DWORD, Data: binary.LittleEndian.AppendUint32(nil, n)})
}
func SetLayerOwner(name string, owner security.SID) error {
	if !owner.Valid() {
		return syscall.EINVAL
	}
	return setLayer(name, "Owner", Value{Type: Binary, Data: owner.Bytes()})
}
func setLayer(name, field string, v Value) error {
	path, e := layerPath(name)
	if e != nil {
		return e
	}
	if strings.EqualFold(name, "base") {
		return syscall.EINVAL
	}
	k, e := Open(path, SetValue, 0)
	if e != nil {
		return e
	}
	defer k.Close()
	return k.Set(field, v, WriteOptions{})
}
func DeleteLayer(name string) error {
	path, e := layerPath(name)
	if e != nil {
		return e
	}
	if strings.EqualFold(name, "base") {
		return syscall.EINVAL
	}
	k, e := Open(path, security.Delete, 0)
	if e != nil {
		return e
	}
	defer k.Close()
	return k.Delete(WriteOptions{})
}
