package native_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/peios/peios-go/registry"
	rsi "github.com/peios/peios-go/registry/source"
	"github.com/peios/peios-go/security"
)

// An isolated in-memory RSI fixture. Transactions use copied snapshots; no
// production database, host hive, or external service participates in the VM.
type fixtureKey struct {
	meta     rsi.ReadKeyResponse
	paths    map[string][]rsi.LookupPathEntry
	values   map[string]rsi.QueryValuesEntry
	blankets map[string]rsi.BlanketTombstoneEntry
}
type fixtureStore map[rsi.GUID]*fixtureKey

func newFixtureKey(meta rsi.ReadKeyResponse) *fixtureKey {
	return &fixtureKey{meta: meta, paths: map[string][]rsi.LookupPathEntry{}, values: map[string]rsi.QueryValuesEntry{}, blankets: map[string]rsi.BlanketTombstoneEntry{}}
}
func (s fixtureStore) clone() fixtureStore {
	out := fixtureStore{}
	for g, k := range s {
		v := newFixtureKey(k.meta)
		for n, x := range k.paths {
			v.paths[n] = append([]rsi.LookupPathEntry{}, x...)
		}
		for n, x := range k.values {
			v.values[n] = x
		}
		for n, x := range k.blankets {
			v.blankets[n] = x
		}
		out[g] = v
	}
	return out
}
func TestRegistrySourceAndOperations(t *testing.T) {
	guest(t)
	d, _ := security.ParseSDDL("O:SYG:SYD:(A;OICI;GA;;;SY)")
	sd, _ := d.MarshalBinary()
	root := rsi.GUID{1}
	store := fixtureStore{root: newFixtureKey(rsi.ReadKeyResponse{Name: "Machine", SD: sd})}
	transactions := map[uint64]fixtureStore{}
	var mu sync.Mutex
	source, e := rsi.Open([]rsi.Hive{{Name: "Machine", Root: root}}, 0)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	handler := func(ctx context.Context, h rsi.RequestHeader, payload []byte) (status uint32, response []byte) {
		mu.Lock()
		defer mu.Unlock()
		status = rsi.StatusOK
		dec := rsi.NewDecoder(payload)
		enc := rsi.NewEncoder(256)
		active := store
		if h.TxnID != 0 {
			var ok bool
			active, ok = transactions[h.TxnID]
			if !ok && h.OpCode != rsi.OpBeginTransaction {
				return rsi.StatusInvalid, nil
			}
		}
		invalid := func(e error) bool {
			if e != nil || dec.Remaining() != 0 {
				t.Errorf("RSI op %x malformed: %v remaining %d", h.OpCode, e, dec.Remaining())
				return true
			}
			return false
		}
		metadata := func(entries []rsi.LookupPathEntry) []rsi.LookupKeyMeta {
			var out []rsi.LookupKeyMeta
			for _, p := range entries {
				if k := active[p.TargetGUID]; k != nil {
					out = append(out, rsi.LookupKeyMeta{GUID: p.TargetGUID, SD: k.meta.SD, Volatile: k.meta.Volatile, Symlink: k.meta.Symlink, LastWriteTime: k.meta.LastWriteTime})
				}
			}
			return out
		}
		switch h.OpCode {
		case rsi.OpBeginTransaction:
			r, e := rsi.DecodeBeginTransactionRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			transactions[r.TxnID] = store.clone()
		case rsi.OpCommitTransaction:
			r, e := rsi.DecodeCommitTransactionRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			if tx, ok := transactions[r.TxnID]; ok {
				store = tx
				delete(transactions, r.TxnID)
			} else {
				return rsi.StatusInvalid, nil
			}
		case rsi.OpAbortTransaction:
			r, e := rsi.DecodeAbortTransactionRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			delete(transactions, r.TxnID)
		case rsi.OpReadKey:
			r, e := rsi.DecodeReadKeyRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			k := active[r.GUID]
			if k == nil {
				return rsi.StatusNotFound, nil
			}
			rsi.EncodeReadKeyResponse(enc, k.meta)
		case rsi.OpLookup:
			r, e := rsi.DecodeLookupRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			k := active[r.ParentGUID]
			if k == nil {
				return rsi.StatusNotFound, nil
			}
			entries := k.paths[strings.ToLower(r.ChildName)]
			rsi.EncodeLookupResponse(enc, entries, metadata(entries))
		case rsi.OpEnumChildren:
			r, e := rsi.DecodeEnumChildrenRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			k := active[r.ParentGUID]
			if k == nil {
				return rsi.StatusNotFound, nil
			}
			var names []string
			for n := range k.paths {
				names = append(names, n)
			}
			sort.Strings(names)
			var children []rsi.EnumChildrenChild
			var meta []rsi.LookupKeyMeta
			for _, n := range names {
				entries := k.paths[n]
				children = append(children, rsi.EnumChildrenChild{ChildName: n, Entries: entries})
				meta = append(meta, metadata(entries)...)
			}
			rsi.EncodeEnumChildrenResponse(enc, children, meta)
		case rsi.OpCreateKey:
			r, e := rsi.DecodeCreateKeyRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			active[r.GUID] = newFixtureKey(rsi.ReadKeyResponse{Name: r.Name, ParentGUID: r.ParentGUID, SD: r.SD, Volatile: r.Volatile, Symlink: r.Symlink})
		case rsi.OpCreateEntry:
			r, e := rsi.DecodeCreateEntryRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			k := active[r.ParentGUID]
			if k == nil {
				return rsi.StatusNotFound, nil
			}
			n := strings.ToLower(r.ChildName)
			k.paths[n] = append(k.paths[n], rsi.LookupPathEntry{LayerName: r.LayerName, TargetGUID: r.ChildGUID, Sequence: r.Sequence})
		case rsi.OpHideEntry:
			r, e := rsi.DecodeHideEntryRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			k := active[r.ParentGUID]
			if k == nil {
				return rsi.StatusNotFound, nil
			}
			n := strings.ToLower(r.ChildName)
			k.paths[n] = append(k.paths[n], rsi.LookupPathEntry{LayerName: r.LayerName, TargetType: 1, Sequence: r.Sequence})
		case rsi.OpDeleteEntry:
			r, e := rsi.DecodeDeleteEntryRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			k := active[r.ParentGUID]
			if k == nil {
				return rsi.StatusNotFound, nil
			}
			n := strings.ToLower(r.ChildName)
			entries := k.paths[n][:0]
			for _, v := range k.paths[n] {
				if v.LayerName != r.LayerName {
					entries = append(entries, v)
				}
			}
			if len(entries) == 0 {
				delete(k.paths, n)
			} else {
				k.paths[n] = entries
			}
		case rsi.OpDropKey:
			r, e := rsi.DecodeDropKeyRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			delete(active, r.GUID)
		case rsi.OpWriteKey:
			r, e := rsi.DecodeWriteKeyRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			k := active[r.GUID]
			if k == nil {
				return rsi.StatusNotFound, nil
			}
			if r.FieldMask&1 != 0 {
				k.meta.SD = r.SD
			}
			if r.FieldMask&2 != 0 {
				k.meta.LastWriteTime = r.LastWriteTime
			}
		case rsi.OpQueryValues:
			r, e := rsi.DecodeQueryValuesRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			k := active[r.GUID]
			if k == nil {
				return rsi.StatusNotFound, nil
			}
			var names []string
			for n, v := range k.values {
				if r.QueryAll || strings.EqualFold(v.ValueName, r.ValueName) {
					names = append(names, n)
				}
			}
			sort.Strings(names)
			var entries []rsi.QueryValuesEntry
			for _, n := range names {
				entries = append(entries, k.values[n])
			}
			var blankets []rsi.BlanketTombstoneEntry
			for _, v := range k.blankets {
				blankets = append(blankets, v)
			}
			rsi.EncodeQueryValuesResponse(enc, entries, blankets)
		case rsi.OpSetValue:
			r, e := rsi.DecodeSetValueRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			k := active[r.GUID]
			if k == nil {
				return rsi.StatusNotFound, nil
			}
			n := strings.ToLower(r.ValueName) + "/" + r.LayerName
			if r.ExpectedSequence != 0 && k.values[n].Sequence != r.ExpectedSequence {
				return rsi.StatusCASFailed, nil
			}
			k.values[n] = rsi.QueryValuesEntry{ValueName: r.ValueName, LayerName: r.LayerName, Type: r.Type, Data: r.Data, Sequence: r.Sequence}
		case rsi.OpDeleteValueEntry:
			r, e := rsi.DecodeDeleteValueEntryRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			k := active[r.GUID]
			if k == nil {
				return rsi.StatusNotFound, nil
			}
			delete(k.values, strings.ToLower(r.ValueName)+"/"+r.LayerName)
		case rsi.OpSetBlanketTombstone:
			r, e := rsi.DecodeSetBlanketTombstoneRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			k := active[r.GUID]
			if k == nil {
				return rsi.StatusNotFound, nil
			}
			if r.Set {
				k.blankets[r.LayerName] = rsi.BlanketTombstoneEntry{LayerName: r.LayerName, Sequence: r.Sequence}
			} else {
				delete(k.blankets, r.LayerName)
			}
		case rsi.OpDeleteLayer:
			r, e := rsi.DecodeDeleteLayerRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
			for _, k := range active {
				for n, v := range k.values {
					if strings.EqualFold(v.LayerName, r.LayerName) {
						delete(k.values, n)
					}
				}
				delete(k.blankets, r.LayerName)
			}
			rsi.EncodeDeleteLayerResponse(enc, nil)
		case rsi.OpFlush:
			_, e := rsi.DecodeFlushRequest(dec)
			if invalid(e) {
				return rsi.StatusInvalid, nil
			}
		default:
			t.Errorf("unexpected RSI op %x", h.OpCode)
			return rsi.StatusInvalid, nil
		}
		return status, enc.Bytes()
	}
	go func() { done <- source.Serve(ctx, 4, handler) }()
	defer func() {
		cancel()
		select {
		case e := <-done:
			if e != nil && !errors.Is(e, context.Canceled) {
				t.Error("source shutdown", e)
			}
		case <-time.After(3 * time.Second):
			t.Error("source failed to stop")
		}
	}()
	rootKey, e := registry.Open("Machine", registry.AllAccess, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer rootKey.Close()
	system, _, e := rootKey.Create("System", registry.CreateOptions{Access: registry.AllAccess})
	if e != nil {
		t.Fatal(e)
	}
	system.Close()
	key, disp, e := rootKey.Create("SDK", registry.CreateOptions{Access: registry.AllAccess})
	if e != nil || disp != 1 {
		t.Fatal(disp, e)
	}
	defer key.Close()
	if e = key.Set("count", registry.Value{Type: registry.DWORD, Data: binary.LittleEndian.AppendUint32(nil, 42)}, registry.WriteOptions{}); e != nil {
		t.Fatal(e)
	}
	v, e := key.Query("count", nil)
	if e != nil {
		t.Fatal(e)
	}
	if n, e := v.Uint32(); n != 42 || e != nil {
		t.Fatal(n, e)
	}
	if v.Layer != "base" || v.Sequence == 0 {
		t.Fatal(v)
	}

	probe, err := key.QueryInto("count", nil, nil, nil)
	if err != syscall.ERANGE || probe.DataLength != 4 || probe.LayerLength != 4 {
		t.Fatal(probe, err)
	}
	data, layer := make([]byte, probe.DataLength), make([]byte, probe.LayerLength)
	probe, err = key.QueryInto("count", nil, data, layer)
	if err != nil || binary.LittleEndian.Uint32(data) != 42 || string(layer) != "base" {
		t.Fatal(probe, err)
	}
	needed, count, err := key.ValuesInto(nil, nil)
	if err != syscall.ERANGE || needed == 0 {
		t.Fatal(needed, count, err)
	}
	packed := make([]byte, needed)
	if n, c, err := key.ValuesInto(nil, packed); err != nil || n != needed || c != 1 {
		t.Fatal(n, c, err)
	}
	enum, err := key.ValueAtInto(0, nil, nil, nil)
	if err != syscall.ERANGE || enum.NameLength != 5 || enum.DataLength != 4 {
		t.Fatal(enum, err)
	}
	name := make([]byte, enum.NameLength)
	enum, err = key.ValueAtInto(0, nil, name, data)
	if err != nil || string(name) != "count" || binary.LittleEndian.Uint32(data) != 42 {
		t.Fatal(enum, err)
	}
	info, e := key.Info()
	if e != nil || info.Values != 1 {
		t.Fatal(info, e)
	}
	enumerated, e := key.ValueAt(0, nil)
	if e != nil || enumerated.Name != "count" {
		t.Fatal(enumerated, e)
	}
	all, e := key.Values(nil)
	if e != nil || len(all) != 1 {
		t.Fatal(all, e)
	}
	if _, e = rootKey.Subkey(0, nil); e != nil {
		t.Fatal(e)
	}
	watch, e := registry.Open(`Machine\SDK`, registry.Read, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer watch.Close()
	if e = watch.Notify(registry.NotifyValue, false); e != nil {
		t.Fatal(e)
	}
	tx, e := registry.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	if e = key.Set("count", registry.Value{Type: registry.DWORD, Data: binary.LittleEndian.AppendUint32(nil, 43)}, registry.WriteOptions{Transaction: tx, ExpectedSequence: &v.Sequence}); e != nil {
		t.Fatal(e)
	}
	in, e := key.Query("count", tx)
	if n, _ := in.Uint32(); e != nil || n != 43 {
		t.Fatal(n, e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	notification := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		n, e := watch.ReadNotifications(buf)
		if e == nil && n < 8 {
			e = fmt.Errorf("short watch record %d", n)
		}
		notification <- e
	}()
	select {
	case e := <-notification:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("missing notification")
	}
	if e = key.Flush(); e != nil {
		t.Fatal(e)
	}
	if e = key.SetDescriptor(security.InfoDACL, sd, nil); e != nil {
		t.Fatal(e)
	}
	if _, e = key.GetDescriptor(security.InfoOwner | security.InfoGroup | security.InfoDACL); e != nil {
		t.Fatal(e)
	}
	backup, e := os.Create("/tmp/registry-backup")
	if e != nil {
		t.Fatal(e)
	}
	defer backup.Close()
	defer os.Remove(backup.Name())
	if e = key.Backup(backup); e != nil {
		t.Fatal("backup", e)
	}
	if e = key.DeleteValue("count", registry.WriteOptions{}); e != nil {
		t.Fatal(e)
	}
	backup.Seek(0, 0)
	if e = key.Restore(backup); e != nil {
		t.Fatal("restore", e)
	}
	if v, e = key.Query("count", nil); e != nil {
		t.Fatal(e)
	}
	if e = registry.CreateLayer("sdk-layer", 0, false); e != nil {
		t.Fatal("create layer", e)
	}
	layers, e := registry.ListLayers()
	if e != nil || len(layers) != 2 {
		t.Fatal(layers, e)
	}
	if e = registry.SetLayerEnabled("sdk-layer", true); e != nil {
		t.Fatal(e)
	}
	if e = registry.SetLayerOwner("sdk-layer", d.Owner); e != nil {
		t.Fatal(e)
	}
	if e = registry.SetLayerPrecedence("sdk-layer", 1); e != nil {
		t.Fatal(e)
	}
	if e = key.Set("count", registry.Value{Type: registry.DWORD, Data: binary.LittleEndian.AppendUint32(nil, 99)}, registry.WriteOptions{Layer: "sdk-layer"}); e != nil {
		t.Fatal(e)
	}
	v, e = key.Query("count", nil)
	if n, _ := v.Uint32(); e != nil || n != 99 {
		t.Fatal(n, e)
	}
	if e = key.BlanketTombstone(true, registry.WriteOptions{Layer: "sdk-layer"}); e != nil {
		t.Fatal(e)
	}
	if e = key.BlanketTombstone(false, registry.WriteOptions{Layer: "sdk-layer"}); e != nil {
		t.Fatal(e)
	}
	if e = registry.DeleteLayer("sdk-layer"); e != nil {
		t.Fatal(e)
	}
	if e = key.Delete(registry.WriteOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e = registry.Open(`Machine\SDK`, registry.Read, 0); !errors.Is(e, syscall.ENOENT) {
		t.Fatal(e)
	}
}
