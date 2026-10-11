package access

import (
	"syscall"
	"unsafe"

	"github.com/peios/peios-go/internal/native"
	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/security"
)

type ObjectType struct {
	Level uint16
	GUID  security.GUID
}
type Request struct {
	Token             syscall.Conn // nil selects the current effective token
	Descriptor        []byte
	Desired           security.AccessMask
	Mapping           security.GenericMapping
	Self              security.SID
	PrivilegeIntent   uint32
	ObjectTree        []ObjectType
	LocalClaims       []byte
	PIPType, PIPTrust uint32
	AuditContext      []byte
}
type Result struct {
	Granted         security.AccessMask
	ContinuousAudit uint32
	StagingMismatch bool
}
type NodeResult struct {
	Granted security.AccessMask
	Status  syscall.Errno
}

func (r Request) withArgs(fn func(*uapi.Kacs_access_check_args, *native.Pins) error) error {
	if len(r.Descriptor) == 0 || len(r.Descriptor) > 65535 || len(r.ObjectTree) > 65535 || uint64(len(r.LocalClaims)) > 0xffffffff {
		return syscall.EINVAL
	}
	if r.AuditContext != nil {
		if e := ValidateAuditContext(r.AuditContext); e != nil {
			return e
		}
	}
	var p native.Pins
	defer p.Unpin()
	tree := make([]uapi.Kacs_object_type_entry, len(r.ObjectTree))
	for i, x := range r.ObjectTree {
		tree[i] = uapi.Kacs_object_type_entry{Level: x.Level, Guid: x.GUID}
	}
	a := uapi.Kacs_access_check_args{Caller_size: 136, Token_fd: -1, Sd_ptr: uint64(p.Bytes(r.Descriptor)), Sd_len: uint32(len(r.Descriptor)), Desired_access: uint32(r.Desired), Mapping_read: uint32(r.Mapping.Read), Mapping_write: uint32(r.Mapping.Write), Mapping_execute: uint32(r.Mapping.Execute), Mapping_all: uint32(r.Mapping.All), Self_sid_ptr: uint64(p.Bytes(r.Self.Bytes())), Self_sid_len: uint32(len(r.Self.Bytes())), Privilege_intent: r.PrivilegeIntent, Object_tree_count: uint32(len(tree)), Local_claims_ptr: uint64(p.Bytes(r.LocalClaims)), Local_claims_len: uint32(len(r.LocalClaims)), Pip_type: r.PIPType, Pip_trust: r.PIPTrust, Audit_context_ptr: uint64(p.Bytes(r.AuditContext)), Audit_context_len: uint32(len(r.AuditContext))}
	if len(tree) > 0 {
		a.Object_tree_ptr = uint64(p.Pointer(unsafe.Pointer(&tree[0])))
	}
	if r.Token == nil {
		return fn(&a, &p)
	}
	return native.WithFD(r.Token, func(fd int) error { a.Token_fd = int32(fd); return fn(&a, &p) })
}

// Check returns the granted subset and audit outputs even on EACCES denial.
func Check(r Request) (out Result, e error) {
	e = r.withArgs(func(a *uapi.Kacs_access_check_args, p *native.Pins) error {
		var granted, audit, mismatch uint32
		a.Granted_out_ptr = uint64(p.Pointer(unsafe.Pointer(&granted)))
		a.Continuous_audit_out_ptr = uint64(p.Pointer(unsafe.Pointer(&audit)))
		a.Staging_mismatch_out_ptr = uint64(p.Pointer(unsafe.Pointer(&mismatch)))
		_, err := native.Call(uapi.SYS_KACS_ACCESS_CHECK, p.Pointer(unsafe.Pointer(a)))
		if err == nil || err == syscall.EACCES {
			out = Result{security.AccessMask(granted), audit, mismatch != 0}
		}
		return err
	})
	return
}

// CheckList reports a separate grant/denial for every object-tree node.
func CheckList(r Request) (out []NodeResult, e error) {
	if len(r.ObjectTree) == 0 {
		return nil, syscall.EINVAL
	}
	e = r.withArgs(func(a *uapi.Kacs_access_check_args, p *native.Pins) error {
		nodes := make([]uapi.Kacs_node_result, len(r.ObjectTree))
		_, err := native.Call(uapi.SYS_KACS_ACCESS_CHECK_LIST, p.Pointer(unsafe.Pointer(a)), p.Pointer(unsafe.Pointer(&nodes[0])), uintptr(len(nodes)))
		if err != nil {
			return err
		}
		out = make([]NodeResult, len(nodes))
		for i, x := range nodes {
			if x.Status > 0 {
				return syscall.EPROTO
			}
			out[i] = NodeResult{security.AccessMask(x.Granted), syscall.Errno(-x.Status)}
		}
		return nil
	})
	return
}
