package security

// Inheritance describes the receiving object. A nil mapping preserves generic
// rights; absent owner/group SIDs preserve the corresponding creator SID.
type Inheritance struct {
	Container    bool
	Owner, Group SID
	Mapping      *GenericMapping
}

func inheritedACEs(parent *ACL, child Inheritance) []ACE {
	var out []ACE
	if parent == nil {
		return out
	}
	const all = ObjectInherit | ContainerInherit | NoPropagate | InheritOnly
	for _, a := range parent.ACEs {
		oi, ci, np := a.Flags&ObjectInherit != 0, a.Flags&ContainerInherit != 0, a.Flags&NoPropagate != 0
		if !(oi || ci && child.Container) || child.Container && !ci && np {
			continue
		}
		a.Flags = (a.Flags | Inherited) &^ InheritOnly
		if child.Container && oi && !ci && !np {
			a.Flags |= InheritOnly
		}
		if np || !child.Container {
			a.Flags &^= all
		}
		creatorOwner, creatorGroup := a.SID.String() == "S-1-3-0", a.SID.String() == "S-1-3-1"
		resolve := a.Type <= 20 && a.Type != 4 && (creatorOwner || creatorGroup || child.Mapping != nil && a.Mask&(GenericRead|GenericWrite|GenericExecute|GenericAll) != 0)
		if !resolve {
			out = append(out, a)
			continue
		}
		if a.Flags&InheritOnly == 0 {
			effective := a
			effective.Flags &^= all
			if creatorOwner && child.Owner.Valid() {
				effective.SID = child.Owner
			}
			if creatorGroup && child.Group.Valid() {
				effective.SID = child.Group
			}
			if child.Mapping != nil {
				effective.Mask = child.Mapping.Map(effective.Mask)
			}
			out = append(out, effective)
		}
		if a.Flags&(ObjectInherit|ContainerInherit) != 0 {
			a.Flags |= InheritOnly
			out = append(out, a)
		}
	}
	return out
}

// Reinherit replaces inherited entries in the selected, unprotected lists.
// Explicit entries keep their order. Creator SIDs resolve against the child's
// owner/group. Both inputs are structurally validated before rewriting.
func Reinherit(parent, child []byte, container bool, mapping *GenericMapping, info SecurityInformation) ([]byte, error) {
	p, e := ParseDescriptor(parent)
	if e != nil {
		return nil, e
	}
	c, e := ParseDescriptor(child)
	if e != nil {
		return nil, e
	}
	facts := Inheritance{container, c.Owner, c.Group, mapping}
	redo := func(old, par *ACL) *ACL {
		passed := inheritedACEs(par, facts)
		if old == nil && len(passed) == 0 {
			return nil
		}
		a := &ACL{}
		if old != nil {
			for _, x := range old.ACEs {
				if x.Flags&Inherited == 0 {
					a.ACEs = append(a.ACEs, x)
				}
			}
		}
		a.ACEs = append(a.ACEs, passed...)
		return a
	}
	// Match the public reference operation's control-bit normalization.
	c.Control &= DACLProtected | SACLProtected | DACLAutoInherited | SACLAutoInherited
	c.ResourceManagerControl = 0
	if info&InfoDACL != 0 && c.Control&DACLProtected == 0 {
		c.DACL = redo(c.DACL, p.DACL)
		c.Control |= DACLAutoInherited
	}
	if info&InfoSACL != 0 && c.Control&SACLProtected == 0 {
		c.SACL = redo(c.SACL, p.SACL)
		c.Control |= SACLAutoInherited
	}
	if c.DACL != nil {
		c.DACL.Revision = 0
		c.DACL.ExactRevision = false
		c.DACL.Reserved1 = 0
		c.DACL.Reserved2 = 0
	}
	if c.SACL != nil {
		c.SACL.Revision = 0
		c.SACL.ExactRevision = false
		c.SACL.Reserved1 = 0
		c.SACL.Reserved2 = 0
	}
	return c.MarshalBinary()
}

// StripInherited removes inherited entries from selected lists and preserves
// descriptor metadata, including protection and ACL revision floors.
func StripInherited(sd []byte, info SecurityInformation) ([]byte, error) {
	d, e := ParseDescriptor(sd)
	if e != nil {
		return nil, e
	}
	if info&(InfoDACL|InfoSACL) == 0 {
		return append([]byte(nil), sd...), nil
	}
	for _, x := range []struct {
		a   *ACL
		bit SecurityInformation
	}{{d.DACL, InfoDACL}, {d.SACL, InfoSACL}} {
		if x.a != nil && info&x.bit != 0 {
			out := x.a.ACEs[:0]
			for _, a := range x.a.ACEs {
				if a.Flags&Inherited == 0 {
					out = append(out, a)
				}
			}
			x.a.ACEs = out
			x.a.Reserved2 = 0
		}
	}
	return d.MarshalBinary()
}
