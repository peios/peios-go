package security

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

func wordValueOf(table []wordValue, word string) (uint32, bool) {
	for _, v := range table {
		if v.word == strings.ToUpper(word) {
			return v.value, true
		}
	}
	return 0, false
}
func words(table []wordValue, s string, hexTail bool) (uint32, error) {
	var v uint32
	for len(s) > 0 {
		if hexTail && len(s) >= 2 && strings.EqualFold(s[:2], "0x") {
			n, e := strconv.ParseUint(s[2:], 16, 32)
			if e != nil {
				return 0, invalid("hex rights")
			}
			return v | uint32(n), nil
		}
		if len(s) < 2 {
			return 0, invalid("incomplete mnemonic")
		}
		n, ok := wordValueOf(table, s[:2])
		if !ok {
			return 0, invalid("unknown mnemonic " + s[:2])
		}
		v |= n
		s = s[2:]
	}
	return v, nil
}
func renderWords(table []wordValue, n uint32) string {
	var b strings.Builder
	for _, v := range table {
		if n&v.value == v.value {
			b.WriteString(v.word)
			n &^= v.value
		}
	}
	if n != 0 {
		fmt.Fprintf(&b, "0x%x", n)
	}
	return b.String()
}
func parseTrustee(s string) (SID, error) {
	if v, ok := aliases[strings.ToUpper(s)]; ok {
		s = v
	}
	return ParseSID(s)
}
func formatTrustee(s SID) string {
	v := s.String()
	for a, s := range aliases {
		if v == s {
			return a
		}
	}
	return v
}

// ParseSDDL parses the Peios SDDL vocabulary. Decimal rights and unresolved
// domain-relative SID aliases are rejected, as in libpeios.
func ParseSDDL(s string) (Descriptor, error) {
	var d Descriptor
	if len(s) == 0 || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return d, invalid("SDDL text")
	}
	type section struct {
		kind       byte
		start, end int
	}
	var sections []section
	depth := 0
	quoted := false
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
			continue
		}
		if c == '(' {
			depth++
		}
		if c == ')' {
			depth--
			if depth < 0 {
				return d, invalid("unbalanced parentheses")
			}
		}
		if depth == 0 && i+1 < len(s) && s[i+1] == ':' {
			kind := c
			if kind >= 'a' && kind <= 'z' {
				kind -= 32
			}
			if !strings.ContainsRune("OGDS", rune(kind)) {
				return d, invalid("SDDL section")
			}
			if len(sections) == 0 && i != 0 {
				return d, invalid("text before first section")
			}
			for _, p := range sections {
				if p.kind == kind {
					return d, invalid("duplicate section")
				}
			}
			if len(sections) > 0 {
				sections[len(sections)-1].end = i
			}
			sections = append(sections, section{kind, i + 2, len(s)})
			i++
		}
	}
	if depth != 0 || quoted || len(sections) == 0 {
		return d, invalid("unbalanced or missing section")
	}
	for _, p := range sections {
		body := s[p.start:p.end]
		switch p.kind {
		case 'O', 'G':
			sid, e := parseTrustee(body)
			if e != nil {
				return d, e
			}
			if p.kind == 'O' {
				d.Owner = sid
			} else {
				d.Group = sid
			}
		default:
			a, c, e := parseTextACL(body, p.kind == 'S')
			if e != nil {
				return d, e
			}
			d.Control |= c
			if p.kind == 'D' {
				d.DACL = a
			} else {
				d.SACL = a
			}
		}
	}
	return d, nil
}
func parseTextACL(s string, sacl bool) (*ACL, Control, error) {
	var a ACL
	var c Control
	nullACL := false
	shift := uint(0)
	if sacl {
		shift = 1
	}
	for len(s) > 0 && s[0] != '(' {
		u := strings.ToUpper(s)
		switch {
		case strings.HasPrefix(u, "NO_ACCESS_CONTROL"):
			if nullACL {
				return nil, c, invalid("duplicate NULL ACL marker")
			}
			nullACL = true
			s = s[len("NO_ACCESS_CONTROL"):]

		case strings.HasPrefix(u, "AR"):
			c |= 0x100 << shift
			s = s[2:]
		case strings.HasPrefix(u, "AI"):
			c |= 0x400 << shift
			s = s[2:]
		case u[0] == 'P':
			c |= 0x1000 << shift
			s = s[1:]
		default:
			return nil, c, invalid("ACL flags")
		}
	}
	if nullACL {
		if len(s) != 0 {
			return nil, c, invalid("NULL ACL with ACEs")
		}
		return nil, c, nil
	}
	if sacl {
		c |= SACLPresent
	} else {
		c |= DACLPresent
	}
	for len(s) > 0 {
		body, rest, e := paren(s)
		if e != nil {
			return nil, c, e
		}
		ace, e := parseTextACE(body)
		if e != nil {
			return nil, c, e
		}
		a.ACEs = append(a.ACEs, ace)
		s = rest
	}
	return &a, c, nil
}
func paren(s string) (string, string, error) {
	if len(s) == 0 || s[0] != '(' {
		return "", "", invalid("expected parenthesis")
	}
	depth := 0
	q := false
	esc := false
	for i, c := range []byte(s) {
		if q {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				q = false
			}
			continue
		}
		if c == '"' {
			q = true
		}
		if c == '(' {
			depth++
		}
		if c == ')' {
			depth--
			if depth == 0 {
				return s[1:i], s[i+1:], nil
			}
		}
	}
	return "", "", invalid("unterminated parentheses")
}
func parseTextACE(s string) (ACE, error) {
	var a ACE
	p := strings.SplitN(s, ";", 7)
	if len(p) < 6 {
		return a, invalid("ACE field count")
	}
	t, ok := wordValueOf(ace_type_codes, p[0])
	if !ok {
		return a, invalid("ACE type")
	}
	a.Type = ACEType(t)
	f, e := words(ace_flag_codes, p[1], false)
	if e != nil {
		return a, e
	}
	a.Flags = ACEFlags(f)
	m, e := words(rights_parse, p[2], true)
	if e != nil {
		return a, e
	}
	a.Mask = AccessMask(m)
	for i, target := range []**GUID{&a.ObjectType, &a.InheritedObjectType} {
		if strings.TrimSpace(p[3+i]) != "" {
			g, e := ParseGUID(strings.TrimSpace(p[3+i]))
			if e != nil {
				return a, e
			}
			*target = &g
		}
	}
	if !objectACE(a.Type) && (a.ObjectType != nil || a.InheritedObjectType != nil) {
		return a, invalid("object fields on non-object ACE")
	}
	a.SID, e = parseTrustee(p[5])
	if e != nil {
		return a, e
	}
	if callbackACE(a.Type) {
		if len(p) != 7 {
			return a, invalid("missing conditional payload")
		}
		a.ApplicationData, e = ParseCondition(p[6])
		if e != nil {
			return a, e
		}
	} else if a.Type == 18 {
		if len(p) != 7 {
			return a, invalid("missing resource claim")
		}
		a.ApplicationData, e = parseClaim(p[6])
		if e != nil {
			return a, e
		}
		a.SID, _ = NewSID(1, 0)
		a.Mask = 0
	} else if len(p) == 7 {
		return a, invalid("unexpected payload")
	}
	return a, nil
}

// SDDL formats a descriptor without dropping entries or payloads. A NULL ACL
// is omitted unless it carries P/AR/AI flags, which it keeps as e.g.
// D:PNO_ACCESS_CONTROL; a descriptor with nothing else to show is written
// D:NO_ACCESS_CONTROL.
func (d Descriptor) SDDL() (string, error) {
	if _, e := d.MarshalBinary(); e != nil {
		return "", e
	}
	var b strings.Builder
	if d.Owner.Valid() {
		b.WriteString("O:" + formatTrustee(d.Owner))
	}
	if d.Group.Valid() {
		b.WriteString("G:" + formatTrustee(d.Group))
	}
	for i, a := range []*ACL{d.DACL, d.SACL} {
		flags := ""
		if d.Control&(0x1000<<i) != 0 {
			flags += "P"
		}
		if d.Control&(0x100<<i) != 0 {
			flags += "AR"
		}
		if d.Control&(0x400<<i) != 0 {
			flags += "AI"
		}
		if a == nil && flags == "" {
			continue
		}
		b.WriteString([]string{"D:", "S:"}[i] + flags)
		if a == nil {
			b.WriteString("NO_ACCESS_CONTROL")
			continue
		}
		for _, ace := range a.ACEs {
			s, e := formatTextACE(ace)
			if e != nil {
				return "", e
			}
			b.WriteString(s)
		}
	}
	if b.Len() == 0 {
		// SDDL has no empty string; this is the NULL DACL it describes.
		b.WriteString("D:NO_ACCESS_CONTROL")
	}
	return b.String(), nil
}
func formatTextACE(a ACE) (string, error) {
	if a.Flags & ^(ObjectInherit|ContainerInherit|NoPropagate|InheritOnly|Inherited|AuditSuccess|AuditFailure) != 0 {
		return "", invalid("ACE flags have no SDDL representation")
	}
	var code string
	for _, v := range ace_type_codes {
		if ACEType(v.value) == a.Type {
			code = v.word
		}
	}
	if code == "" {
		return "", invalid("ACE has no SDDL representation")
	}
	rights := rights_format
	if a.Type == MandatoryLabel {
		rights = []wordValue{{"NW", 1}, {"NR", 2}, {"NX", 4}}
	}
	obj, inh := "", ""
	if a.ObjectType != nil {
		obj = a.ObjectType.String()
	}
	if a.InheritedObjectType != nil {
		inh = a.InheritedObjectType.String()
	}
	p := []string{code, renderWords(ace_flag_codes, uint32(a.Flags)), renderWords(rights, uint32(a.Mask)), obj, inh, formatTrustee(a.SID)}
	if callbackACE(a.Type) {
		s, e := FormatCondition(a.ApplicationData)
		if e != nil {
			return "", e
		}
		p = append(p, "("+s+")")
	} else if a.Type == 18 {
		s, e := formatClaim(a.ApplicationData)
		if e != nil {
			return "", e
		}
		p = append(p, s)
	}
	return "(" + strings.Join(p, ";") + ")", nil
}
func ParseGUID(s string) (GUID, error) {
	var g GUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return g, invalid("GUID")
	}
	b, e := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if e != nil {
		return g, invalid("GUID hex")
	}
	copy(g[:], b)
	g[0], g[1], g[2], g[3] = g[3], g[2], g[1], g[0]
	g[4], g[5] = g[5], g[4]
	g[6], g[7] = g[7], g[6]
	return g, nil
}
func (g GUID) String() string {
	g[0], g[1], g[2], g[3] = g[3], g[2], g[1], g[0]
	g[4], g[5] = g[5], g[4]
	g[6], g[7] = g[7], g[6]
	return fmt.Sprintf("%x-%x-%x-%x-%x", g[:4], g[4:6], g[6:8], g[8:10], g[10:])
}
