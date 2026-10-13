package token

import (
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/security"
)

var ErrSpec = errors.New("peios/token: invalid token specification")

type Group struct {
	SID        security.SID
	Attributes uint32
}
type LCSCredentials struct {
	Scopes        []security.GUID
	PrivateLayers []string
}

// Spec is the portable token construction recipe. Zero scalar values are
// encoded verbatim; the kernel validates policy and the caller's authority.
// Choose Type and Level deliberately: a zero Level means Anonymous, not an
// unspecified default. CreateToken accepts all four levels for Primary tokens.
// A low primary level bounds peer captures and derivations without changing
// the process's own identity. Older kernels reject primary levels below
// Impersonation; Duplicate still requires that floor for primary results.
type Spec struct {
	User                                                                security.SID
	Groups, DeviceGroups, RestrictedSIDs                                []Group
	Type                                                                Type
	Level                                                               ImpersonationLevel
	IntegrityRID, MandatoryPolicy                                       uint32
	PrivilegesPresent, PrivilegesEnabled                                uint64
	ProjectedUID, ProjectedGID, AuditPolicy                             uint32
	Expiration, SessionID                                               uint64
	OwnerIndex, PrimaryGroupIndex                                       uint32
	SourceName                                                          string
	SourceID                                                            uint64
	DefaultDACL                                                         *security.ACL
	Confinement                                                         security.SID
	SupplementaryGIDs                                                   []uint32
	UserClaims, DeviceClaims                                            []security.Claim
	WriteRestricted, UserDenyOnly, IsolationBoundary, ConfinementExempt bool
	LCS                                                                 *LCSCredentials
}

func (s Spec) MarshalBinary() ([]byte, error) {
	b := make([]byte, uapi.KACS_TOKEN_SPEC_HEADER_BYTES)
	put := func(off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
	put64 := func(off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }
	put(uapi.KACS_TOKEN_SPEC_OFF_VERSION, uapi.KACS_TOKEN_SPEC_VERSION)
	if s.Type > 255 || s.Level > 255 || len(s.SourceName) > 8 || strings.ContainsRune(s.SourceName, 0) {
		return nil, ErrSpec
	}
	b[uapi.KACS_TOKEN_SPEC_OFF_TOKEN_TYPE] = byte(s.Type)
	b[uapi.KACS_TOKEN_SPEC_OFF_IMPERSONATION_LEVEL] = byte(s.Level)
	put(uapi.KACS_TOKEN_SPEC_OFF_INTEGRITY_RID, s.IntegrityRID)
	put(uapi.KACS_TOKEN_SPEC_OFF_MANDATORY_POLICY, s.MandatoryPolicy)
	put(uapi.KACS_TOKEN_SPEC_OFF_PROJECTED_UID, s.ProjectedUID)
	put(uapi.KACS_TOKEN_SPEC_OFF_PROJECTED_GID, s.ProjectedGID)
	put(uapi.KACS_TOKEN_SPEC_OFF_AUDIT_POLICY, s.AuditPolicy)
	put(uapi.KACS_TOKEN_SPEC_OFF_OWNER_SID_INDEX, s.OwnerIndex)
	put(uapi.KACS_TOKEN_SPEC_OFF_PRIMARY_GROUP_INDEX, s.PrimaryGroupIndex)
	put64(uapi.KACS_TOKEN_SPEC_OFF_PRIVS_PRESENT, s.PrivilegesPresent)
	put64(uapi.KACS_TOKEN_SPEC_OFF_PRIVS_ENABLED, s.PrivilegesEnabled)
	put64(uapi.KACS_TOKEN_SPEC_OFF_EXPIRATION, s.Expiration)
	put64(uapi.KACS_TOKEN_SPEC_OFF_LOGON_SESSION_ID, s.SessionID)
	put64(uapi.KACS_TOKEN_SPEC_OFF_SOURCE_ID, s.SourceID)
	if s.WriteRestricted {
		b[uapi.KACS_TOKEN_SPEC_OFF_WRITE_RESTRICTED] = 1
	}
	if s.UserDenyOnly {
		b[uapi.KACS_TOKEN_SPEC_OFF_USER_DENY_ONLY] = 1
	}
	if s.IsolationBoundary {
		b[uapi.KACS_TOKEN_SPEC_OFF_ISOLATION_BOUNDARY] = 1
	}
	if s.ConfinementExempt {
		b[uapi.KACS_TOKEN_SPEC_OFF_CONFINEMENT_EXEMPT] = 1
	}
	copy(b[uapi.KACS_TOKEN_SPEC_OFF_SOURCE_NAME:], s.SourceName)
	place := func(off, count int, data []byte, n int) error {
		if len(data) == 0 {
			return nil
		}
		if len(b)+len(data) > uapi.KACS_TOKEN_SPEC_MAX_BYTES {
			return ErrSpec
		}
		put(off, uint32(len(b)))
		if count >= 0 {
			put(count, uint32(n))
		}
		b = append(b, data...)
		return nil
	}
	if s.User.Valid() {
		if e := place(88, -1, s.User.Bytes(), 0); e != nil {
			return nil, e
		}
	}
	groups := func(off, count int, gs []Group) error {
		// The wire byte ceiling, not an arbitrary group count, is the limit.
		if len(gs) > (uapi.KACS_TOKEN_SPEC_MAX_BYTES-uapi.KACS_TOKEN_SPEC_HEADER_BYTES)/16 {
			return ErrSpec
		}
		var data []byte
		for _, g := range gs {
			if !g.SID.Valid() {
				return ErrSpec
			}
			sid := g.SID.Bytes()
			data = binary.LittleEndian.AppendUint32(data, uint32(len(sid)))
			data = append(data, sid...)
			data = binary.LittleEndian.AppendUint32(data, g.Attributes)
		}
		return place(off, count, data, len(gs))
	}
	if e := groups(92, 96, s.Groups); e != nil {
		return nil, e
	}
	if s.DefaultDACL != nil {
		d, e := s.DefaultDACL.MarshalBinary()
		if e != nil {
			return nil, e
		}
		if e = place(100, 104, d, len(d)); e != nil {
			return nil, e
		}
	}
	if e := groups(124, 128, s.DeviceGroups); e != nil {
		return nil, e
	}
	if e := groups(132, 136, s.RestrictedSIDs); e != nil {
		return nil, e
	}
	if s.Confinement.Valid() {
		d := s.Confinement.Bytes()
		if e := place(140, 144, d, len(d)); e != nil {
			return nil, e
		}
	}
	var gids []byte
	for _, g := range s.SupplementaryGIDs {
		gids = binary.LittleEndian.AppendUint32(gids, g)
	}
	if e := place(160, 164, gids, len(s.SupplementaryGIDs)); e != nil {
		return nil, e
	}
	for i, claims := range [][]security.Claim{s.UserClaims, s.DeviceClaims} {
		var data []byte
		for _, c := range claims {
			d, e := marshalClaim(c)
			if e != nil {
				return nil, e
			}
			data = binary.LittleEndian.AppendUint32(data, uint32(len(d)))
			data = append(data, d...)
			if len(data) > uapi.KACS_TOKEN_SPEC_MAX_BYTES {
				return nil, ErrSpec
			}
		}
		if e := place(108+i*8, 112+i*8, data, len(data)); e != nil {
			return nil, e
		}
	}
	if s.LCS != nil {
		d, e := s.LCS.MarshalBinary()
		if e != nil {
			return nil, e
		}
		if e = place(188, -1, d, 0); e != nil {
			return nil, e
		}
	}
	return b, nil
}
func (c LCSCredentials) MarshalBinary() ([]byte, error) {
	if len(c.Scopes) > uapi.KACS_TOKEN_LCS_MAX_SCOPE_GUIDS || len(c.PrivateLayers) > uapi.KACS_TOKEN_LCS_MAX_PRIVATE_LAYERS {
		return nil, ErrSpec
	}
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b, uapi.KACS_TOKEN_LCS_EXT_VERSION)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(c.Scopes)))
	binary.LittleEndian.PutUint32(b[12:], uint32(len(c.PrivateLayers)))
	seen := map[security.GUID]bool{}
	for _, g := range c.Scopes {
		if g == (security.GUID{}) || seen[g] {
			return nil, ErrSpec
		}
		seen[g] = true
		b = append(b, g[:]...)
	}
	names := map[string]bool{}
	for _, n := range c.PrivateLayers {
		lower := strings.Map(func(r rune) rune {
			if r >= 'A' && r <= 'Z' {
				return r + 32
			}
			return r
		}, n)
		if len(n) == 0 || len(n) > uapi.KACS_TOKEN_LCS_MAX_LAYER_NAME_BYTES || !utf8.ValidString(n) || strings.ContainsAny(n, "/\\\x00") || names[lower] {
			return nil, ErrSpec
		}
		names[lower] = true
		b = binary.LittleEndian.AppendUint32(b, uint32(len(n)))
	}
	for _, n := range c.PrivateLayers {
		b = append(b, n...)
	}
	return b, nil
}

// marshalClaim uses token-builder layout: offset table, slots, indirect data,
// then name. Resource-attribute ACL encoding uses a different canonical order.
func marshalClaim(c security.Claim) ([]byte, error) {
	validated, e := c.MarshalBinary()
	if e != nil {
		return nil, e
	}
	typ := binary.LittleEndian.Uint16(validated[4:])
	scalar := typ == 1 || typ == 2 || typ == 6
	size := 4
	if scalar {
		size = 8
	}
	start := 16 + 4*len(c.Values)
	b := make([]byte, start+size*len(c.Values))
	binary.LittleEndian.PutUint16(b[4:], typ)
	binary.LittleEndian.PutUint32(b[8:], c.Flags)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(c.Values)))
	utf16z := func(s string) []byte {
		var out []byte
		for _, u := range utf16.Encode([]rune(s)) {
			out = binary.LittleEndian.AppendUint16(out, u)
		}
		return append(out, 0, 0)
	}
	for i, v := range c.Values {
		slot := start + i*size
		binary.LittleEndian.PutUint32(b[16+i*4:], uint32(slot))
		switch x := v.(type) {
		case int64:
			binary.LittleEndian.PutUint64(b[slot:], uint64(x))
		case uint64:
			binary.LittleEndian.PutUint64(b[slot:], x)
		case bool:
			if x {
				binary.LittleEndian.PutUint64(b[slot:], 1)
			}
		default:
			binary.LittleEndian.PutUint32(b[slot:], uint32(len(b)))
			switch x := v.(type) {
			case string:
				b = append(b, utf16z(x)...)
			case security.SID:
				b = append(b, x.Bytes()...)
			case []byte:
				b = binary.LittleEndian.AppendUint32(b, uint32(len(x)))
				b = append(b, x...)
			}
		}
	}
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	b = append(b, utf16z(c.Name)...)
	return b, nil
}
