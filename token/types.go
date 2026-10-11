package token

import (
	"github.com/peios/peios-go/internal/uapi"
	"github.com/peios/peios-go/security"
)

type Access = security.AccessMask
type Class uint32
type Type uint32
type ImpersonationLevel uint32

const (
	LevelAnonymous      ImpersonationLevel = uapi.KACS_IMLEVEL_ANONYMOUS
	LevelIdentification ImpersonationLevel = uapi.KACS_IMLEVEL_IDENTIFICATION
	LevelImpersonation  ImpersonationLevel = uapi.KACS_IMLEVEL_IMPERSONATION
	LevelDelegation     ImpersonationLevel = uapi.KACS_IMLEVEL_DELEGATION
	Query               Access             = uapi.KACS_TOKEN_QUERY
	Duplicate           Access             = uapi.KACS_TOKEN_DUPLICATE
	Impersonate         Access             = uapi.KACS_TOKEN_IMPERSONATE
	AdjustPrivileges    Access             = uapi.KACS_TOKEN_ADJUST_PRIVS
	AdjustGroups        Access             = uapi.KACS_TOKEN_ADJUST_GROUPS
	AdjustDefault       Access             = uapi.KACS_TOKEN_ADJUST_DEFAULT
	Real                uint32             = uapi.KACS_TOKEN_OPEN_REAL
	User                Class              = uapi.KACS_TOKEN_CLASS_USER
	Groups              Class              = uapi.KACS_TOKEN_CLASS_GROUPS
	Privileges          Class              = uapi.KACS_TOKEN_CLASS_PRIVILEGES
	Statistics          Class              = uapi.KACS_TOKEN_CLASS_STATISTICS
	DefaultDACL         Class              = uapi.KACS_TOKEN_CLASS_DEFAULT_DACL
	Primary             Type               = uapi.KACS_TOKEN_TYPE_PRIMARY
	Impersonation       Type               = uapi.KACS_TOKEN_TYPE_IMPERSONATION
)

const (
	AppContainerSID            Class = uapi.KACS_TOKEN_CLASS_APPCONTAINER_SID
	Capabilities               Class = uapi.KACS_TOKEN_CLASS_CAPABILITIES
	DeviceClaims               Class = uapi.KACS_TOKEN_CLASS_DEVICE_CLAIMS
	DeviceGroups               Class = uapi.KACS_TOKEN_CLASS_DEVICE_GROUPS
	ElevationType              Class = uapi.KACS_TOKEN_CLASS_ELEVATION_TYPE
	ImpersonationLevelClass    Class = uapi.KACS_TOKEN_CLASS_IMPERSONATION_LEVEL
	IntegrityLevel             Class = uapi.KACS_TOKEN_CLASS_INTEGRITY_LEVEL
	InteractivityScope         Class = uapi.KACS_TOKEN_CLASS_INTERACTIVITY_SCOPE
	LogonSID                   Class = uapi.KACS_TOKEN_CLASS_LOGON_SID
	LogonType                  Class = uapi.KACS_TOKEN_CLASS_LOGON_TYPE
	MandatoryPolicy            Class = uapi.KACS_TOKEN_CLASS_MANDATORY_POLICY
	Origin                     Class = uapi.KACS_TOKEN_CLASS_ORIGIN
	Owner                      Class = uapi.KACS_TOKEN_CLASS_OWNER
	PrimaryGroup               Class = uapi.KACS_TOKEN_CLASS_PRIMARY_GROUP
	ProjectedSupplementaryGIDs Class = uapi.KACS_TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS
	RestrictedSIDs             Class = uapi.KACS_TOKEN_CLASS_RESTRICTED_SIDS
	Source                     Class = uapi.KACS_TOKEN_CLASS_SOURCE
	TokenType                  Class = uapi.KACS_TOKEN_CLASS_TYPE
	UserClaims                 Class = uapi.KACS_TOKEN_CLASS_USER_CLAIMS
)

const (
	AllAccess                Access = uapi.KACS_TOKEN_ALL_ACCESS
	QuerySource              Access = uapi.KACS_TOKEN_QUERY_SOURCE
	AdjustInteractivityScope Access = uapi.KACS_TOKEN_ADJUST_INTERACTIVITY_SCOPE
	PrivilegeEnabled         uint32 = uapi.KACS_PRIVILEGE_ATTR_ENABLED
	PrivilegeRemoved         uint32 = uapi.KACS_PRIVILEGE_ATTR_REMOVED
)
