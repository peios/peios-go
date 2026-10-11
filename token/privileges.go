package token

import "github.com/peios/peios-go/internal/uapi"

// Privilege masks for Spec and Restriction. Adjustment LUIDs are bit indices.
const (
	PrivilegeAssignPrimaryToken   uint64 = uapi.KACS_SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE
	PrivilegeAudit                uint64 = uapi.KACS_SE_AUDIT_PRIVILEGE
	PrivilegeBackup               uint64 = uapi.KACS_SE_BACKUP_PRIVILEGE
	PrivilegeChangeNotify         uint64 = uapi.KACS_SE_CHANGE_NOTIFY_PRIVILEGE
	PrivilegeCreateSymbolicLink   uint64 = uapi.KACS_SE_CREATE_SYMBOLIC_LINK_PRIVILEGE
	PrivilegeCreateToken          uint64 = uapi.KACS_SE_CREATE_TOKEN_PRIVILEGE
	PrivilegeDebug                uint64 = uapi.KACS_SE_DEBUG_PRIVILEGE
	PrivilegeImpersonate          uint64 = uapi.KACS_SE_IMPERSONATE_PRIVILEGE
	PrivilegeIncreaseBasePriority uint64 = uapi.KACS_SE_INCREASE_BASE_PRIORITY_PRIVILEGE
	PrivilegeIncreaseQuota        uint64 = uapi.KACS_SE_INCREASE_QUOTA_PRIVILEGE
	PrivilegeLoadDriver           uint64 = uapi.KACS_SE_LOAD_DRIVER_PRIVILEGE
	PrivilegeLockMemory           uint64 = uapi.KACS_SE_LOCK_MEMORY_PRIVILEGE
	PrivilegeManageVolume         uint64 = uapi.KACS_SE_MANAGE_VOLUME_PRIVILEGE
	PrivilegeProfileSingleProcess uint64 = uapi.KACS_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE
	PrivilegeRelabel              uint64 = uapi.KACS_SE_RELABEL_PRIVILEGE
	PrivilegeRemoteShutdown       uint64 = uapi.KACS_SE_REMOTE_SHUTDOWN_PRIVILEGE
	PrivilegeRestore              uint64 = uapi.KACS_SE_RESTORE_PRIVILEGE
	PrivilegeSecurity             uint64 = uapi.KACS_SE_SECURITY_PRIVILEGE
	PrivilegeShutdown             uint64 = uapi.KACS_SE_SHUTDOWN_PRIVILEGE
	PrivilegeSystemTime           uint64 = uapi.KACS_SE_SYSTEMTIME_PRIVILEGE
	PrivilegeSystemProfile        uint64 = uapi.KACS_SE_SYSTEM_PROFILE_PRIVILEGE
	PrivilegeTakeOwnership        uint64 = uapi.KACS_SE_TAKE_OWNERSHIP_PRIVILEGE
	PrivilegeTCB                  uint64 = uapi.KACS_SE_TCB_PRIVILEGE
)
