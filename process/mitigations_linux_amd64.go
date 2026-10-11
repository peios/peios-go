package process

import "github.com/peios/peios-go/internal/uapi"

const (
	MitigationAll      uint32 = uapi.KACS_MIT_ALL
	MitigationCFI      uint32 = uapi.KACS_MIT_CFI
	MitigationCFIB     uint32 = uapi.KACS_MIT_CFIB
	MitigationCFIF     uint32 = uapi.KACS_MIT_CFIF
	MitigationLSV      uint32 = uapi.KACS_MIT_LSV
	MitigationNoChild  uint32 = uapi.KACS_MIT_NO_CHILD
	MitigationPIE      uint32 = uapi.KACS_MIT_PIE
	MitigationSML      uint32 = uapi.KACS_MIT_SML
	MitigationTLP      uint32 = uapi.KACS_MIT_TLP
	MitigationUIAccess uint32 = uapi.KACS_MIT_UI_ACCESS
	MitigationWXP      uint32 = uapi.KACS_MIT_WXP
)
