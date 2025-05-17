package memprocfs

/*
#include "vmmdll.h"
#include "leechcore.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

// Special PID to enable kernel memory access
const (
	PidProcessWithKernelMemory = 0x80000000
)

// Flags for memory read operations and behavior tuning
const (
	FlagNoCache                   = 0x0001 // Do not use the data cache (force direct memory reads)
	FlagZeroPadOnFail             = 0x0002 // Zero-pad failed physical memory reads if within physical memory range
	FlagForceCacheRead            = 0x0008 // Force use of cache; fail if page isn't cached (invalid with NoCache / ZeroPadOnFail)
	FlagNoPaging                  = 0x0010 // Do not try to read paged-out memory from pagefile/compressed memory
	FlagNoPagingIO                = 0x0020 // Do not trigger I/O operations to fetch paged-out memory
	FlagNoCachePut                = 0x0100 // Do not write successful memory reads back to cache
	FlagCacheRecentOnly           = 0x0200 // Only fetch from the most recent active cache region
	FlagNoPredictiveRead          = 0x0400 // (Deprecated/unused)
	FlagForceCacheReadDisable     = 0x0800 // Disable any use of ForceCacheRead; only recommended for local files
	FlagScatterPrepareExNoMemZero = 0x1000 // Do not zero out memory buffer before scatter read
	FlagNoMemCallback             = 0x2000 // Disable memory callback functions during memory reads
	FlagScatterForcePageRead      = 0x4000 // Force page-sized reads when using scatter functionality
)

// Memory read/write flags
const (
	VMMDLL_MEM_FLAG_NONE            = 0x00000000
	VMMDLL_MEM_FLAG_ZEROPAD_ON_FAIL = 0x00000001
	VMMDLL_MEM_FLAG_CACHE_READ      = 0x00000002
	VMMDLL_MEM_FLAG_NOCACHE         = 0x00000004
	VMMDLL_MEM_FLAG_NOCACHEPUT      = 0x00000008
	VMMDLL_MEM_FLAG_NOPAGING        = 0x00000010
	VMMDLL_MEM_FLAG_NOPAGING_IO     = 0x00000020
)

type vmmHandle C.VMM_HANDLE

type Vmm struct {
	handle vmmHandle
}

var defaultArgs = []string{"-device", "fpga"}

func NewVmm(args ...string) (*Vmm, error) {
	if len(args) == 0 {
		args = defaultArgs
	}
	cArgs := make([]C.LPCSTR, len(args))
	for i, s := range args {
		cArgs[i] = C.CString(s)
		defer C.free(unsafe.Pointer(cArgs[i]))
	}

	argc := C.DWORD(len(args))

	handle := C.VMMDLL_Initialize(argc, &cArgs[0])
	if handle == nil {
		return nil, errors.New("VMM initialization failed")
	}

	return &Vmm{handle: vmmHandle(handle)}, nil
}

func (v *Vmm) Close() {
	if v.handle == nil {
		return
	}

	go C.VMMDLL_Close(v.handle)
}

func CloseAll() {
	C.VMMDLL_CloseAll()
}

// MemReadScatter reads memory in a scattered way

func (v *Vmm) NewScatterTask(pid uint32, flags uint32) (*ScatterTask, error) {
	return InitializeScatter(v, pid, flags)
}

func freeMemory(ptr C.PVOID) {
	if ptr != nil {
		C.VMMDLL_MemFree(ptr)
	}
}

func getMemSize(ptr C.PVOID) uint64 {
	if ptr == nil {
		return 0
	}

	return uint64(C.VMMDLL_MemSize(ptr))
}
