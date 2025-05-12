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

// VMMDLL_MEMORYMODEL_TP constants
const (
	VMMDLL_MEMORYMODEL_NA     = 0
	VMMDLL_MEMORYMODEL_X86    = 1
	VMMDLL_MEMORYMODEL_X86PAE = 2
	VMMDLL_MEMORYMODEL_X64    = 3
	VMMDLL_MEMORYMODEL_ARM64  = 4
)

// VMMDLL_SYSTEM_TP constants
const (
	VMMDLL_SYSTEM_UNKNOWN_PHYSICAL = 0
	VMMDLL_SYSTEM_UNKNOWN_64       = 1
	VMMDLL_SYSTEM_WINDOWS_64       = 2
	VMMDLL_SYSTEM_UNKNOWN_32       = 3
	VMMDLL_SYSTEM_WINDOWS_32       = 4
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

	var pErrorInfo C.PPLC_CONFIG_ERRORINFO

	handle := C.VMMDLL_InitializeEx(argc, &cArgs[0], pErrorInfo)
	defer freeMemory(unsafe.Pointer(pErrorInfo))

	if handle == nil {
		info := newLCConfigErrorInfo(pErrorInfo)
		return nil, errors.New(info.Text)
	}

	return &Vmm{handle: handle}, nil
}

func (v *Vmm) Close() {
	if v.handle != nil {
		C.VMMDLL_Close(v.handle)
	}
}

func CloseAll() {
	C.VMMDLL_CloseAll()
}

// MemRead reads memory from the specified process
func (v *Vmm) MemRead(pid uint32, va uint64, size uint32) ([]byte, error) {
	buf := make([]byte, size)
	success := C.VMMDLL_MemRead(v.handle, C.DWORD(pid), C.ULONG64(va), (*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(size))
	if success == 0 {
		return nil, errors.New("failed to read memory")
	}

	return buf, nil
}

// MemReadEx reads memory with additional flags
func (v *Vmm) MemReadEx(pid uint32, va uint64, size uint32, flags uint64) ([]byte, uint32, error) {
	buf := make([]byte, size)
	var bytesRead uint32
	success := C.VMMDLL_MemReadEx(v.handle, C.DWORD(pid), C.ULONG64(va),
		(*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(size),
		(*C.DWORD)(unsafe.Pointer(&bytesRead)), C.ULONG64(flags))
	if success == 0 {
		return nil, 0, errors.New("failed to read memory")
	}
	return buf, bytesRead, nil
}

// MemWrite writes memory to the specified process
func (v *Vmm) MemWrite(pid uint32, va uint64, data []byte) error {
	success := C.VMMDLL_MemWrite(v.handle, C.DWORD(pid), C.ULONG64(va),
		(*C.BYTE)(unsafe.Pointer(&data[0])), C.DWORD(len(data)))
	if success == 0 {
		return errors.New("failed to write memory")
	}
	return nil
}

// MemVirt2Phys converts virtual address to physical address
func (v *Vmm) MemVirt2Phys(pid uint32, va uint64) (uint64, error) {
	var pa uint64
	success := C.VMMDLL_MemVirt2Phys(v.handle, C.DWORD(pid), C.ULONG64(va), (*C.ULONG64)(unsafe.Pointer(&pa)))
	if success == 0 {
		return 0, errors.New("failed to convert virtual address to physical")
	}
	return pa, nil
}

// MemReadScatter reads memory in a scattered way

// ConfigGet gets a configuration value
func (v *Vmm) ConfigGet(option uint64) (uint64, error) {
	var value uint64
	success := C.VMMDLL_ConfigGet(v.handle, C.ULONG64(option), (*C.ULONG64)(unsafe.Pointer(&value)))
	if success == 0 {
		return 0, errors.New("failed to get config")
	}
	return value, nil
}

// ConfigSet sets a configuration value
func (v *Vmm) ConfigSet(option uint64, value uint64) error {
	success := C.VMMDLL_ConfigSet(v.handle, C.ULONG64(option), C.ULONG64(value))
	if success == 0 {
		return errors.New("failed to set config")
	}
	return nil
}
