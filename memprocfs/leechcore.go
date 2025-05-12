package memprocfs

/*
#include "leechcore.h"
*/
import "C"
import (
	"unicode/utf16"
	"unsafe"
)

const (
	MemScatterVersion     = 0xc0fe0002
	MemScatterStackSize   = 12
	MemScatterAddrInvalid = ^uint64(0) // ((QWORD)-1)
)

type LCConfigErrorInfo struct {
	Version          uint32
	StructSize       uint32
	FutureUse        [16]uint32
	UserInputRequest bool
	TextLength       uint32
	Text             string
}

func newLCConfigErrorInfo(ppInfo C.PPLC_CONFIG_ERRORINFO) *LCConfigErrorInfo {
	cInfo := *(*C.LC_CONFIG_ERRORINFO)(*ppInfo)
	if cInfo == nil {
		return nil
	}

	info := &LCConfigErrorInfo{
		Version:          uint32(cInfo.dwVersion),
		StructSize:       uint32(cInfo.cbStruct),
		UserInputRequest: cInfo.fUserInputRequest != 0,
		TextLength:       uint32(cInfo.cwszUserText),
	}

	//  WCHAR* (uint16) -> Go string
	if info.TextLength > 0 {
		ptr := unsafe.Pointer(&cInfo.wszUserText[0])

		wcharSlice := (*[1 << 20]C.WCHAR)(ptr)[:info.TextLength:info.TextLength]

		u16 := make([]uint16, info.TextLength)
		for i := 0; i < int(info.TextLength); i++ {
			u16[i] = uint16(wcharSlice[i])
		}

		info.Text = string(utf16.Decode(u16))
	}

	return info
}

func freeMemory(ptr unsafe.Pointer) {
	if ptr != nil {
		C.LcMemFree(ptr)
	}
}

type MemScatter struct {
	cMem C.MEM_SCATTER
	buf  []byte // to keep reference to Go-side buffer, so GC doesn’t move it
}

func NewMemScatter(addr uint64, size uint32) *MemScatter {
	ms := &MemScatter{
		buf: make([]byte, size),
	}
	ms.cMem.version = C.DWORD(MemScatterVersion)
	ms.cMem.f = 0
	ms.cMem.qwA = C.QWORD(addr)
	ms.cMem.pb = (*C.uchar)(unsafe.Pointer(&ms.buf[0]))
	ms.cMem.cb = C.DWORD(size)
	ms.cMem.iStack = 0
	for i := 0; i < MemScatterStackSize; i++ {
		ms.cMem.vStack[i] = 0
	}
	return ms
}

func (m *MemScatter) Data() []byte {
	if m.cMem.f == 1 {
		return m.buf
	}
	return nil
}

func (m *MemScatter) Success() bool {
	return m.cMem.f == 1
}
