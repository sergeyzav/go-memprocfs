package memprocfs

/*
#include "vmmdll.h"
*/
import "C"
import (
	"context"
	"errors"
	"fmt"
	"unsafe"
)

type scatterHandle C.VMMDLL_SCATTER_HANDLE

type ScatterTask struct {
	handle scatterHandle
	pid    uint32
	flags  uint32
}

var ErrScatterInitFailed = errors.New("failed to initialize scatter handle")

func InitializeScatter(vmm *Vmm, pid uint32, flags uint32) (*ScatterTask, error) {
	h := C.VMMDLL_Scatter_Initialize(C.VMM_HANDLE(vmm.handle), C.DWORD(pid), C.DWORD(flags))
	if h == nil {
		return nil, ErrScatterInitFailed
	}
	return &ScatterTask{handle: scatterHandle(h), pid: pid, flags: flags}, nil
}

func (s *ScatterTask) Close(ctx context.Context) {
	done := make(chan bool, 1)

	go func() {
		C.VMMDLL_Scatter_CloseHandle(C.VMMDLL_SCATTER_HANDLE(s.handle))
		done <- true
	}()

	select {
	case <-ctx.Done():
		return
	case <-done:
		return
	}
}

func (s *ScatterTask) Clear(ctx context.Context) bool {
	resultChan := make(chan bool, 1)

	go func() {
		success := C.VMMDLL_Scatter_Clear(C.VMMDLL_SCATTER_HANDLE(s.handle), C.DWORD(s.pid), C.DWORD(s.flags))
		resultChan <- success != 0
	}()

	select {
	case <-ctx.Done():
		return false
	case result := <-resultChan:
		return result
	}
}

func (s *ScatterTask) Prepare(ctx context.Context, address uint64, size uint32, buffer unsafe.Pointer) error {
	errChan := make(chan error, 1)

	go func() {
		success := C.VMMDLL_Scatter_PrepareEx(C.VMMDLL_SCATTER_HANDLE(s.handle), C.QWORD(address), C.DWORD(size), C.PBYTE(buffer), nil)

		if success == 0 {
			errChan <- errors.New("VMMDLL_Scatter_PrepareEx: failed to prepare scatter")
		} else {
			errChan <- nil
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errChan:
		return err
	}
}

func (s *ScatterTask) Execute(ctx context.Context) error {
	errChan := make(chan error, 1)

	go func() {
		success := C.VMMDLL_Scatter_ExecuteRead(C.VMMDLL_SCATTER_HANDLE(s.handle))

		if success == 0 {
			errChan <- fmt.Errorf("failed to execute scatter read")
		} else {
			errChan <- nil
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errChan:
		return err
	}
}
