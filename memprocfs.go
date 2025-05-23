package go_memprocfs

import (
	"context"
	"unsafe"
)

type MemProcFS interface {
}

type ScatterTaskI interface {
	PrepareRead(ctx context.Context, address uint64, size uint32, buffer unsafe.Pointer) error
	ExecuteRead(ctx context.Context) error
	PrepareWrite(ctx context.Context, address uint64, size uint32, buffer unsafe.Pointer) error
	Execute(ctx context.Context) error
	Close(ctx context.Context) error
	Clear(ctx context.Context) error
}
