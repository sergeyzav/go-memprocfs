package memprocfs

import (
	"bytes"
	"unsafe"
)

func cString(ptr unsafe.Pointer, size int) string {
	bytesArr := (*[1 << 20]byte)(ptr)[:size:size] // max 1 MB safety
	last := bytes.IndexByte(bytesArr, 0)
	if last == -1 {
		last = size
	}
	return string(bytesArr[:last])
}
