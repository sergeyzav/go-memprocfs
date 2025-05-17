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

func boolToInt(b bool) int {
	var i int
	if b {
		i = 1
	} else {
		i = 0
	}
	return i
}

func multiString(data []byte) []string {
	var result []string
	parts := bytes.Split(data, []byte{0})

	for _, part := range parts {
		if len(part) > 0 {
			result = append(result, string(part))
		}
	}
	return result
}

/**
todo: VMMDLL_Log
*/
