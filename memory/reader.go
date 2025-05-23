package memory

import (
	memprocfs "github.com/sergeyzav/memprocfs"
)

type VmmReader struct {
	vmm       *memprocfs.Vmm
	pid       uint32
	baseAddr  uint64
	readFlags memprocfs.VMMFlag
}

func NewVmmReader(vmm *memprocfs.Vmm, baseAddr uint64, readFlags memprocfs.VMMFlag) *VmmReader {
	return &VmmReader{
		vmm:       vmm,
		baseAddr:  baseAddr,
		readFlags: readFlags,
	}
}

func (v *VmmReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	n, err := v.vmm.MemReadEx(v.pid, v.baseAddr, p, v.readFlags)
	if err != nil {
		return 0, err
	}

	v.baseAddr += uint64(n)
	return int(n), nil
}
