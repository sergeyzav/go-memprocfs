package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sergeyzav/go-memprocfs/memprocfs"
)

func main() {

	vmm, err := memprocfs.NewVmm("-device", "/Users/user/projects/go-memprocfs/examples/memdump.raw", "-v", "-printf", "-memmap", "/Users/user/GolandProjects/MemProcFsGolang/libs/memmap.txt")
	//vmm, err := memprocfs.NewVmm("-device", "/Users/user/Downloads/memdump.raw")
	//vmm, err := memprocfs.NewVmm("-device", "/Users/user/Downloads/memdump.raw", "-v", "-vv", "-vvv", "-printf")

	if err != nil {
		fmt.Println(err)
		return
	}

	defer vmm.Close()

	pid, err := vmm.GetPidByName(context.TODO(), "chrome.exe")

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("pid: ", pid)

	infoString, err := vmm.GetProcessInfoString(context.TODO(), pid, memprocfs.ProcessInformationOptStringPathKernel)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("info string path kernel: ", infoString)

	infoString, err = vmm.GetProcessInfoString(context.TODO(), pid, memprocfs.ProcessInformationOptStringPathUserImage)
	if err != nil {
		fmt.Println(err)
		//return
	}

	fmt.Println("info string user image: ", infoString)

	infoString, err = vmm.GetProcessInfoString(context.TODO(), pid, memprocfs.ProcessInformationOptStringCmdline)
	if err != nil {
		fmt.Println(err)
		//return
	}

	fmt.Println("info string cmd line: ", infoString)

	explorerPid, err := vmm.GetPidByName(context.TODO(), "explorer.exe")

	if err != nil {
		fmt.Println(err)
		//return
	} else {
		fmt.Println("explorer pid: ", explorerPid)
	}

	directories, err := vmm.GetProcessDirectories(context.TODO(), explorerPid, "kernel32.dll")
	if err != nil {
		fmt.Println(err)
		//return
	}

	for _, dictionary := range directories {
		fmt.Printf("dic: 0x%x, size: 0x%x\n", dictionary.VirtualAddress, dictionary.Size)
	}

	sections, err := vmm.GetProcessSections(context.TODO(), explorerPid, "kernel32.dll")
	if err != nil {
		fmt.Println(err)
		//return
	}

	for _, section := range sections {
		j, _ := json.Marshal(section)
		fmt.Printf("section: %s\n", j)
		//fmt.Printf("section: 0x%x, characteristics: 0x%x\n", section.VirtualAddress, section.Characteristics)
	}

	addr, err := vmm.GetProcessAddress(context.TODO(), explorerPid, "kernel32.dll", "LoadLibraryW")

	if err != nil {
		fmt.Println(err)
		//return
	} else {
		fmt.Printf("addr: 0x%x\n", addr)
	}

	addr, err = vmm.GetProcessModule(context.TODO(), explorerPid, "kernel32.dll")

	if err != nil {
		fmt.Println(err)
		//return
	} else {
		fmt.Printf("addr: 0x%x\n", addr)
	}

}
