//go:build windows

package main

import (
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	ariaTh32csSnapProcess                 = 0x00000002
	ariaJobObjectExtendedLimitInformation = 9
	ariaJobObjectLimitKillOnJobClose      = 0x00002000
	ariaProcessSetQuota                   = 0x0100
	ariaProcessTerminate                  = 0x0001
	ariaProcessSynchronize                = 0x00100000
)

var (
	ariaModKernel32            = syscall.NewLazyDLL("kernel32.dll")
	ariaProcToolhelpSnapshot   = ariaModKernel32.NewProc("CreateToolhelp32Snapshot")
	ariaProcProcess32First     = ariaModKernel32.NewProc("Process32FirstW")
	ariaProcProcess32Next      = ariaModKernel32.NewProc("Process32NextW")
	ariaProcCreateJobObject    = ariaModKernel32.NewProc("CreateJobObjectW")
	ariaProcSetJobInfo         = ariaModKernel32.NewProc("SetInformationJobObject")
	ariaProcAssignToJobObject  = ariaModKernel32.NewProc("AssignProcessToJobObject")
	ariaProcTerminateJobObject = ariaModKernel32.NewProc("TerminateJobObject")
)

// PROCESSENTRY32W，布局需与 Win32 结构体一致（Go 会自动插入指针对齐填充）。
type ariaProcessEntry32W struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

type ariaJobBasicLimitInfo struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ariaIOCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type ariaJobExtendedLimitInfo struct {
	BasicLimitInformation ariaJobBasicLimitInfo
	IoInfo                ariaIOCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// processRunningByName 通过 Toolhelp32 快照枚举进程名，不调用 tasklist 等外部程序。
func processRunningByName(names ...string) bool {
	snap, _, _ := ariaProcToolhelpSnapshot.Call(ariaTh32csSnapProcess, 0)
	if snap == 0 || snap == ^uintptr(0) {
		return false
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var entry ariaProcessEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))
	if r, _, _ := ariaProcProcess32First.Call(snap, uintptr(unsafe.Pointer(&entry))); r == 0 {
		return false
	}
	for {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		for _, want := range names {
			if strings.EqualFold(name, want) {
				return true
			}
		}
		if r, _, _ := ariaProcProcess32Next.Call(snap, uintptr(unsafe.Pointer(&entry))); r == 0 {
			return false
		}
	}
}

// watchAria2cChild 把 aria2c 放进带 KILL_ON_JOB_CLOSE 的 Job。
// 主程序退出时操作系统会关闭 Job 句柄并终止子进程，即使走 os.Exit 也不会残留。
func watchAria2cChild(cmd *exec.Cmd) func() {
	fallback := func() {
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	job, _, _ := ariaProcCreateJobObject.Call(0, 0)
	if job == 0 || job == ^uintptr(0) {
		return fallback
	}
	info := ariaJobExtendedLimitInfo{
		BasicLimitInformation: ariaJobBasicLimitInfo{
			LimitFlags: ariaJobObjectLimitKillOnJobClose,
		},
	}
	if r, _, _ := ariaProcSetJobInfo.Call(job, ariaJobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Sizeof(info))); r == 0 {
		syscall.CloseHandle(syscall.Handle(job))
		return fallback
	}

	ph, err := syscall.OpenProcess(
		ariaProcessSetQuota|ariaProcessTerminate|ariaProcessSynchronize,
		false, uint32(cmd.Process.Pid))
	if err != nil {
		syscall.CloseHandle(syscall.Handle(job))
		return fallback
	}
	defer syscall.CloseHandle(ph)
	if r, _, _ := ariaProcAssignToJobObject.Call(job, uintptr(ph)); r == 0 {
		syscall.CloseHandle(syscall.Handle(job))
		return fallback
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			ariaProcTerminateJobObject.Call(job, 1)
			syscall.CloseHandle(syscall.Handle(job))
		})
	}
}
