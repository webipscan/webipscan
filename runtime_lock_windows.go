//go:build windows

package main

import (
	"os"
	"syscall"
)

// ERROR_SHARING_VIOLATION：文件已被其它进程以不兼容的共享模式打开。
const errorSharingViolation = syscall.Errno(32)

// openRuntimeLockFile 以 share=FILE_SHARE_READ 打开锁文件：
// 允许后来者只读查看 PID，但拒绝第二个可写句柄，保证同一目录只有一个主程序。
func openRuntimeLockFile(path string) (*os.File, bool, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, err
	}
	h, e := syscall.CreateFile(
		p,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if e != nil {
		if e == errorSharingViolation {
			return nil, false, nil
		}
		return nil, false, e
	}
	return os.NewFile(uintptr(h), path), true, nil
}
