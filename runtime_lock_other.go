//go:build !windows

package main

import (
	"os"
	"syscall"
)

// openRuntimeLockFile 用 flock 非阻塞独占锁防止同一目录启动第二个主程序。
func openRuntimeLockFile(path string) (*os.File, bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return nil, false, nil
		}
		return nil, false, err
	}
	return f, true, nil
}
