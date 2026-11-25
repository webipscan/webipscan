package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// runtimeLockFileName 是以 runtimeDir 为粒度的主程序独占锁文件。
const runtimeLockFileName = ".webipscan-main.lock"

// runtimeLock 持有运行时目录的独占锁。
// 文件句柄需保持到进程退出，由操作系统在进程结束时自动释放锁。
type runtimeLock struct {
	file *os.File
	path string
}

// anotherInstanceError 表示同一 runtimeDir 已有主程序运行。
type anotherInstanceError struct {
	dir string
	pid int
}

func (e *anotherInstanceError) Error() string {
	if e.pid > 0 {
		return fmt.Sprintf("运行时目录 %s 已有主程序在运行（PID %d）", e.dir, e.pid)
	}
	return fmt.Sprintf("运行时目录 %s 已有主程序在运行", e.dir)
}

// tryLockRuntimeDir 尝试独占 dir，成功后把当前 PID 写入锁文件供后来者识别。
// 目录已被占用时返回 *anotherInstanceError，其它失败返回原始错误。
func tryLockRuntimeDir(dir string) (*runtimeLock, error) {
	path := filepath.Join(dir, runtimeLockFileName)
	f, acquired, err := openRuntimeLockFile(path)
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, &anotherInstanceError{dir: dir, pid: readRuntimeLockPID(path)}
	}

	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	_ = f.Sync()
	return &runtimeLock{file: f, path: path}, nil
}

// readRuntimeLockPID 读取锁文件中记录的主程序 PID，读不到时返回 0。
func readRuntimeLockPID(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}
