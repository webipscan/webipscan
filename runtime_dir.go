package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// userDataDirName 仅在无法从 exe 文件名推导目录名时作为兜底。
const userDataDirName = "webipscan"

var (
	// runtimeDir 是 aria2c.exe、mb132_x64.dll 及 aria2c 数据文件的统一存放目录。
	runtimeDir string
	// runtimeUserMode 标记当前是否处于用户模式。
	runtimeUserMode bool
)

// dirWritable 通过在目录中创建并删除临时文件判断该目录是否可写。
func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".webipscan-write-test-")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// userDataRoot 返回用户目录下的主启动目录：目录名取当前 exe 的文件名（去掉扩展名）。
// 例如 webipscan.exe 对应 %USERPROFILE%\webipscan。
func userDataRoot() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("获取 exe 路径失败：%w", err)
	}
	base := strings.TrimSuffix(filepath.Base(exe), filepath.Ext(exe))
	if base == "" || base == "." || base == ".." {
		base = userDataDirName
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("获取用户目录失败：%w", err)
	}
	if home == "" {
		return "", fmt.Errorf("获取用户目录失败：路径为空")
	}
	p := filepath.Join(home, base)
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return p, nil
}

// initRuntimeDir 在解析启动参数后调用，确定运行时文件目录。
//
// 默认即用户模式（包括不带任何参数启动）：aria2c.exe 与 mb132_x64.dll 都从
// %USERPROFILE%\<exe 文件名> 释放并加载，DLL 的加载目录随该路径一起切换。
// 仅当显式指定 --no-user / --no-user-mode 或环境变量 WEBIPSCAN_USER_MODE=0 时，
// 才回退到 exe 所在目录；用户目录不可用时同样自动回退。
func initRuntimeDir(disableUser bool) {
	exeDir := "."
	if exe, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exe)
	}
	if abs, err := filepath.Abs(exeDir); err == nil {
		exeDir = abs
	}

	userMode := !disableUser && os.Getenv("WEBIPSCAN_USER_MODE") != "0"
	if userMode {
		if p, err := userDataRoot(); err == nil {
			if err := os.MkdirAll(p, 0755); err == nil && dirWritable(p) {
				runtimeDir, runtimeUserMode = p, true
				return
			}
		}
	}

	runtimeDir, runtimeUserMode = exeDir, false
}

// runtimeDirLabel 返回便于打印的模式说明。
func runtimeDirLabel() string {
	if runtimeUserMode {
		return "用户模式（用户目录 " + runtimeDir + "）"
	}
	return "普通模式（程序目录 " + runtimeDir + "）"
}
