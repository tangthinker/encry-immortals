//go:build unix

package lock

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
)

// ControlLock is the process-level exclusive lock on the control plane.
type ControlLock struct {
	f    *os.File
	path string
}

// AcquireControl takes flock(LOCK_EX|LOCK_NB) on <dir>/lock.
func AcquireControl(dir string) (*ControlLock, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "无法创建控制平面目录：%s", dir)
	}
	path := filepath.Join(dir, ControlLockName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "无法打开锁文件：%s", path)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, apexerr.New(apexerr.CodeLocked, "另一个 apex 进程正在使用该 vault（flock 获取失败）").
			WithNext("等待该进程结束；若确认没有其他进程，检查 " + path)
	}
	return &ControlLock{f: f, path: path}, nil
}

// Release unlocks and closes the file.
func (c *ControlLock) Release() error {
	if c == nil || c.f == nil {
		return nil
	}
	_ = syscall.Flock(int(c.f.Fd()), syscall.LOCK_UN)
	err := c.f.Close()
	c.f = nil
	return err
}
