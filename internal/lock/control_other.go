//go:build !unix

package lock

import (
	"os"
	"path/filepath"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
)

// ControlLock is a best-effort exclusive lock on platforms without flock:
// an O_EXCL marker file removed on release. A crashed process leaves the file
// behind and the user must delete it (documented in the error text).
type ControlLock struct {
	path string
}

// AcquireControl creates <dir>/lock exclusively.
func AcquireControl(dir string) (*ControlLock, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "无法创建控制平面目录：%s", dir)
	}
	path := filepath.Join(dir, ControlLockName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil, apexerr.New(apexerr.CodeLocked, "另一个 eimmortal 进程正在使用该 vault").
				WithNext("确认无进程后删除 " + path)
		}
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "无法创建锁文件：%s", path)
	}
	f.Close()
	return &ControlLock{path: path}, nil
}

// Release removes the marker file.
func (c *ControlLock) Release() error {
	if c == nil || c.path == "" {
		return nil
	}
	if err := os.Remove(c.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	c.path = ""
	return nil
}
