// Package lock implements the three-layer writer exclusion of spec 01.4 / D-15:
// a process-level flock on the control plane, a cross-host .apex.lock file in
// TargetDir, and (in the store) O_EXCL journal creation plus strict seq order.
package lock

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
)

// File names owned by the lock layer.
const (
	TargetLockName  = ".apex.lock"
	ControlLockName = "lock"
)

// TargetInfo is the JSON payload of <TargetDir>/.apex.lock.
type TargetInfo struct {
	HostID      string `json:"host_id"`
	PID         int    `json:"pid"`
	BootID      string `json:"boot_id"`
	StartedUnix int64  `json:"started_unix"`
	ToolVersion string `json:"tool_version"`
}

// NewTargetInfo fills the lock record for this process.
func NewTargetInfo(toolVersion string) TargetInfo {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	return TargetInfo{
		HostID:      host,
		PID:         os.Getpid(),
		BootID:      readBootID(),
		StartedUnix: time.Now().Unix(),
		ToolVersion: toolVersion,
	}
}

// TargetLock is the held cross-host lock.
type TargetLock struct {
	path string
	info TargetInfo
}

// AcquireTargetLock creates <TargetDir>/.apex.lock with O_EXCL.
//
// A pre-existing lock is a hard stop: spec 01.4 explicitly refuses to guess
// whether the other host is dead.
func AcquireTargetLock(targetDir string, info TargetInfo) (*TargetLock, error) {
	path := filepath.Join(targetDir, TargetLockName)
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法序列化锁记录")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if os.IsExist(err) {
			other, rerr := ReadTargetLock(targetDir)
			if rerr != nil {
				return nil, apexerr.New(apexerr.CodeLocked, "检测到 TargetDir 已存在 .apex.lock，但无法读取其内容").
					WithScope("可能是另一个 apex 进程或另一台主机正在写入").
					WithNext("确认无人写入后执行 apex backup --break-lock")
			}
			return nil, apexerr.Newf(apexerr.CodeLocked,
				"检测到另一台主机正在写入：host=%s pid=%d started=%s boot=%s",
				other.HostID, other.PID, time.Unix(other.StartedUnix, 0).Format(time.RFC3339), other.BootID).
				WithScope("同一 TargetDir 只允许一个写者（D-15）").
				WithNext("如确认该主机已失效，执行 apex backup --break-lock")
		}
		return nil, apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建锁文件：%s", path)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return nil, apexerr.Wrap(err, apexerr.CodeNoSpace, "写入锁文件失败")
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return nil, apexerr.Wrap(err, apexerr.CodeNoSpace, "刷盘锁文件失败")
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, apexerr.Wrap(err, apexerr.CodeNoSpace, "关闭锁文件失败")
	}
	return &TargetLock{path: path, info: info}, nil
}

// Release removes the lock file.
func (t *TargetLock) Release() error {
	if t == nil {
		return nil
	}
	if err := os.Remove(t.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Info returns the record this lock was created with.
func (t *TargetLock) Info() TargetInfo { return t.info }

// ReadTargetLock parses an existing lock file.
func ReadTargetLock(targetDir string) (*TargetInfo, error) {
	raw, err := os.ReadFile(filepath.Join(targetDir, TargetLockName))
	if err != nil {
		return nil, err
	}
	var info TargetInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("锁文件内容非法：%w", err)
	}
	return &info, nil
}

// BreakTargetLock removes the lock file unconditionally (spec 01.4: no inference).
func BreakTargetLock(targetDir string) error {
	path := filepath.Join(targetDir, TargetLockName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return apexerr.Wrapf(err, apexerr.CodeInternal, "无法删除锁文件：%s", path)
	}
	return nil
}
