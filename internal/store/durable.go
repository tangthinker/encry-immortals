package store

import (
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
)

// FsyncDir flushes a directory entry change (spec §05.1: mandatory before and
// after a rename that makes data visible).
func FsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return apexerr.Wrapf(err, apexerr.CodeInternal, "无法打开目录以 fsync：%s", dir)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		// Windows can open directories but cannot flush them reliably (§05.8).
		if runtime.GOOS == "windows" {
			return nil
		}
		return apexerr.Wrapf(err, apexerr.CodeInternal, "目录 fsync 失败：%s", dir)
	}
	return nil
}

// RenameDurable renames from -> to and fsyncs the destination directory.
func RenameDurable(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "原子移动失败：%s -> %s", from, to)
	}
	return FsyncDir(dirOf(to))
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if os.IsPathSeparator(p[i]) {
			if i == 0 {
				return string(p[0])
			}
			return p[:i]
		}
	}
	return "."
}

// CommitStaged fsyncs a fully written staging file, closes it, then atomically
// publishes it at finalPath and fsyncs the destination directory (§05.1 S2/S3,
// S5/S6).
func CommitStaged(f *os.File, stagingPath, finalPath string) error {
	if err := f.Sync(); err != nil {
		f.Close()
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法刷盘：%s", stagingPath)
	}
	if err := f.Close(); err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法关闭：%s", stagingPath)
	}
	if err := os.MkdirAll(dirOf(finalPath), 0o755); err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建目标目录：%s", dirOf(finalPath))
	}
	return RenameDurable(stagingPath, finalPath)
}

// WriteFileDurable writes data to path via a staging file in stagingDir.
func WriteFileDurable(stagingDir, finalPath string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建暂存目录：%s", stagingDir)
	}
	tmp, err := os.CreateTemp(stagingDir, "apex-staged-*")
	if err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建暂存文件")
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpPath)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "写入暂存文件失败")
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return apexerr.Wrapf(err, apexerr.CodeInternal, "设置暂存文件权限失败")
	}
	if err := CommitStaged(tmp, tmpPath, finalPath); err != nil {
		cleanup()
		return err
	}
	return nil
}

// CopyFile copies src to dst, fsyncing the destination file.
func CopyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return apexerr.Wrapf(err, apexerr.CodeInternal, "无法打开 %s", src)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建 %s", dst)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return apexerr.Wrapf(err, apexerr.CodeNoSpace, "写入 %s 失败", dst)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return apexerr.Wrap(err, apexerr.CodeNoSpace, fmt.Sprintf("刷盘失败：%s", dst))
	}
	return out.Close()
}

// SweepStaging removes staging leftovers older than maxAge (§01.2 / §06.2).
// It only ever touches files directly inside the staging directory.
func SweepStaging(stagingDir string, now int64, maxAgeSeconds int64) (removed int, bytes int64, err error) {
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, apexerr.Wrapf(err, apexerr.CodeInternal, "无法读取暂存目录：%s", stagingDir)
	}
	for _, e := range entries {
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		if now-info.ModTime().Unix() < maxAgeSeconds {
			continue
		}
		if rerr := os.RemoveAll(stagingDir + string(os.PathSeparator) + e.Name()); rerr != nil {
			continue
		}
		removed++
		bytes += info.Size()
	}
	return removed, bytes, nil
}
