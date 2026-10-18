package cli

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/term"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
)

// password obtains the master password without ever accepting it on the command
// line (spec 10.4).
func (a *App) password(g *globalFlags, prompt string, confirm bool) ([]byte, error) {
	var pw []byte
	var err error
	switch {
	case g.passwordFD >= 0:
		pw, err = readPasswordFD(g.passwordFD)
	case g.passwordFile != "":
		pw, err = readPasswordFile(g.passwordFile)
	case a.PasswordReader != nil:
		pw, err = a.PasswordReader(prompt)
	default:
		pw, err = a.readPasswordTTY(prompt)
	}
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		return nil, apexerr.New(apexerr.CodeUsage, "主密码不能为空")
	}
	if confirm {
		if err := a.confirmPassword(pw, g); err != nil {
			zero(pw)
			return nil, err
		}
	}
	return pw, nil
}

func (a *App) confirmPassword(first []byte, g *globalFlags) error {
	if g.passwordFD >= 0 || g.passwordFile != "" || a.PasswordReader != nil {
		return nil // non-interactive sources are unambiguous
	}
	second, err := a.readPasswordTTY("请再次输入主密码：")
	if err != nil {
		return err
	}
	defer zero(second)
	if string(first) != string(second) {
		return apexerr.New(apexerr.CodeUsage, "两次输入的主密码不一致")
	}
	return nil
}

func (a *App) readPasswordTTY(prompt string) ([]byte, error) {
	fd := a.Stdin.Fd()
	if !term.IsTerminal(int(fd)) {
		return nil, apexerr.New(apexerr.CodeUsage, "当前不是交互式终端，无法读取主密码").
			WithNext("使用 --password-fd <n> 或 --password-file <path>")
	}
	fmt.Fprint(a.Stderr, prompt)
	raw, err := term.ReadPassword(int(fd))
	fmt.Fprintln(a.Stderr)
	if err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeUsage, "读取主密码失败")
	}
	return raw, nil
}

func readPasswordFD(fd int) ([]byte, error) {
	f := os.NewFile(uintptr(fd), "password-fd")
	if f == nil {
		return nil, apexerr.Newf(apexerr.CodeUsage, "无效的 --password-fd：%d", fd)
	}
	defer f.Close()
	return readLine(f)
}

func readPasswordFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "无法读取密码文件：%s", path)
	}
	// Windows has no POSIX mode bits: os.Stat reports 0666 for every writable
	// file, so a 0600 check would reject any password file. Access there is
	// enforced by ACLs, which FileMode cannot express.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, apexerr.Newf(apexerr.CodeUsage, "密码文件权限过宽：%s（%o）", path, info.Mode().Perm()).
			WithNext("执行 chmod 600 " + path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeUsage, "无法读取密码文件：%s", path)
	}
	return trimNewline(raw), nil
}

func readLine(f *os.File) ([]byte, error) {
	buf := make([]byte, 0, 256)
	one := make([]byte, 1)
	for {
		n, err := f.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				break
			}
			buf = append(buf, one[0])
			if len(buf) > 4096 {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return trimNewline(buf), nil
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
