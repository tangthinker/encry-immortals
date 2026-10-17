// Package cli implements the eimmortal command surface (spec 10).
//
// Output contract (§10.6): human progress goes to stderr, result data to stdout.
// Exit codes are the stable contract of §10.5.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/config"
	"github.com/tangthinker/encry-immortals/internal/index"
	"github.com/tangthinker/encry-immortals/internal/lock"
	"github.com/tangthinker/encry-immortals/internal/vault"
)

// Version is reported by "eimmortal version".
var Version = "0.1.0-dev"

// App is the CLI runtime. Fields are injectable for tests.
type App struct {
	Stdout         io.Writer
	Stderr         io.Writer
	Stdin          *os.File
	PasswordReader func(prompt string) ([]byte, error)
}

// globalFlags are accepted anywhere on the command line.
type globalFlags struct {
	configPath   string
	vaultDir     string
	json         bool
	debug        bool
	passwordFD   int
	passwordFile string
}

type command struct {
	name         string
	summary      string
	writesTarget bool
	run          func(a *App, g *globalFlags, args []string) error
}

var commands = map[string]*command{}

func register(c *command) { commands[c.name] = c }

// Run executes one command line and returns the process exit code.
func (a *App) Run(args []string) int {
	if a.Stdout == nil {
		a.Stdout = os.Stdout
	}
	if a.Stderr == nil {
		a.Stderr = os.Stderr
	}
	if a.Stdin == nil {
		a.Stdin = os.Stdin
	}
	registerAll()
	g, rest, err := parseGlobalFlags(args)
	if err != nil {
		a.fail(err)
		return apexerr.ExitCode(err)
	}
	if len(rest) == 0 || rest[0] == "help" || rest[0] == "--help" || rest[0] == "-h" {
		a.printUsage()
		return apexerr.ExitOK
	}
	cmd, ok := commands[rest[0]]
	if !ok {
		a.fail(apexerr.Newf(apexerr.CodeUsage, "未知命令：%s", rest[0]).WithNext("执行 eimmortal help 查看可用命令"))
		return apexerr.ExitUsage
	}
	if err := cmd.run(a, g, rest[1:]); err != nil {
		a.fail(err)
		return apexerr.ExitCode(err)
	}
	return apexerr.ExitOK
}

func (a *App) fail(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(a.Stderr, err.Error())
}

func (a *App) printUsage() {
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("eimmortal " + Version + " — 加密增量备份（网盘盲盒化）\n\n")
	b.WriteString("用法：eimmortal [全局选项] <命令> [命令选项]\n\n命令（★ 表示会写入 TargetDir）：\n")
	for _, n := range names {
		c := commands[n]
		mark := " "
		if c.writesTarget {
			mark = "★"
		}
		b.WriteString(fmt.Sprintf("  %s %-14s %s\n", mark, n, c.summary))
	}
	b.WriteString("\n全局选项：\n")
	b.WriteString("  --config <path>       配置文件（默认 ~/.config/eimmortal/config.toml）\n")
	b.WriteString("  --vault <dir>         控制平面目录（默认 ~/.config/eimmortal-vault）\n")
	b.WriteString("  --json                结果输出为 JSON（人类进度仍走 stderr）\n")
	b.WriteString("  --password-fd <n>     从文件描述符读取主密码（非交互场景）\n")
	b.WriteString("  --password-file <p>   从 0600 权限的文件读取主密码\n")
	fmt.Fprint(a.Stdout, b.String())
}

func parseGlobalFlags(args []string) (*globalFlags, []string, error) {
	g := &globalFlags{passwordFD: -1}
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", apexerr.Newf(apexerr.CodeUsage, "%s 缺少取值", arg)
			}
			i++
			return args[i], nil
		}
		switch {
		case arg == "--config":
			v, err := next()
			if err != nil {
				return nil, nil, err
			}
			g.configPath = v
		case strings.HasPrefix(arg, "--config="):
			g.configPath = strings.TrimPrefix(arg, "--config=")
		case arg == "--vault":
			v, err := next()
			if err != nil {
				return nil, nil, err
			}
			g.vaultDir = v
		case strings.HasPrefix(arg, "--vault="):
			g.vaultDir = strings.TrimPrefix(arg, "--vault=")
		case arg == "--json":
			g.json = true
		case arg == "--debug":
			g.debug = true
		case arg == "--password-fd":
			v, err := next()
			if err != nil {
				return nil, nil, err
			}
			if _, err := fmt.Sscanf(v, "%d", &g.passwordFD); err != nil {
				return nil, nil, apexerr.Newf(apexerr.CodeUsage, "--password-fd 不是整数：%s", v)
			}
		case strings.HasPrefix(arg, "--password-fd="):
			if _, err := fmt.Sscanf(strings.TrimPrefix(arg, "--password-fd="), "%d", &g.passwordFD); err != nil {
				return nil, nil, apexerr.New(apexerr.CodeUsage, "--password-fd 不是整数")
			}
		case arg == "--password-file":
			v, err := next()
			if err != nil {
				return nil, nil, err
			}
			g.passwordFile = v
		case strings.HasPrefix(arg, "--password-file="):
			g.passwordFile = strings.TrimPrefix(arg, "--password-file=")
		default:
			rest = append(rest, arg)
		}
	}
	if g.passwordFD < 0 {
		if v := firstEnv("EIMMORTAL_PASSWORD_FD", "APEX_PASSWORD_FD"); v != "" {
			if _, err := fmt.Sscanf(v, "%d", &g.passwordFD); err != nil {
				return nil, nil, apexerr.New(apexerr.CodeUsage, "EIMMORTAL_PASSWORD_FD 不是整数")
			}
		}
	}
	return g, rest, nil
}

// session bundles the unlocked control plane for one command.
type session struct {
	cfg      *config.Config
	vaultDir string
	meta     *vault.Meta
	keys     *vault.Keys
	db       *index.DB
	lock     *lock.ControlLock
	stdout   io.Writer
	stderr   io.Writer
	json     bool
	app      *App
}

func (s *session) progress(format string, args ...any) {
	fmt.Fprintf(s.stderr, format+"\n", args...)
}

func (s *session) Close() {
	if s.keys != nil {
		s.keys.Destroy()
	}
	if s.db != nil {
		s.db.Close()
	}
	if s.lock != nil {
		s.lock.Release()
	}
}

func (s *session) emitJSON(v any) error {
	enc := json.NewEncoder(s.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (s *session) printJSONOrHuman(v any, human func()) error {
	if s.json {
		return s.emitJSON(v)
	}
	human()
	return nil
}

// openSession locks the control plane, loads vault.meta and opens state.db.
func (a *App) openSession(g *globalFlags, needKeys bool) (*session, error) {
	cfg, err := config.Load(g.configPath)
	if err != nil {
		return nil, err
	}
	vaultDir := g.vaultDir
	if vaultDir == "" {
		vaultDir = cfg.Vault.Dir
	}
	if vaultDir == "" {
		return nil, apexerr.New(apexerr.CodeUsage, "未配置控制平面目录")
	}
	if err := os.MkdirAll(vaultDir, vault.DirPerm); err != nil {
		return nil, apexerr.Wrapf(err, apexerr.CodeNoSpace, "无法创建控制平面目录：%s", vaultDir)
	}
	s := &session{cfg: cfg, vaultDir: vaultDir, stdout: a.Stdout, stderr: a.Stderr, json: g.json, app: a}
	lk, err := lock.AcquireControl(vaultDir)
	if err != nil {
		return nil, err
	}
	s.lock = lk
	meta, err := vault.LoadMeta(vaultDir)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.meta = meta
	db, err := index.Open(vaultDir)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.db = db
	if err := s.bindCache(); err != nil {
		s.Close()
		return nil, err
	}
	if !needKeys {
		return s, nil
	}
	pw, err := a.password(g, "请输入主密码：", false)
	if err != nil {
		s.Close()
		return nil, err
	}
	keys, err := meta.Unlock(pw)
	zero(pw)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.keys = keys
	return s, nil
}

// bindCache drops a state.db that belongs to a different vault (spec 05.7).
func (s *session) bindCache() error {
	stored, ok, err := s.db.VaultID()
	if err != nil {
		return err
	}
	want, err := s.meta.VaultIDBytes()
	if err != nil {
		return err
	}
	if ok && string(stored) == string(want) {
		return nil
	}
	if err := s.db.Reset(); err != nil {
		return err
	}
	return s.db.SetVaultID(want)
}

// firstEnv returns the first non-empty environment variable (legacy fallbacks
// exist so that scripts written before the rename keep working).
func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}
