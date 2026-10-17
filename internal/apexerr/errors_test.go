package apexerr

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitMappingIsStable(t *testing.T) {
	cases := []struct {
		code Code
		exit int
	}{
		{CodeInternal, 1},
		{CodeUsage, 2},
		{CodeUnlock, 10},
		{CodeChain, 11},
		{CodeCorrupt, 12},
		{CodeIncomplete, 13},
		{CodeNoSpace, 14},
		{CodeArmor, 12},
		{CodeLocked, 20},
		{CodeUnsupported, 21},
		{CodeInterrupted, 130},
	}
	for _, c := range cases {
		if got := ExitFor(c.code); got != c.exit {
			t.Errorf("ExitFor(%s) = %d, want %d", c.code, got, c.exit)
		}
		if got := ExitCode(New(c.code, "x")); got != c.exit {
			t.Errorf("ExitCode(New(%s)) = %d, want %d", c.code, got, c.exit)
		}
	}
}

func TestErrorFormat(t *testing.T) {
	e := New(CodeCorrupt, "切片解密失败：data/2026-03/pack_x.dat 偏移 32 处 MAC 校验不通过。").
		WithScope("该文件可能无法还原").
		WithNext("apex verify --deep").
		WithErr(errors.New("cipher: message authentication failed"))
	want := "E12 切片解密失败：data/2026-03/pack_x.dat 偏移 32 处 MAC 校验不通过。影响：该文件可能无法还原。建议：apex verify --deep（cipher: message authentication failed）"
	if got := e.Error(); got != want {
		t.Fatalf("Error() = %q\nwant      %q", got, want)
	}
}

func TestExitCode(t *testing.T) {
	if got := ExitCode(nil); got != ExitOK {
		t.Errorf("ExitCode(nil) = %d", got)
	}
	if got := ExitCode(errors.New("boom")); got != ExitInternal {
		t.Errorf("ExitCode(plain) = %d", got)
	}
	wrapped := fmt.Errorf("ctx: %w", New(CodeChain, "链断裂"))
	if got := ExitCode(wrapped); got != ExitChain {
		t.Errorf("ExitCode(wrapped) = %d, want %d", got, ExitChain)
	}
	if CodeOf(wrapped) != CodeChain {
		t.Errorf("CodeOf(wrapped) = %s", CodeOf(wrapped))
	}
	if got := ExitCode(From(errors.New("boom"))); got != ExitInternal {
		t.Errorf("ExitCode(From(plain)) = %d", got)
	}
}

func TestCopiesDoNotMutateOriginal(t *testing.T) {
	base := New(CodeUsage, "bad flag")
	withNext := base.WithNext("run apex --help")
	if base.Next != "" {
		t.Fatalf("base was mutated: %q", base.Next)
	}
	if withNext.Next == "" {
		t.Fatal("copy lost the next step")
	}
}
