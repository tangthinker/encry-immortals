package cli

import (
	"flag"
	"fmt"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

type logEntry struct {
	Seq      uint64 `json:"seq"`
	TimeUnix int64  `json:"ts_unix"`
	Kind     string `json:"kind"`
	Msg      string `json:"msg"`
	Ops      int    `json:"ops"`
	Dirs     int    `json:"dirs"`
	Packs    int    `json:"packs"`
	Hashed   string `json:"journal_sha256"`
}

func kindName(k uint8) string {
	switch k {
	case wire.KindCheckpoint:
		return "checkpoint"
	case wire.KindNote:
		return "note"
	default:
		return "commit"
	}
}

func cmdLog(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	if err := parseInterspersed(fs, args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	s, err := a.openSession(g, true)
	if err != nil {
		return err
	}
	defer s.Close()
	layout, err := newLayout(s.cfg)
	if err != nil {
		return err
	}
	chain, err := journal.Load(layout, s.keys.Sub.Journal.Bytes(), s.keys.VaultID[:], journal.LoadOptions{})
	if err != nil {
		return err
	}
	entries := make([]logEntry, 0, len(chain.Files))
	for _, f := range chain.Files {
		entries = append(entries, logEntry{
			Seq:      f.Seq,
			TimeUnix: f.Body.TSUnix,
			Kind:     kindName(f.Body.Kind),
			Msg:      f.Body.Msg,
			Ops:      len(f.Body.Ops),
			Dirs:     len(f.Body.Dirs),
			Packs:    len(f.Body.Packs),
			Hashed:   shortHash(f.SHA256),
		})
	}
	return s.printJSONOrHuman(entries, func() {
		if len(entries) == 0 {
			fmt.Fprintln(s.stdout, "（还没有任何提交）")
			return
		}
		for _, e := range entries {
			ts := time.Unix(e.TimeUnix, 0).Format("2006-01-02 15:04:05")
			msg := e.Msg
			if msg == "" {
				msg = "-"
			}
			fmt.Fprintf(s.stdout, "%08d  %s  %-10s ops=%-5d dirs=%-3d packs=%-3d %s  %s\n",
				e.Seq, ts, e.Kind, e.Ops, e.Dirs, e.Packs, e.Hashed, msg)
		}
	})
}

func cmdShow(a *App, g *globalFlags, args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	if err := parseInterspersed(fs, args); err != nil {
		return apexerr.Wrap(err, apexerr.CodeUsage, "参数错误")
	}
	rawSeq := fs.Arg(0)
	if rawSeq == "" {
		return apexerr.New(apexerr.CodeUsage, "用法：eimmortal show <seq>")
	}
	seq, err := parseUintFlag(rawSeq, "seq")
	if err != nil {
		return err
	}
	s, err := a.openSession(g, true)
	if err != nil {
		return err
	}
	defer s.Close()
	layout, err := newLayout(s.cfg)
	if err != nil {
		return err
	}
	chain, err := journal.Load(layout, s.keys.Sub.Journal.Bytes(), s.keys.VaultID[:],
		journal.LoadOptions{TargetSeq: seq})
	if err != nil {
		return err
	}
	var found *journal.File
	for _, f := range chain.Files {
		if f.Seq == seq {
			found = f
			break
		}
	}
	if found == nil {
		return apexerr.Newf(apexerr.CodeUsage, "不存在 seq=%d 的提交", seq)
	}
	type opJSON struct {
		Type  string `json:"type"`
		Path  string `json:"path"`
		Mode  uint32 `json:"mode"`
		Size  uint64 `json:"size"`
		Extra string `json:"extra,omitempty"`
	}
	doc := struct {
		Seq   uint64   `json:"seq"`
		Time  int64    `json:"ts_unix"`
		Kind  string   `json:"kind"`
		Msg   string   `json:"msg"`
		Ops   []opJSON `json:"ops"`
		Dirs  int      `json:"dirs"`
		Packs int      `json:"packs"`
	}{
		Seq: found.Seq, Time: found.Body.TSUnix, Kind: kindName(found.Body.Kind),
		Msg: found.Body.Msg, Dirs: len(found.Body.Dirs), Packs: len(found.Body.Packs),
	}
	for _, op := range found.Body.Ops {
		doc.Ops = append(doc.Ops, opJSON{
			Type: op.Type.String(), Path: op.Path, Mode: op.Mode, Size: op.Size, Extra: op.Extra,
		})
	}
	return s.printJSONOrHuman(doc, func() {
		fmt.Fprintf(s.stdout, "seq %d  %s  %s\n", doc.Seq,
			time.Unix(doc.Time, 0).Format("2006-01-02 15:04:05"), doc.Kind)
		if doc.Msg != "" {
			fmt.Fprintf(s.stdout, "message: %s\n", doc.Msg)
		}
		fmt.Fprintf(s.stdout, "dirs=%d packs=%d ops=%d\n", doc.Dirs, doc.Packs, len(doc.Ops))
		for _, op := range doc.Ops {
			extra := ""
			if op.Extra != "" {
				extra = " -> " + op.Extra
			}
			fmt.Fprintf(s.stdout, "  %-8s %s %-10s %s%s\n", op.Type, modeString(op.Mode), humanBytes(int64(op.Size)), op.Path, extra)
		}
	})
}

func shortHash(h [32]byte) string {
	const hexdigits = "0123456789abcdef"
	buf := make([]byte, 8)
	for i := 0; i < 4; i++ {
		buf[i*2] = hexdigits[h[i]>>4]
		buf[i*2+1] = hexdigits[h[i]&0x0f]
	}
	return string(buf)
}
