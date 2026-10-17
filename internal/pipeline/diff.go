// Package pipeline implements the backup and restore state machines
// (spec 05.1 S0–S7, 05.6).
package pipeline

import (
	"path"
	"sort"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/scan"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

// HashFunc returns the content SHA-256 of a source file.
type HashFunc func(absPath string) ([32]byte, error)

// Stats counts one diff.
type Stats struct {
	Added    int
	Modified int
	Deleted  int
	Meta     int
	Dirs     int
	Links    int
}

// Changed reports whether the diff would produce a journal (I8).
func (s Stats) Changed() bool {
	return s.Added+s.Modified+s.Deleted+s.Meta+s.Dirs+s.Links > 0
}

// Diff is the ordered operation list for one commit.
type Diff struct {
	Ops   []wire.Op
	Dirs  []wire.DirEntry
	Stats Stats
}

// ComputeDiff compares the replayed tree with a fresh scan.
//
// Ordering is part of the protocol (spec 04.5): DELETE, then RMDIR (deepest
// first), then MKDIR (shallowest first), then content-bearing ops.
func ComputeDiff(tree *journal.Tree, scanned *scan.Result, strict bool, hash HashFunc) (*Diff, error) {
	d := &Diff{}
	seen := make(map[string]scan.Entry, len(scanned.Entries))
	for _, e := range scanned.Entries {
		seen[e.Path] = e
	}

	var deletes, rmdirs, mkdirs, writes []wire.Op

	// Removals: everything in the tree that the scan no longer sees.
	for _, n := range tree.Snapshot() {
		switch n.Kind {
		case journal.KindFile:
			if e, ok := seen[n.Path]; !ok || e.Kind != scan.KindFile {
				deletes = append(deletes, wire.Op{Type: wire.OpDelete, Path: n.Path, Mode: n.Mode})
				d.Stats.Deleted++
			}
		case journal.KindSymlink:
			if e, ok := seen[n.Path]; !ok || e.Kind != scan.KindSymlink {
				deletes = append(deletes, wire.Op{Type: wire.OpDelete, Path: n.Path, Mode: n.Mode})
				d.Stats.Deleted++
			}
		case journal.KindDir:
			if e, ok := seen[n.Path]; !ok || e.Kind != scan.KindDir {
				rmdirs = append(rmdirs, wire.Op{Type: wire.OpRmdir, Path: n.Path, Mode: n.Mode})
			}
		}
	}

	for _, e := range scanned.Entries {
		switch e.Kind {
		case scan.KindDir:
			node, ok := tree.Get(e.Path)
			if !ok || node.Kind != journal.KindDir {
				mkdirs = append(mkdirs, mkdirOp(e))
				d.Dirs = append(d.Dirs, dirEntry(e))
				d.Stats.Dirs++
				continue
			}
			if node.Mode != e.Mode || node.ModTimeNS != e.ModTimeNS {
				mkdirs = append(mkdirs, mkdirOp(e))
				d.Dirs = append(d.Dirs, dirEntry(e))
				d.Stats.Dirs++
			}
		case scan.KindSymlink:
			node, ok := tree.Get(e.Path)
			if !ok || node.Kind != journal.KindSymlink || node.LinkTarget != e.LinkTarget {
				writes = append(writes, wire.Op{
					Type: wire.OpSymlink, Path: e.Path, Mode: e.Mode, ModTimeNS: e.ModTimeNS,
					Extra: e.LinkTarget,
				})
				d.Stats.Links++
			}
		case scan.KindFile:
			node, ok := tree.Get(e.Path)
			if !ok || node.Kind != journal.KindFile {
				writes = append(writes, wire.Op{
					Type: wire.OpAdd, Path: e.Path, Mode: e.Mode, Size: uint64(e.Size),
					ModTimeNS: e.ModTimeNS,
				})
				d.Stats.Added++
				continue
			}
			unchanged := node.Size == uint64(e.Size) && node.ModTimeNS == e.ModTimeNS
			if unchanged {
				if node.Mode != e.Mode {
					writes = append(writes, metaOp(e))
					d.Stats.Meta++
				}
				continue
			}
			if strict && hash != nil {
				sum, err := hash(e.Path)
				if err != nil {
					return nil, err
				}
				if sum == node.ContentSHA256 {
					writes = append(writes, metaOp(e))
					d.Stats.Meta++
					continue
				}
			}
			writes = append(writes, wire.Op{
				Type: wire.OpModify, Path: e.Path, Mode: e.Mode, Size: uint64(e.Size),
				ModTimeNS: e.ModTimeNS,
			})
			d.Stats.Modified++
		}
	}

	sort.Slice(deletes, func(i, j int) bool { return deletes[i].Path < deletes[j].Path })
	sort.Slice(rmdirs, func(i, j int) bool {
		di, dj := depth(rmdirs[i].Path), depth(rmdirs[j].Path)
		if di != dj {
			return di > dj
		}
		return rmdirs[i].Path > rmdirs[j].Path
	})
	sort.Slice(mkdirs, func(i, j int) bool {
		di, dj := depth(mkdirs[i].Path), depth(mkdirs[j].Path)
		if di != dj {
			return di < dj
		}
		return mkdirs[i].Path < mkdirs[j].Path
	})
	sort.Slice(writes, func(i, j int) bool { return writes[i].Path < writes[j].Path })

	// RMDIR may only be emitted for directories that end up empty.
	remaining := make(map[string]bool, len(rmdirs))
	for _, n := range tree.Snapshot() {
		if n.Kind == journal.KindDir {
			remaining[n.Path] = true
		}
	}
	for _, e := range scanned.Entries {
		if e.Kind == scan.KindDir {
			remaining[e.Path] = true
		}
	}
	for _, op := range rmdirs {
		for p := range remaining {
			if isChild(op.Path, p) {
				return nil, apexerr.Newf(apexerr.CodeCorrupt,
					"内部错误：目录 %s 在提交后仍非空，却准备发出 RMDIR", op.Path)
			}
		}
		d.Ops = append(d.Ops, op)
		d.Stats.Dirs++
	}
	d.Ops = append(d.Ops, deletes...)
	d.Ops = append(d.Ops, mkdirs...)
	d.Ops = append(d.Ops, writes...)
	sort.Slice(d.Dirs, func(i, j int) bool { return d.Dirs[i].Path < d.Dirs[j].Path })
	return d, nil
}

func metaOp(e scan.Entry) wire.Op {
	return wire.Op{
		Type: wire.OpMeta, Path: e.Path, Mode: e.Mode, Size: uint64(e.Size), ModTimeNS: e.ModTimeNS,
	}
}

func mkdirOp(e scan.Entry) wire.Op {
	return wire.Op{Type: wire.OpMkdir, Path: e.Path, Mode: e.Mode, ModTimeNS: e.ModTimeNS}
}

func dirEntry(e scan.Entry) wire.DirEntry {
	return wire.DirEntry{Path: e.Path, Mode: e.Mode, ModTimeNS: e.ModTimeNS}
}

func depth(p string) int { return len(splitPath(p)) }

func splitPath(p string) []string {
	var out []string
	start := 0
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			out = append(out, p[start:i])
			start = i + 1
		}
	}
	return append(out, p[start:])
}

func isChild(dir, p string) bool {
	return len(p) > len(dir) && p[:len(dir)] == dir && p[len(dir)] == '/'
}

var _ = path.Base
