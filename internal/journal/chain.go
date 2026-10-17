package journal

import (
	"crypto/sha256"
	"os"
	"path/filepath"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/store"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

// File is one decrypted journal file.
type File struct {
	Seq     uint64
	RelPath string
	Raw     []byte
	SHA256  [32]byte
	Body    *wire.Journal
}

// Chain is the verified journal history plus its replayed tree.
type Chain struct {
	Files   []*File
	Tree    *Tree
	LastSeq uint64
	LastSHA [32]byte
}

// LoadOptions controls chain loading.
type LoadOptions struct {
	// TargetSeq stops the chain at this sequence (0 = latest). Spec 05.6's
	// snapshot travel maps onto this.
	TargetSeq uint64
	// Progress is called once per decrypted journal.
	Progress func(done, total int)
	// AllowIncompleteChain downgrades a "journal missing in the middle" error to
	// a truncation at the gap; only recovery flows use it.
	AllowIncompleteChain bool
}

// Load decrypts, authenticates and replays every journal up to the target.
//
// Verification order matters: seq file-name check -> AEAD (seq in AAD) ->
// body.Seq check -> prev_hash chain -> replay. Each failure maps to E11/E12.
func Load(layout *store.Layout, journalKey, vaultID []byte, opts LoadOptions) (*Chain, error) {
	seqs, err := layout.ListJournals()
	if err != nil {
		return nil, err
	}
	chain := &Chain{Tree: NewTree()}
	if len(seqs) == 0 {
		return chain, nil
	}
	maxSeq := seqs[len(seqs)-1]
	target := opts.TargetSeq
	if target == 0 || target > maxSeq {
		target = maxSeq
	}

	var selected []uint64
	for _, s := range seqs {
		if s <= target {
			selected = append(selected, s)
		}
	}
	// I10: sequences must be contiguous from 1.
	for i, s := range selected {
		if s != uint64(i+1) {
			if opts.AllowIncompleteChain {
				selected = selected[:i]
				break
			}
			return nil, apexerr.Newf(apexerr.CodeChain,
				"哈希链断裂：缺少 seq=%d 的 journal（现有下一个是 %d）", i+1, s).
				WithScope("从该点之后的历史都不再可信").
				WithNext("用 eimmortal doctor --chain 定位；若确定是从云端丢失，只能恢复到 seq=" + itoa(uint64(i)))
		}
	}

	prevHash := GenesisHash
	for i, seq := range selected {
		rel := layout.JournalRelPath(seq)
		abs, err := layout.AbsPath(rel)
		if err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(filepath.Clean(abs))
		if err != nil {
			return nil, apexerr.Wrapf(err, apexerr.CodeIncomplete, "无法读取 %s", rel)
		}
		sum := sha256.Sum256(raw)
		body, err := wire.OpenJournalFile(journalKey, seq, vaultID, raw)
		if err != nil {
			return nil, apexerr.From(err).WithScope(rel + " 无法解密或已损坏")
		}
		j, err := wire.DecodeJournalBody(body)
		if err != nil {
			return nil, apexerr.From(err).WithScope(rel + " 的明文结构非法")
		}
		if j.Seq != seq {
			return nil, apexerr.Newf(apexerr.CodeChain,
				"%s 内部 seq=%d 与文件名不一致", rel, j.Seq).
				WithNext("该 journal 可能被重命名或替换，执行 eimmortal doctor --chain")
		}
		if j.PrevHash != prevHash {
			return nil, apexerr.Newf(apexerr.CodeChain,
				"哈希链断裂于 seq=%d：prev_hash 与前一个 journal 不匹配", seq).
				WithScope("这通常意味着 seq=" + itoa(seq-1) + " 的 journal 被替换或损坏").
				WithNext("执行 eimmortal doctor --chain")
		}
		chain.Files = append(chain.Files, &File{Seq: seq, RelPath: rel, Raw: raw, SHA256: sum, Body: j})
		prevHash = sum
		if opts.Progress != nil {
			opts.Progress(i+1, len(selected))
		}
	}

	if err := chain.replay(); err != nil {
		return nil, err
	}
	if len(chain.Files) > 0 {
		last := chain.Files[len(chain.Files)-1]
		chain.LastSeq = last.Seq
		chain.LastSHA = last.SHA256
	}
	return chain, nil
}

// replay applies every journal in order.
func (c *Chain) replay() error {
	tree := NewTree()
	for _, f := range c.Files {
		if f.Body.Kind == wire.KindCheckpoint {
			tree = NewTree()
			for _, d := range f.Body.Dirs {
				tree.Put(&Node{Path: d.Path, Kind: KindDir, Mode: d.Mode, ModTimeNS: d.ModTimeNS})
			}
			for _, n := range f.Body.Tree {
				node := &Node{
					Path: n.Path, Kind: KindFile, Mode: n.Mode, Size: n.Size,
					ModTimeNS: n.ModTimeNS, ContentSHA256: n.ContentSHA256, Slices: n.Slices,
				}
				for _, s := range n.Slices {
					if int(s.PackIdx) >= len(f.Body.Packs) {
						return apexerr.Newf(apexerr.CodeCorrupt, "checkpoint seq=%d 引用了不存在的 pack 下标 %d", f.Seq, s.PackIdx)
					}
					name := f.Body.Packs[s.PackIdx].Name
					node.PackNames = append(node.PackNames, name)
					if txn, ok := tree.PackTxn[name]; ok {
						node.TxnID = txn
					} else {
						return apexerr.Newf(apexerr.CodeCorrupt,
							"checkpoint seq=%d 引用的 pack %s 没有可追溯的 transaction", f.Seq, name)
					}
				}
				tree.Put(node)
			}
		}
		for _, p := range f.Body.Packs {
			if existing, ok := tree.Packs[p.Name]; ok && existing.SHA256 != p.SHA256 {
				return apexerr.Newf(apexerr.CodeCorrupt,
					"pack %s 被多个不同的 transaction 引用且指纹不同（违反 I2）", p.Name)
			}
			tree.Packs[p.Name] = p
			if txn, ok := tree.PackTxn[p.Name]; ok && txn != f.Body.TxnID {
				return apexerr.Newf(apexerr.CodeCorrupt,
					"pack %s 被多个 transaction 引用（违反 I2）", p.Name)
			}
			tree.PackTxn[p.Name] = f.Body.TxnID
		}
		if err := applyOps(tree, f.Body); err != nil {
			return err
		}
	}
	c.Tree = tree
	return nil
}

// applyOps implements the deterministic replay table (spec 04.5).
func applyOps(tree *Tree, j *wire.Journal) error {
	for _, d := range j.Dirs {
		if n, ok := tree.Get(d.Path); ok && n.Kind == KindDir {
			n.Mode = d.Mode
			n.ModTimeNS = d.ModTimeNS
			continue
		}
		tree.Put(&Node{Path: d.Path, Kind: KindDir, Mode: d.Mode, ModTimeNS: d.ModTimeNS})
	}
	for _, op := range j.Ops {
		switch op.Type {
		case wire.OpAdd, wire.OpModify:
			node := &Node{
				Path: op.Path, Kind: KindFile, Mode: op.Mode, Size: op.Size,
				ModTimeNS: op.ModTimeNS, ContentSHA256: op.ContentSHA256, Slices: op.Slices,
				TxnID: j.TxnID,
			}
			for _, s := range op.Slices {
				if int(s.PackIdx) >= len(j.Packs) {
					return apexerr.Newf(apexerr.CodeCorrupt,
						"seq=%d 的切片引用了不存在的 pack 下标 %d", j.Seq, s.PackIdx)
				}
				node.PackNames = append(node.PackNames, j.Packs[s.PackIdx].Name)
			}
			tree.Put(node)
		case wire.OpDelete:
			tree.Remove(op.Path)
		case wire.OpMkdir:
			tree.Put(&Node{Path: op.Path, Kind: KindDir, Mode: op.Mode, ModTimeNS: op.ModTimeNS})
		case wire.OpRmdir:
			if tree.HasChildren(op.Path) {
				return apexerr.Newf(apexerr.CodeCorrupt,
					"seq=%d 的 RMDIR %s 作用于非空目录", j.Seq, op.Path).
					WithScope("写入端应保证 RMDIR 之前已发出所有 DELETE")
			}
			tree.Remove(op.Path)
		case wire.OpSymlink:
			tree.Put(&Node{
				Path: op.Path, Kind: KindSymlink, Mode: op.Mode,
				ModTimeNS: op.ModTimeNS, LinkTarget: op.Extra,
			})
		case wire.OpMeta:
			if n, ok := tree.Get(op.Path); ok {
				n.Mode = op.Mode
				n.ModTimeNS = op.ModTimeNS
			}
		default:
			return apexerr.Newf(apexerr.CodeCorrupt, "seq=%d 含未知 op_type %d", j.Seq, op.Type)
		}
	}
	return nil
}

// itoa formats a uint64 without dragging strconv into error paths.
func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
