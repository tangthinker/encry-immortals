// Package journal verifies the encrypted journal chain and replays it into a
// virtual file tree (spec 04.3–04.5, 05.6).
package journal

import (
	"crypto/sha256"
	"sort"
	"strings"

	"github.com/tangthinker/encry-immortals/internal/wire"
)

// GenesisHash is the fixed prev_hash of seq=1 (spec 04.3).
var GenesisHash = sha256.Sum256([]byte("APEX-JOURNAL-GENESIS-v3"))

// Kind is the node type in the virtual tree.
type Kind uint8

// Node kinds.
const (
	KindFile Kind = iota
	KindDir
	KindSymlink
)

// Node is one entry of the replayed tree.
type Node struct {
	Path          string
	Kind          Kind
	Mode          uint32
	Size          uint64
	ModTimeNS     int64
	ContentSHA256 [32]byte
	Slices        []wire.SliceRef
	// PackNames parallels Slices: the relative pack path for each slice, so a
	// reader never has to re-resolve the writer's pack_idx.
	PackNames []string
	// TxnID is the transaction that wrote these slices (bound into the AAD).
	TxnID      [16]byte
	LinkTarget string
}

// Tree is the deterministic replay result.
type Tree struct {
	nodes map[string]*Node
	// Packs maps pack relative name to its fingerprint, accumulated from every
	// journal that referenced it (D-05).
	Packs map[string]wire.PackRef
	// PackTxn maps pack name to the transaction that wrote it (I2).
	PackTxn map[string][16]byte
}

// NewTree returns an empty tree.
func NewTree() *Tree {
	return &Tree{
		nodes:   make(map[string]*Node),
		Packs:   make(map[string]wire.PackRef),
		PackTxn: make(map[string][16]byte),
	}
}

// Get returns a node by path.
func (t *Tree) Get(path string) (*Node, bool) {
	n, ok := t.nodes[path]
	return n, ok
}

// Put inserts or replaces a node.
func (t *Tree) Put(n *Node) { t.nodes[n.Path] = n }

// Remove deletes a node.
func (t *Tree) Remove(path string) { delete(t.nodes, path) }

// Len reports the number of nodes.
func (t *Tree) Len() int { return len(t.nodes) }

// HasChildren reports whether any node lives below dir.
func (t *Tree) HasChildren(dir string) bool {
	prefix := dir + "/"
	for p := range t.nodes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// Paths returns every path sorted ascending.
func (t *Tree) Paths() []string {
	out := make([]string, 0, len(t.nodes))
	for p := range t.nodes {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// NodesByKind returns nodes of one kind sorted by path.
func (t *Tree) NodesByKind(kind Kind) []*Node {
	var out []*Node
	for _, n := range t.nodes {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Files returns file nodes sorted by path.
func (t *Tree) Files() []*Node { return t.NodesByKind(KindFile) }

// Dirs returns directory nodes sorted by path.
func (t *Tree) Dirs() []*Node { return t.NodesByKind(KindDir) }

// Links returns symlink nodes sorted by path.
func (t *Tree) Links() []*Node { return t.NodesByKind(KindSymlink) }

// LegalTree paths are the ones that can be restored. Kept as a helper so tests
// can compare trees without depending on map ordering.
func (t *Tree) Snapshot() []Node {
	out := make([]Node, 0, len(t.nodes))
	for _, p := range t.Paths() {
		out = append(out, *t.nodes[p])
	}
	return out
}
