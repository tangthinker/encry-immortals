package journal

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/tangthinker/encry-immortals/internal/wire"
)

// TestChainLoadScaling measures the cost that checkpoints would remove.
//
// It exists to answer a design question with numbers instead of intuition:
// how expensive is "verify + replay every journal" as the vault grows?
func TestChainLoadScaling(t *testing.T) {
	if testing.Short() || os.Getenv("EIMMORTAL_SCALE_TEST") == "" {
		t.Skip("scaling measurement: run with EIMMORTAL_SCALE_TEST=1 go test ./internal/journal -run TestChainLoadScaling -v")
	}
	cases := []struct {
		journals int
		opsEach  int
	}{
		{100, 10},
		{500, 10},
		{1000, 10},
		{1000, 100},
		{2000, 10},
	}
	for _, c := range cases {
		l := newLayout(t)
		prev := GenesisHash
		start := time.Now()
		for seq := 1; seq <= c.journals; seq++ {
			ops := make([]wire.Op, 0, c.opsEach)
			for k := 0; k < c.opsEach; k++ {
				ops = append(ops, addOp(fmt.Sprintf("dir%d/file%05d-%03d.txt", seq%50, seq, k)))
			}
			prev = writeJournal(t, l, uint64(seq), prev, ops)
		}
		build := time.Since(start)

		start = time.Now()
		chain, err := Load(l, testJournalKey, testVaultID, LoadOptions{})
		if err != nil {
			t.Fatalf("journals=%d: %v", c.journals, err)
		}
		load := time.Since(start)
		t.Logf("journals=%-5d ops/journal=%-4d total_ops=%-7d build=%-8s load=%-8s tree_nodes=%d",
			c.journals, c.opsEach, c.journals*c.opsEach,
			build.Round(time.Millisecond), load.Round(time.Millisecond), chain.Tree.Len())
	}
}
