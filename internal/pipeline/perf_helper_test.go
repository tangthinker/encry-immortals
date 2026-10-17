package pipeline

import (
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/store"
)

func journalLoadForPerf(l *store.Layout) (*journal.Chain, error) {
	return journal.Load(l, testKeys.Sub.Journal.Bytes(), testKeys.VaultID[:], journal.LoadOptions{})
}
