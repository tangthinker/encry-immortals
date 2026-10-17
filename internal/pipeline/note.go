package pipeline

import (
	"crypto/sha256"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	"github.com/tangthinker/encry-immortals/internal/codec"
	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
	"github.com/tangthinker/encry-immortals/internal/journal"
	"github.com/tangthinker/encry-immortals/internal/store"
	"github.com/tangthinker/encry-immortals/internal/vault"
	"github.com/tangthinker/encry-immortals/internal/wire"
)

// NoteOptions drives "apex note" (spec 04.7: a kind=2 journal with no ops).
type NoteOptions struct {
	Layout  *store.Layout
	Keys    *vault.Keys
	Params  wire.VaultParams
	Message string
	Codec   codec.Options
	Now     func() time.Time
}

// WriteNote appends one annotation journal and returns its sequence and hash.
func WriteNote(opts NoteOptions) (uint64, [32]byte, error) {
	var zero [32]byte
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if opts.Message == "" {
		return 0, zero, apexerr.New(apexerr.CodeUsage, "apex note 需要一个非空的消息")
	}
	chain, err := journal.Load(opts.Layout, opts.Keys.Sub.Journal.Bytes(), opts.Keys.VaultID[:], journal.LoadOptions{})
	if err != nil {
		return 0, zero, err
	}
	maxSeq, err := opts.Layout.MaxSeq()
	if err != nil {
		return 0, zero, err
	}
	if maxSeq != chain.LastSeq {
		return 0, zero, apexerr.Newf(apexerr.CodeLocked,
			"journal 链在本次运行期间发生了变化：内存 seq=%d，磁盘 seq=%d", chain.LastSeq, maxSeq)
	}
	txnRaw, err := randomTxn()
	if err != nil {
		return 0, zero, err
	}
	prev := journal.GenesisHash
	if chain.LastSeq > 0 {
		prev = chain.LastSHA
	}
	seq := maxSeq + 1
	j := &wire.Journal{
		FormatVersion: wire.JournalFormatVersion,
		Seq:           seq,
		TxnID:         txnRaw,
		TSUnix:        now().Unix(),
		Msg:           opts.Message,
		PrevHash:      prev,
		Flags:         wire.JournalFlagFinal,
		Kind:          wire.KindNote,
		Params:        opts.Params,
	}
	body, err := wire.EncodeJournalBody(j)
	if err != nil {
		return 0, zero, apexerr.From(err)
	}
	raw, err := wire.SealJournalFileWithOptions(opts.Keys.Sub.Journal.Bytes(), seq, opts.Keys.VaultID[:], body, opts.Codec)
	if err != nil {
		return 0, zero, apexerr.From(err)
	}
	abs, err := opts.Layout.AbsPath(opts.Layout.JournalRelPath(seq))
	if err != nil {
		return 0, zero, err
	}
	if err := store.WriteFileDurableAs(opts.Layout.StagingDir,
		opts.Layout.JournalName(seq)+".tmp", abs, raw, 0o644); err != nil {
		return 0, zero, err
	}
	return seq, sha256.Sum256(raw), nil
}

func randomTxn() ([16]byte, error) {
	var out [16]byte
	b, err := vaultcrypto.RandomBytes(16)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}
