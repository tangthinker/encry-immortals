// Package index is the local state.db cache (spec 05.7 / D-13).
//
// It is a pure cache: every row must be reconstructible from the journals
// (invariant I14). It stores only HMACs of paths, never plaintext paths (I13).
package index

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"time"

	"github.com/tangthinker/encry-immortals/internal/apexerr"
	_ "modernc.org/sqlite" // pure-Go SQLite driver (ADR-003)
)

// SchemaVersion is bumped only for incompatible changes.
const SchemaVersion = "1"

// Meta keys used by the rest of apex.
const (
	MetaVaultID        = "vault_id"
	MetaLastSeq        = "last_seq"
	MetaSchemaVersion  = "schema_version"
	MetaParamsSnapshot = "params_snapshot"
	MetaLastExportUnix = "last_export_unix"
	MetaLastDrillUnix  = "last_drill_unix"
	MetaUnverified     = "unverified_restore"
)

var schemaSQL = []string{
	`CREATE TABLE IF NOT EXISTS meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS anchor (
		seq INTEGER PRIMARY KEY,
		journal_sha256 BLOB NOT NULL,
		mac BLOB NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS entries (
		path_hmac BLOB PRIMARY KEY,
		size INTEGER NOT NULL,
		mtime_ns INTEGER NOT NULL,
		ctime_ns INTEGER NOT NULL,
		content_sha256 BLOB NOT NULL,
		last_seq INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS dirs (
		path_hmac BLOB PRIMARY KEY,
		mode INTEGER NOT NULL,
		last_seq INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS checkpoints (
		seq INTEGER PRIMARY KEY
	)`,
}

// DB wraps state.db.
type DB struct {
	sql  *sql.DB
	path string
}

// Entry is one cached file record, keyed by HMAC(PathKey, path).
type Entry struct {
	PathHMAC      [32]byte
	Size          int64
	MtimeNS       int64
	CtimeNS       int64
	ContentSHA256 [32]byte
	LastSeq       uint64
}

// Dir is one cached directory record.
type Dir struct {
	PathHMAC [32]byte
	Mode     uint32
	LastSeq  uint64
}

// Anchor is the local anti-rollback anchor (§04.3).
type Anchor struct {
	Seq        uint64
	JournalSHA [32]byte
	MAC        [32]byte
}

// Open opens (creating if needed) <dir>/state.db with WAL and synchronous=FULL.
func Open(dir string) (*DB, error) {
	path := filepath.Join(dir, "state.db")
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法打开 state.db")
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, apexerr.Wrap(err, apexerr.CodeInternal, "无法连接 state.db")
	}
	for _, stmt := range schemaSQL {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, apexerr.Wrap(err, apexerr.CodeInternal, "初始化 state.db 表结构失败")
		}
	}
	d := &DB{sql: db, path: path}
	if err := d.SetMeta(MetaSchemaVersion, SchemaVersion); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

// Path returns the database file path.
func (d *DB) Path() string { return d.path }

// Close closes the database.
func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

// SetMeta stores a key/value pair.
func (d *DB) SetMeta(key, value string) error {
	_, err := d.sql.Exec(`INSERT INTO meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	if err != nil {
		return apexerr.Wrapf(err, apexerr.CodeInternal, "写入 state.db meta(%s) 失败", key)
	}
	return nil
}

// Meta reads a key/value pair.
func (d *DB) Meta(key string) (string, bool, error) {
	var v string
	err := d.sql.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, apexerr.Wrapf(err, apexerr.CodeInternal, "读取 state.db meta(%s) 失败", key)
	}
	return v, true, nil
}

// SetVaultID records which vault owns this cache (spec 05.7).
func (d *DB) SetVaultID(id []byte) error {
	return d.SetMeta(MetaVaultID, base64.RawURLEncoding.EncodeToString(id))
}

// VaultID returns the recorded vault id.
func (d *DB) VaultID() ([]byte, bool, error) {
	v, ok, err := d.Meta(MetaVaultID)
	if err != nil || !ok {
		return nil, false, err
	}
	b, derr := base64.RawURLEncoding.DecodeString(v)
	if derr != nil {
		return nil, false, nil
	}
	return b, true, nil
}

// SetLastSeq records the highest committed sequence.
func (d *DB) SetLastSeq(seq uint64) error {
	return d.SetMeta(MetaLastSeq, fmt.Sprintf("%d", seq))
}

// LastSeq returns the recorded sequence (0 when unset).
func (d *DB) LastSeq() (uint64, error) {
	v, ok, err := d.Meta(MetaLastSeq)
	if err != nil || !ok {
		return 0, err
	}
	var seq uint64
	if _, err := fmt.Sscanf(v, "%d", &seq); err != nil {
		return 0, nil
	}
	return seq, nil
}

// PutEntry upserts a file record.
func (d *DB) PutEntry(e Entry) error {
	_, err := d.sql.Exec(`INSERT INTO entries(path_hmac, size, mtime_ns, ctime_ns, content_sha256, last_seq)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(path_hmac) DO UPDATE SET
			size=excluded.size, mtime_ns=excluded.mtime_ns, ctime_ns=excluded.ctime_ns,
			content_sha256=excluded.content_sha256, last_seq=excluded.last_seq`,
		e.PathHMAC[:], e.Size, e.MtimeNS, e.CtimeNS, e.ContentSHA256[:], int64(e.LastSeq))
	if err != nil {
		return apexerr.Wrap(err, apexerr.CodeInternal, "写入 state.db entries 失败")
	}
	return nil
}

// Entry looks up a file record.
func (d *DB) Entry(pathHMAC [32]byte) (*Entry, bool, error) {
	row := d.sql.QueryRow(`SELECT size, mtime_ns, ctime_ns, content_sha256, last_seq
		FROM entries WHERE path_hmac = ?`, pathHMAC[:])
	var e Entry
	var sha []byte
	var lastSeq int64
	if err := row.Scan(&e.Size, &e.MtimeNS, &e.CtimeNS, &sha, &lastSeq); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, apexerr.Wrap(err, apexerr.CodeInternal, "读取 state.db entries 失败")
	}
	copy(e.PathHMAC[:], pathHMAC[:])
	copy(e.ContentSHA256[:], sha)
	e.LastSeq = uint64(lastSeq)
	return &e, true, nil
}

// DeleteEntry removes a file record.
func (d *DB) DeleteEntry(pathHMAC [32]byte) error {
	if _, err := d.sql.Exec(`DELETE FROM entries WHERE path_hmac = ?`, pathHMAC[:]); err != nil {
		return apexerr.Wrap(err, apexerr.CodeInternal, "删除 state.db entries 失败")
	}
	return nil
}

// PutDir upserts a directory record.
func (d *DB) PutDir(dir Dir) error {
	_, err := d.sql.Exec(`INSERT INTO dirs(path_hmac, mode, last_seq) VALUES(?, ?, ?)
		ON CONFLICT(path_hmac) DO UPDATE SET mode=excluded.mode, last_seq=excluded.last_seq`,
		dir.PathHMAC[:], int64(dir.Mode), int64(dir.LastSeq))
	if err != nil {
		return apexerr.Wrap(err, apexerr.CodeInternal, "写入 state.db dirs 失败")
	}
	return nil
}

// DeleteDir removes a directory record.
func (d *DB) DeleteDir(pathHMAC [32]byte) error {
	if _, err := d.sql.Exec(`DELETE FROM dirs WHERE path_hmac = ?`, pathHMAC[:]); err != nil {
		return apexerr.Wrap(err, apexerr.CodeInternal, "删除 state.db dirs 失败")
	}
	return nil
}

// PutAnchor stores the rollback anchor for seq.
func (d *DB) PutAnchor(seq uint64, journalSHA [32]byte, mac [32]byte) error {
	_, err := d.sql.Exec(`INSERT INTO anchor(seq, journal_sha256, mac) VALUES(?, ?, ?)
		ON CONFLICT(seq) DO UPDATE SET journal_sha256=excluded.journal_sha256, mac=excluded.mac`,
		int64(seq), journalSHA[:], mac[:])
	if err != nil {
		return apexerr.Wrap(err, apexerr.CodeInternal, "写入 state.db anchor 失败")
	}
	return nil
}

// LatestAnchor returns the highest anchor.
func (d *DB) LatestAnchor() (Anchor, bool, error) {
	row := d.sql.QueryRow(`SELECT seq, journal_sha256, mac FROM anchor ORDER BY seq DESC LIMIT 1`)
	var a Anchor
	var seq int64
	var sha, mac []byte
	if err := row.Scan(&seq, &sha, &mac); err != nil {
		if err == sql.ErrNoRows {
			return Anchor{}, false, nil
		}
		return Anchor{}, false, apexerr.Wrap(err, apexerr.CodeInternal, "读取 state.db anchor 失败")
	}
	a.Seq = uint64(seq)
	copy(a.JournalSHA[:], sha)
	copy(a.MAC[:], mac)
	return a, true, nil
}

// AddCheckpoint records a checkpoint sequence.
func (d *DB) AddCheckpoint(seq uint64) error {
	if _, err := d.sql.Exec(`INSERT OR IGNORE INTO checkpoints(seq) VALUES(?)`, int64(seq)); err != nil {
		return apexerr.Wrap(err, apexerr.CodeInternal, "写入 state.db checkpoints 失败")
	}
	return nil
}

// LatestCheckpoint returns the highest checkpoint sequence.
func (d *DB) LatestCheckpoint() (uint64, bool, error) {
	var seq int64
	err := d.sql.QueryRow(`SELECT seq FROM checkpoints ORDER BY seq DESC LIMIT 1`).Scan(&seq)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, apexerr.Wrap(err, apexerr.CodeInternal, "读取 state.db checkpoints 失败")
	}
	return uint64(seq), true, nil
}

// ClearIndex drops every derived row while keeping the anchor and meta.
func (d *DB) ClearIndex() error {
	for _, stmt := range []string{`DELETE FROM entries`, `DELETE FROM dirs`, `DELETE FROM checkpoints`} {
		if _, err := d.sql.Exec(stmt); err != nil {
			return apexerr.Wrap(err, apexerr.CodeInternal, "清空 state.db 索引失败")
		}
	}
	return nil
}

// Reset wipes everything: used when the cache belongs to another vault (§05.7).
func (d *DB) Reset() error {
	for _, stmt := range []string{`DELETE FROM entries`, `DELETE FROM dirs`, `DELETE FROM checkpoints`,
		`DELETE FROM anchor`, `DELETE FROM meta`} {
		if _, err := d.sql.Exec(stmt); err != nil {
			return apexerr.Wrap(err, apexerr.CodeInternal, "重置 state.db 失败")
		}
	}
	return nil
}

// MarkDrill records a successful restore drill.
func (d *DB) MarkDrill(now time.Time) error {
	return d.SetMeta(MetaLastDrillUnix, fmt.Sprintf("%d", now.Unix()))
}

// MarkExport records an export-key run.
func (d *DB) MarkExport(now time.Time) error {
	return d.SetMeta(MetaLastExportUnix, fmt.Sprintf("%d", now.Unix()))
}
