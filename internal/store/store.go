package store

import (
	"database/sql"
	"errors"
	"github.com/rgligora/go-kms/internal/kmspec"
	"time"
)

var ErrNotFound = errors.New("record not found")

// KeyVersion represents one version of a wrapped DEK.
type KeyVersion struct {
	Version   int
	Wrapped   []byte
	CreatedAt time.Time
}

// MetadataStore defines operations for storing and retrieving KMS metadata.
type MetadataStore interface {
	// GetMasterKeySalt retrieves the PBKDF2 salt for deriving the master key.
	// Returns (nil, nil) if no salt is stored yet.
	GetMasterKeySalt() ([]byte, error)
	// SetMasterKeySalt stores or updates the PBKDF2 salt for the master key.
	SetMasterKeySalt(salt []byte) error
}

type KeyMetadataStore interface {
	// StoreKeyMetadata inserts a new row into keys_metadata.
	StoreKeyMetadata(spec kmspec.KeySpec) error
	// GetKeyMetadata loads the purpose+algorithm for a given keyID.
	GetKeyMetadata(keyID string) (kmspec.KeySpec, error)
	// ListKeySpecs returns all keys’ metadata (key_id, purpose, algorithm).
	ListKeySpecs() ([]kmspec.KeySpec, error)
}

// SecretStore defines operations for storing wrapped DEKs and other secrets.
type SecretStore interface {
	// StoreWrappedKey saves or updates a wrapped key for the given keyID & version.
	StoreWrappedKey(keyID string, version int, wrapped []byte) error
	// LoadWrappedKey loads *all* versions for the given keyID.
	LoadWrappedKey(keyID string) (key []KeyVersion, err error)
	// LoadLatestWrappedKey loads the latest version for the given keyID.
	LoadLatestWrappedKey(keyID string) (wrapped []byte, version int, err error)
	// LoadWrappedKeyVersion loads a specific version for the given keyID.
	LoadWrappedKeyVersion(keyID string, version int) ([]byte, error)
	// DeleteWrappedKey deletes *all* versions for the given keyID.
	DeleteWrappedKey(keyID string) error
}

// SQLiteStore implements MetadataStore and SecretStore using SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a new SQLiteStore with the given database connection.
func NewSQLiteStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

const (
	metadataTable     = "metadata"
	saltKey           = "master_key_salt"
	keysTable         = "keys"
	keysMetadataTable = "keys_metadata"
)

// GetMasterKeySalt retrieves the salt from the metadata table.
func (s *SQLiteStore) GetMasterKeySalt() ([]byte, error) {
	var salt []byte
	err := s.db.QueryRow(
		"SELECT value FROM "+metadataTable+" WHERE key = ?", saltKey,
	).Scan(&salt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return salt, err
}

// SetMasterKeySalt upserts the salt into the metadata table.
func (s *SQLiteStore) SetMasterKeySalt(salt []byte) error {
	_, err := s.db.Exec(
		"INSERT INTO "+metadataTable+"(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		saltKey, salt,
	)
	return err
}

// StoreWrappedKey saves or updates a wrapped key in the keys table.
func (s *SQLiteStore) StoreWrappedKey(keyID string, version int, wrapped []byte) error {
	_, err := s.db.Exec(`
      INSERT INTO `+keysTable+` (key_id, version, wrapped_key)
           VALUES (?, ?, ?)
      ON CONFLICT(key_id, version) DO UPDATE
        SET wrapped_key = excluded.wrapped_key
    `, keyID, version, wrapped)
	return err
}

// LoadWrappedKey loads *all* versions for a given keyID.
func (s *SQLiteStore) LoadWrappedKey(keyID string) ([]KeyVersion, error) {
	rows, err := s.db.Query(`
      SELECT version, wrapped_key, last_version_at
        FROM `+keysTable+`
       WHERE key_id = ?
    ORDER BY version
    `, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []KeyVersion
	for rows.Next() {
		var kv KeyVersion
		if err := rows.Scan(&kv.Version, &kv.Wrapped, &kv.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, kv)
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, rows.Err()
}

// LoadLatestWrappedKey retrieves the latest wrapped key for a given keyID
func (s *SQLiteStore) LoadLatestWrappedKey(keyID string) ([]byte, int, error) {
	var wrapped []byte
	var version int
	err := s.db.QueryRow(`
      SELECT wrapped_key, version
        FROM `+keysTable+`
       WHERE key_id = ?
    ORDER BY version DESC
       LIMIT 1
    `, keyID).Scan(&wrapped, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrNotFound
	}
	return wrapped, version, err
}

// LoadWrappedKeyVersion retrieves a specific version for a given keyID.
func (s *SQLiteStore) LoadWrappedKeyVersion(keyID string, version int) ([]byte, error) {
	var wrapped []byte
	err := s.db.QueryRow(`
      SELECT wrapped_key
        FROM `+keysTable+`
       WHERE key_id = ? AND version = ?
    `, keyID, version).Scan(&wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return wrapped, err
}

// DeleteWrappedKey deletes all versions for a given keyID with metadata.
func (s *SQLiteStore) DeleteWrappedKey(keyID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	// ensure we roll back on any error
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// 1) delete all versions
	res, err := tx.Exec(`
        DELETE FROM `+keysTable+`
        WHERE key_id = ?
    `, keyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}

	// 2) delete the metadata row too
	if _, err = tx.Exec(`
        DELETE FROM `+keysMetadataTable+`
        WHERE key_id = ?
    `, keyID); err != nil {
		return err
	}

	// 3) commit both deletes together
	return tx.Commit()
}

// - KeyMetadataStore implementation
//
// StoreKeyMetadata inserts the key’s static metadata.
func (s *SQLiteStore) StoreKeyMetadata(spec kmspec.KeySpec) error {
	const sqlStmt = `
      INSERT INTO ` + keysMetadataTable + ` (key_id, purpose, algorithm)
           VALUES (?,    ?,       ?)
      ON CONFLICT(key_id) DO NOTHING;
    `
	_, err := s.db.Exec(sqlStmt, spec.KeyID, spec.Purpose, spec.Algorithm)
	return err
}

// GetKeyMetadata retrieves the purpose & algorithm for keyID.
func (s *SQLiteStore) GetKeyMetadata(keyID string) (kmspec.KeySpec, error) {
	const sqlStmt = `
      SELECT purpose, algorithm
        FROM ` + keysMetadataTable + `
       WHERE key_id = ?
    `
	var spec kmspec.KeySpec
	spec.KeyID = keyID
	err := s.db.QueryRow(sqlStmt, keyID).Scan(&spec.Purpose, &spec.Algorithm)
	if err == sql.ErrNoRows {
		return kmspec.KeySpec{}, ErrNotFound
	}
	return spec, err
}

// ListKeySpecs returns all entries from keys_metadata.
func (s *SQLiteStore) ListKeySpecs() ([]kmspec.KeySpec, error) {
	const sqlStmt = `
      SELECT key_id, purpose, algorithm
        FROM ` + keysMetadataTable + `
    `
	rows, err := s.db.Query(sqlStmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []kmspec.KeySpec
	for rows.Next() {
		var ks kmspec.KeySpec
		if err := rows.Scan(&ks.KeyID, &ks.Purpose, &ks.Algorithm); err != nil {
			return nil, err
		}
		out = append(out, ks)
	}
	return out, rows.Err()
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
