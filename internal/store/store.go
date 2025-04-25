package store

import (
	"database/sql"
	"errors"
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

// SecretStore defines operations for storing wrapped DEKs and other secrets.
type SecretStore interface {
	// StoreWrappedKey saves or updates a wrapped data-encryption key (DEK) by ID.
	StoreWrappedKey(keyID string, version int, wrapped []byte) error
	// LoadWrappedKey retrieves the wrapped DEK for the given ID.
	LoadWrappedKey(keyID string) (key []KeyVersion, err error)
	// LoadLatestWrappedKey retrieves the latest wrapped DEK for the given ID.
	LoadLatestWrappedKey(keyID string) (wrapped []byte, version int, err error)
	// LoadWrappedKeyVersion retrieves the specific version of the wrapped DEK
	LoadWrappedKeyVersion(keyID string, version int) ([]byte, error)
	// DeleteWrappedKey deletes the wrapped DEK associated with the given ID.
	DeleteWrappedKey(keyID string) error
	// ListKeyIDs returns all stored key IDs.
	ListKeyIDs() ([]string, error)
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
	metadataTable = "metadata"
	saltKey       = "master_key_salt"
	keysTable     = "keys"
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

// StoreWrappedKey saves or updates a wrapped DEK in the keys_version table.
func (s *SQLiteStore) StoreWrappedKey(keyID string, version int, wrapped []byte) error {
	_, err := s.db.Exec(`
      INSERT INTO keys (key_id, version, wrapped_key)
           VALUES (?, ?, ?)
      ON CONFLICT(key_id, version) DO UPDATE
        SET wrapped_key = excluded.wrapped_key
    `, keyID, version, wrapped)
	return err
}

// LoadWrappedKey loads *all* versions for a given key ID.
func (s *SQLiteStore) LoadWrappedKey(keyID string) ([]KeyVersion, error) {
	rows, err := s.db.Query(`
      SELECT version, wrapped_key, created_at
        FROM keys
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

func (s *SQLiteStore) LoadLatestWrappedKey(keyID string) ([]byte, int, error) {
	var wrapped []byte
	var version int
	err := s.db.QueryRow(`
      SELECT wrapped_key, version
        FROM keys
       WHERE key_id = ?
    ORDER BY version DESC
       LIMIT 1
    `, keyID).Scan(&wrapped, &version)
	if err == sql.ErrNoRows {
		return nil, 0, ErrNotFound
	}
	return wrapped, version, err
}

// LoadWrappedKeyVersion retrieves a specific version of the wrapped DEK.
func (s *SQLiteStore) LoadWrappedKeyVersion(keyID string, version int) ([]byte, error) {
	var wrapped []byte
	err := s.db.QueryRow(`
      SELECT wrapped_key
        FROM keys
       WHERE key_id = ? AND version = ?
    `, keyID, version).Scan(&wrapped)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return wrapped, err
}

// DeleteWrappedKey deletes the wrapped DEK associated with the given key ID.
func (s *SQLiteStore) DeleteWrappedKey(keyID string) error {
	res, err := s.db.Exec(`DELETE FROM keys WHERE key_id = ?`, keyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListKeyIDs returns all stored key IDs in the keys table.
func (s *SQLiteStore) ListKeyIDs() ([]string, error) {
	rows, err := s.db.Query(
		"SELECT key_id FROM " + keysTable,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
