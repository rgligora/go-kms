package store

import (
	"database/sql"
	"errors"
)

var ErrNotFound = errors.New("record not found")

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
	StoreWrappedKey(keyID string, wrapped []byte) error
	// LoadWrappedKey retrieves the wrapped DEK for the given ID.
	LoadWrappedKey(keyID string) ([]byte, error)
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

// StoreWrappedKey saves or updates a wrapped DEK in the keys table.
func (s *SQLiteStore) StoreWrappedKey(keyID string, wrapped []byte) error {
	_, err := s.db.Exec(
		"INSERT INTO "+keysTable+"(key_id, wrapped_key) VALUES(?, ?) ON CONFLICT(key_id) DO UPDATE SET wrapped_key = excluded.wrapped_key",
		keyID, wrapped,
	)
	return err
}

// LoadWrappedKey retrieves the wrapped DEK for a given key ID.
func (s *SQLiteStore) LoadWrappedKey(keyID string) ([]byte, error) {
	var wrapped []byte
	err := s.db.QueryRow(
		"SELECT wrapped_key FROM "+keysTable+" WHERE key_id = ?", keyID,
	).Scan(&wrapped)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return wrapped, err
}

// DeleteWrappedKey deletes the wrapped DEK associated with the given key ID.
func (s *SQLiteStore) DeleteWrappedKey(keyID string) error {
	res, err := s.db.Exec(
		"DELETE FROM "+keysTable+" WHERE key_id = ?", keyID,
	)
	if err != nil {
		return err
	}
	if count, _ := res.RowsAffected(); count == 0 {
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
