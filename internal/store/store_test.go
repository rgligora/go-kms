package store

import (
	"bytes"
	"database/sql"
	"github.com/rgligora/go-kms/internal/kmspec"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupStore(t *testing.T) *SQLiteStore {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	// metadata table unchanged
	if _, err := db.Exec(`
      CREATE TABLE metadata(
        key   TEXT PRIMARY KEY,
        value BLOB NOT NULL
      );
    `); err != nil {
		t.Fatal(err)
	}
	// versioned keys table
	if _, err := db.Exec(`
      CREATE TABLE keys (
        key_id      TEXT    NOT NULL,
        purpose     TEXT    NOT NULL,
        algorithm   TEXT    NOT NULL,
        version     INTEGER NOT NULL,
        wrapped_key BLOB    NOT NULL,
        created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (key_id, purpose, algorithm, version)
      );
    `); err != nil {
		t.Fatal(err)
	}

	return NewSQLiteStore(db)
}

func TestSaltRoundTrip(t *testing.T) {
	s := setupStore(t)
	original := []byte("random-salt-1234")
	if err := s.SetMasterKeySalt(original); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetMasterKeySalt()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("expected %v, got %v", original, got)
	}
}

func TestStoreAndLoadAllVersions(t *testing.T) {
	s := setupStore(t)

	spec := kmspec.KeySpec{
		KeyID:     "foo",
		Purpose:   kmspec.PurposeEncrypt,
		Algorithm: kmspec.AlgAES256GCM,
	}

	// write two versions
	s.StoreWrappedKey(spec, 1, []byte("v1"))
	s.StoreWrappedKey(spec, 2, []byte("v2"))

	kvs, err := s.LoadWrappedKey(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(kvs) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(kvs))
	}
	if kvs[0].Version != 1 || !bytes.Equal(kvs[0].Wrapped, []byte("v1")) {
		t.Errorf("bad v1: %#v", kvs[0])
	}
	if kvs[1].Version != 2 || !bytes.Equal(kvs[1].Wrapped, []byte("v2")) {
		t.Errorf("bad v2: %#v", kvs[1])
	}
}
