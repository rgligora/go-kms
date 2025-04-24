package store

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupStore(t *testing.T) *SQLiteStore {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE metadata(key TEXT PRIMARY KEY,value BLOB);`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE keys(key_id TEXT PRIMARY KEY, wrapped_key BLOB);`); err != nil {
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

// ... similarly for wrapped-key methods ...
