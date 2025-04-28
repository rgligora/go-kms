package store

import (
	"bytes"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rgligora/go-kms/internal/kmspec"
)

func setupStore(t *testing.T) *SQLiteStore {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	// metadata table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS metadata (
			key   TEXT PRIMARY KEY,
			value BLOB    NOT NULL
		);
	`); err != nil {
		t.Fatal(err)
	}
	// secret keys table
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			key_id         TEXT    NOT NULL,
			version        INTEGER NOT NULL,
			wrapped_key    BLOB    NOT NULL,
			last_version_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (key_id, version)
		);
	`); err != nil {
		t.Fatal(err)
	}
	// metadata for keys
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS keys_metadata (
			key_id     TEXT PRIMARY KEY,
			purpose    TEXT NOT NULL,
			algorithm  TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		t.Fatal(err)
	}
	return NewSQLiteStore(db)
}

func TestSaltRoundTrip(t *testing.T) {
	s := setupStore(t)
	orig := []byte("some-random-salt")
	if err := s.SetMasterKeySalt(orig); err != nil {
		t.Fatalf("SetMasterKeySalt: %v", err)
	}
	got, err := s.GetMasterKeySalt()
	if err != nil {
		t.Fatalf("GetMasterKeySalt: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("salt mismatch: got %q, want %q", got, orig)
	}
}

func TestSecretStoreEmptyLoads(t *testing.T) {
	s := setupStore(t)
	// LoadWrappedKey
	if _, err := s.LoadWrappedKey("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("LoadWrappedKey(empty) error = %v; want ErrNotFound", err)
	}
	// LoadLatestWrappedKey
	if _, _, err := s.LoadLatestWrappedKey("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("LoadLatestWrappedKey(empty) error = %v; want ErrNotFound", err)
	}
	// LoadWrappedKeyVersion
	if _, err := s.LoadWrappedKeyVersion("nope", 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("LoadWrappedKeyVersion(empty) error = %v; want ErrNotFound", err)
	}
}

func TestStoreAndLoadAllVersions(t *testing.T) {
	s := setupStore(t)
	keyID := "foo"

	if err := s.StoreWrappedKey(keyID, 1, []byte("v1")); err != nil {
		t.Fatalf("StoreWrappedKey v1: %v", err)
	}
	if err := s.StoreWrappedKey(keyID, 2, []byte("v2")); err != nil {
		t.Fatalf("StoreWrappedKey v2: %v", err)
	}

	kvs, err := s.LoadWrappedKey(keyID)
	if err != nil {
		t.Fatalf("LoadWrappedKey: %v", err)
	}
	if len(kvs) != 2 {
		t.Fatalf("got %d versions; want 2", len(kvs))
	}
	if kvs[0].Version != 1 || !bytes.Equal(kvs[0].Wrapped, []byte("v1")) {
		t.Errorf("version1 = %+v; want Version=1, Wrapped=v1", kvs[0])
	}
	if kvs[1].Version != 2 || !bytes.Equal(kvs[1].Wrapped, []byte("v2")) {
		t.Errorf("version2 = %+v; want Version=2, Wrapped=v2", kvs[1])
	}
}

func TestLoadLatestAndSpecificVersion(t *testing.T) {
	s := setupStore(t)
	keyID := "bar"

	// store v1 and v2
	s.StoreWrappedKey(keyID, 1, []byte("one"))
	time.Sleep(1 * time.Millisecond) // ensure different timestamps
	s.StoreWrappedKey(keyID, 2, []byte("two"))

	// latest
	gotWrapped, gotVer, err := s.LoadLatestWrappedKey(keyID)
	if err != nil {
		t.Fatalf("LoadLatestWrappedKey: %v", err)
	}
	if gotVer != 2 || !bytes.Equal(gotWrapped, []byte("two")) {
		t.Errorf("latest = (ver=%d, wrapped=%s); want (2,two)", gotVer, gotWrapped)
	}

	// specific
	for _, tc := range []struct {
		ver  int
		want string
	}{
		{1, "one"},
		{2, "two"},
	} {
		got, err := s.LoadWrappedKeyVersion(keyID, tc.ver)
		if err != nil {
			t.Errorf("LoadWrappedKeyVersion(%d): %v", tc.ver, err)
			continue
		}
		if !bytes.Equal(got, []byte(tc.want)) {
			t.Errorf("version %d wrapped = %q; want %q", tc.ver, got, tc.want)
		}
	}

	// non-existent version
	if _, err := s.LoadWrappedKeyVersion(keyID, 3); !errors.Is(err, ErrNotFound) {
		t.Errorf("LoadWrappedKeyVersion(3) error = %v; want ErrNotFound", err)
	}
}

func TestDeleteWrappedKey(t *testing.T) {
	s := setupStore(t)
	keyID := "todelete"
	s.StoreWrappedKey(keyID, 1, []byte("x"))

	// delete it
	if err := s.DeleteWrappedKey(keyID); err != nil {
		t.Fatalf("DeleteWrappedKey: %v", err)
	}
	// now all loads should 404
	if _, err := s.LoadWrappedKey(keyID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete LoadWrappedKey error = %v; want ErrNotFound", err)
	}

	// deleting again yields ErrNotFound
	if err := s.DeleteWrappedKey(keyID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteWrappedKey error = %v; want ErrNotFound", err)
	}
}

func TestKeyMetadataStore(t *testing.T) {
	s := setupStore(t)
	spec1 := kmspec.KeySpec{"k1", kmspec.PurposeEncrypt, kmspec.AlgAES256GCM}
	spec2 := kmspec.KeySpec{"k2", kmspec.PurposeSign, kmspec.AlgRSA4096}

	// initially empty
	if _, err := s.GetKeyMetadata(spec1.KeyID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetKeyMetadata(empty) error = %v; want ErrNotFound", err)
	}
	list, err := s.ListKeySpecs()
	if err != nil {
		t.Fatalf("ListKeySpecs(empty): %v", err)
	}
	if len(list) != 0 {
		t.Errorf("ListKeySpecs(empty) = %v; want []", list)
	}

	// store two specs
	if err := s.StoreKeyMetadata(spec1); err != nil {
		t.Fatalf("StoreKeyMetadata spec1: %v", err)
	}
	if err := s.StoreKeyMetadata(spec2); err != nil {
		t.Fatalf("StoreKeyMetadata spec2: %v", err)
	}

	// Get each
	got1, err := s.GetKeyMetadata(spec1.KeyID)
	if err != nil {
		t.Fatalf("GetKeyMetadata k1: %v", err)
	}
	if got1 != spec1 {
		t.Errorf("GetKeyMetadata k1 = %+v; want %+v", got1, spec1)
	}
	got2, err := s.GetKeyMetadata(spec2.KeyID)
	if err != nil {
		t.Fatalf("GetKeyMetadata k2: %v", err)
	}
	if got2 != spec2 {
		t.Errorf("GetKeyMetadata k2 = %+v; want %+v", got2, spec2)
	}

	// ListKeySpecs returns both (order not guaranteed)
	list, err = s.ListKeySpecs()
	if err != nil {
		t.Fatalf("ListKeySpecs: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListKeySpecs = %v; want length 2", list)
	}
	m := map[string]kmspec.KeySpec{}
	for _, sp := range list {
		m[sp.KeyID] = sp
	}
	for _, want := range []kmspec.KeySpec{spec1, spec2} {
		if got, ok := m[want.KeyID]; !ok || got != want {
			t.Errorf("ListKeySpecs missing %+v; got map %v", want, m)
		}
	}
}
