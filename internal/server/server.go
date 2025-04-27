package server

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/rgligora/go-kms/api/handlers"
	"github.com/rgligora/go-kms/internal/service"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rgligora/go-kms/internal/config"
	"github.com/rgligora/go-kms/internal/cryptoutil"
	"github.com/rgligora/go-kms/internal/store"
	"golang.org/x/term"
)

// Server holds dependencies for the KMS service
type Server struct {
	cfg       *config.Config
	db        *sql.DB
	store     *store.SQLiteStore
	masterKey []byte
}

// NewServer bootstraps the KMS server: loads passphrase, derives master key, initializes storage.
func NewServer(cfg *config.Config) (*Server, error) {
	// 1) Load or prompt passphrase
	passphrase, err := loadMasterPassphrase(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to load passphrase: %w", err)
	}
	defer cryptoutil.Zeroize(passphrase)

	// 2) Open SQLite database
	db, err := sql.Open("sqlite3", cfg.Database.DSN)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	// 3) Ensure metadata table exists
	if err := ensureMetadataTable(db); err != nil {
		return nil, fmt.Errorf("creating metadata table: %w", err)
	}

	if err := ensureKeysTable(db); err != nil {
		return nil, fmt.Errorf("creating keys table: %w", err)
	}

	sqlite := store.NewSQLiteStore(db)

	// 4) Retrieve or generate salt
	salt, err := sqlite.GetMasterKeySalt()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			salt = nil
		} else {
			return nil, fmt.Errorf("getting master key salt: %w", err)
		}
	}
	if salt == nil {
		salt, err = cryptoutil.GenerateSalt()
		if err != nil {
			return nil, fmt.Errorf("generating salt: %w", err)
		}
		if err := sqlite.SetMasterKeySalt(salt); err != nil {
			return nil, fmt.Errorf("storing master key salt: %w", err)
		}
	}

	// 5) Derive master key
	masterKey := cryptoutil.DeriveMasterKey(passphrase, salt)

	// 6) Validate passphrase or master.key
	const initKeyID = "__init__"
	wrappedInit, err := sqlite.LoadWrappedKeyVersion(initKeyID, 1)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("loading init marker: %w", err)
	}
	if wrappedInit == nil {
		// First run ever: store the init marker
		marker := []byte("kms-initialized")
		wrapped, err := cryptoutil.WrapKey(masterKey, marker)
		if err != nil {
			return nil, fmt.Errorf("wrapping init marker: %w", err)
		}
		if err := sqlite.StoreWrappedKey(initKeyID, 1, wrapped); err != nil {
			return nil, fmt.Errorf("storing init marker: %w", err)
		}
	} else {
		// Subsequent runs: verify the marker unwraps correctly
		if _, err := cryptoutil.UnwrapKey(masterKey, wrappedInit); err != nil {
			return nil, fmt.Errorf("master passphrase mismatch or corrupt data: %w", err)
		}
	}

	return &Server{
		cfg:       cfg,
		db:        db,
		store:     sqlite,
		masterKey: masterKey,
	}, nil
}

// Run starts the HTTP server with configured routes
func (s *Server) Run() error {
	tlsCfg, err := loadTLSConfig(s.cfg.Server.ServerCert, s.cfg.Server.ServerKey, s.cfg.Server.CaCert)
	if err != nil {
		return fmt.Errorf("TLS config error: %w", err)
	}
	mux := http.NewServeMux()
	svc := service.NewKMSService(s.store, s.masterKey)
	h := handlers.NewHandler(svc)
	h.RegisterRoutes(mux)

	server := &http.Server{
		Addr:      fmt.Sprintf("127.0.0.1:%d", s.cfg.Server.Port),
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	log.Printf("KMS listening on %s (mTLS, localhost only)", server.Addr)
	return server.ListenAndServeTLS("", "")
}

// Close tears down the server: zeroizes the master key and closes DB.
func (s *Server) Close() error {
	// Wipe the master key from memory
	cryptoutil.Zeroize(s.masterKey)
	// Close the DB connection
	return s.db.Close()
}

// loadMasterPassphrase handles interactive or file-based passphrase loading
func loadMasterPassphrase(cfg *config.Config) ([]byte, error) {
	// Attempt file-based loading
	if strings.TrimSpace(cfg.KMS.PassphraseFile) != "" {
		data, err := os.ReadFile(cfg.KMS.PassphraseFile)
		if err == nil {
			pass := strings.TrimSpace(string(data))
			if pass != "" {
				return []byte(pass), nil
			}
		} else {
			// Optional: log error but continue to prompt
			fmt.Fprintf(os.Stderr, "Warning: could not read passphrase file: %v\n", err)
		}
	}

	// Fallback: interactive prompt
	fmt.Print("Enter master passphrase: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	return pass, nil
}

// ensureMetadataTable creates the metadata table if it doesn't exist
func ensureMetadataTable(db *sql.DB) error {
	const sqlStmt = `
        CREATE TABLE IF NOT EXISTS metadata (
            key   TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );`
	_, err := db.Exec(sqlStmt)
	return err
}

// ensureKeyVersionsTable creates the key versions table for keys
func ensureKeysTable(db *sql.DB) error {
	const sqlStmt = `
		CREATE TABLE IF NOT EXISTS keys (
			key_id      TEXT NOT NULL,
			purpose     TEXT    NOT NULL,
  			algorithm   TEXT    NOT NULL,
			version     INTEGER NOT NULL,
			wrapped_key BLOB  NOT NULL,
			created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (key_id, purpose, algorithm, version)
		);`
	_, err := db.Exec(sqlStmt)
	return err
}
