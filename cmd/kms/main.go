package main

import (
	"github.com/rgligora/go-kms/internal/config"
	"github.com/rgligora/go-kms/internal/server"
	"log"
)

func main() {
	// 1) Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	// 2) Bootstrap server (loads passphrase, derives master key, opens DB)
	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("server bootstrap error: %v", err)
	}
	// Ensure we zeroize masterKey and close DB on exit
	defer func() {
		if err := srv.Close(); err != nil {
			log.Printf("error during shutdown: %v", err)
		}
	}()

	// 3) Run HTTP(S) server
	if err := srv.Run(); err != nil {
		log.Fatalf("server run error: %v", err)
	}
}
