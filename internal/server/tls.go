package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

// loadTLSConfig returns a tls.Config requiring mTLS.
func loadTLSConfig(serverCert, serverKey, caCert string) (*tls.Config, error) {
	// Load server certificate
	cert, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	// Load CA certificate
	caPEM, err := ioutil.ReadFile(caCert)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("failed to append CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
