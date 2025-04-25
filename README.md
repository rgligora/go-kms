# Go KMS

A lightweight, on-premise Key Management Service (KMS) written in Go.  
Supports envelope encryption, key‐ring versioning (multiple DEK versions per key), master-key derivation via PBKDF2, AES-256-GCM DEK wrapping, and a simple HTTP + mTLS API.

---

## Table of Contents

1. [Features](#features)
2. [Architecture & Packages](#architecture--packages)
3. [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Configuration](#configuration)
    - [Development Run](#development-run)
4. [API Endpoints](#api-endpoints)
5. [Testing](#testing)
    - [Unit Tests](#unit-tests)
    - [Integration Tests](#integration-tests)
6. [Production Deployment](#production-deployment)
    - [Docker Compose Example](#docker-compose-example)
    - [Managing TLS & Secrets](#managing-tls--secrets)
    - [Certificate Rotation](#certificate-rotation)
7. [Security Considerations](#security-considerations)
8. [TODO / Roadmap](#todo--roadmap)

---

## Features

- **Envelope encryption**:
    - Master key derived via PBKDF2-HMAC-SHA256 (600 000 iterations, 16 B salt)
    - AES-256-GCM wrapping/unwrapping of Data–Encryption Keys (DEKs)
- **Key rings & versioning**:
    - `keys` table schema: `(key_id, version, wrapped_key, created_at)`
    - APIs to list all versions, fetch latest or specific version
    - Ciphertexts prefixed by `v<version>:` so decryptors pick the right key
- **Secure passphrase handling**:
    - Interactive prompt (no shell history) or file-mounted secret (`0400`)
    - “Init marker” unwrap at startup to detect wrong passphrase early
- **mTLS-protected HTTP API** (localhost-only by default)
- **SQLite persistence** (file-backed or in-memory for tests)
- Clean shutdown: zeroize master key, close DB

---

## Architecture & Packages

```
go-kms/
├── cmd/kms/           # CLI entrypoint (main.go)
├── config/            # dev/prod YAML config
├── internal/
│   ├── config/        # Viper loader
│   ├── cryptoutil/    # PBKDF2, AES-GCM wrap/unwrap, zeroize
│   ├── server/        # HTTP server bootstrap + mTLS
│   ├── service/       # KMSService business logic
│   └── store/         # SQLiteStore SecretStore & MetadataStore
└── api/
    └── handlers/      # HTTP handlers & routing
```

- **`cmd/kms`**: builds the `go-kms` binary
- **`config`**: `config.dev.yaml`, `config.prod.yaml`
- **`internal/store`**: defines `SecretStore` interface & `SQLiteStore` implementation

---

## Getting Started

### Prerequisites

- **Go** ≥ 1.20
- **SQLite3** (for local dev)
- **OpenSSL** (to generate dev certificates)
- **Postman** or **curl** for API testing

### Configuration

1. **Development** (`config/config.dev.yaml`):

   ```yaml
   server:
     port:       8080
     serverCert: "./secrets/server.crt"
     serverKey:  "./secrets/server.key"
     caCert:     "./secrets/ca.pem"

   kms:
     master_passphrase_file: "./secrets/master.key"

   database:
     dsn: "./data/dev.db"
   ```

2. **Production** (`config/config.prod.yaml`):

   ```yaml
   server:
     port:       8443
     serverCert: "/run/secrets/server_cert"
     serverKey:  "/run/secrets/server_key"
     caCert:     "/run/secrets/ca_cert"

   kms:
     master_passphrase_file: "/run/secrets/master_passphrase"

   database:
     dsn: "/var/lib/go-kms/prod.db"
   ```

3. **Environment**
   ```bash
   export KMS_ENV=dev      # or "prod"
   export KMS_DATABASE_DSN=./data/dev.db
   ```

### Development Run

1. **Generate dev certs & passphrase** (in `./secrets/`):

   ```bash
   # CA
   openssl genrsa -out secrets/ca.key 2048
   openssl req -x509 -new -nodes -key secrets/ca.key -subj "/CN=dev-ca" -days 365      -out secrets/ca.pem

   # Server
   openssl genrsa -out secrets/server.key 2048
   openssl req -new -key secrets/server.key -subj "/CN=localhost"      -out secrets/server.csr
   openssl x509 -req -in secrets/server.csr -CA secrets/ca.pem -CAkey secrets/ca.key -CAcreateserial      -out secrets/server.crt -days 365

   # Client (for Postman)
   openssl genrsa -out secrets/client.key 2048
   openssl req -new -key secrets/client.key -subj "/CN=orchestrator"      -out secrets/client.csr
   openssl x509 -req -in secrets/client.csr -CA secrets/ca.pem -CAkey secrets/ca.key -CAcreateserial      -out secrets/client.crt -days 365

   # Passphrase
   echo "super-secret-pass" > secrets/master.key
   chmod 0400 secrets/master.key
   ```

2. **Build & run**:

   ```bash
   go build -o bin/go-kms ./cmd/kms
   export KMS_ENV=dev
   ./bin/go-kms
   ```

3. **Test with curl** (disable TLS verification):

   ```bash
   curl -k --cacert ./secrets/ca.pem --cert ./secrets/client.crt --key ./secrets/client.key      -X POST https://localhost:8080/v1/kms/keys      -H "Content-Type: application/json"      -d '{"key_id":"device123"}'
   ```

---

## API Endpoints

| Method | Path                                    | Description                                         |
| ------ | --------------------------------------- | --------------------------------------------------- |
| `POST` | `/v1/kms/keys`                          | Create **new** key (version 1).                     |
| `GET`  | `/v1/kms/keys/{key_id}`                | List **all** wrapped-key versions (`key_versions`). |
| `DELETE`|`/v1/kms/keys/{key_id}`                | Delete **all** versions of a key.                   |
| `POST` | `/v1/kms/keys/{key_id}/rotate`         | Rotate to a **new** random DEK version (v+1).       |
| `POST` | `/v1/kms/keys/{key_id}/recreate`       | Wipe & re-create as version 1 (fresh DEK).          |
| `POST` | `/v1/kms/encrypt`                      | Encrypt base64-plaintext under latest DEK.          |
| `POST` | `/v1/kms/decrypt`                      | Decrypt base64-ciphertext (parses `vN:` prefix).    |

### Example: Encrypt / Decrypt

```bash
# Encrypt "Hello"
PT=$(echo -n "Hello" | base64)
CT=$(curl -sk .../encrypt      -d "{"key_id":"device123","plaintext":"$PT"}"      | jq -r .ciphertext)

# Decrypt back
curl -sk .../decrypt   -d "{"key_id":"device123","ciphertext":"$CT"}"   | jq -r .plaintext | base64 --decode
```

---

## Testing

### Unit Tests

```bash
go test ./internal/cryptoutil
go test ./internal/store
go test ./internal/service
go test ./api/handlers
```

### Integration Tests

```bash
go test ./integration -tags=integration -v
```

Or include them by removing the build tag:

```bash
go test ./... -timeout 30s
```

---

## Production Deployment

### Docker Compose Example

```yaml
version: "3.8"
services:
  go-kms:
    image: yourrepo/go-kms:latest
    ports:
      - "8443:8443"
    environment:
      - KMS_ENV=prod
      - KMS_DATABASE_DSN=/var/lib/go-kms/prod.db
    volumes:
      - ./data/prod.db:/var/lib/go-kms/prod.db
    secrets:
      - server_cert
      - server_key
      - ca_cert
      - master_passphrase

secrets:
  server_cert:
    file: ./secrets/server.crt
  server_key:
    file: ./secrets/server.key
  ca_cert:
    file: ./secrets/ca.pem
  master_passphrase:
    file: ./secrets/master.key
```

### Managing TLS & Secrets

- **Docker Secrets**: secrets are mounted at `/run/secrets/<name>`.
- **Config** file (`config.prod.yaml`) lives under `/etc/go-kms/` via Docker Config or volume.
- **DB Persistence**: mount `prod.db` to a Docker volume (bind-mount or named volume).

### Certificate Rotation

- Automate via your CI/CD pipeline every 2 months:
    1. Issue new server & client certs from your internal CA.
    2. Update Docker secrets (`docker secret rm/create`).
    3. Rolling restart: `docker-compose up -d go-kms`.

---

## Security Considerations

- **Master passphrase** never in env vars; loaded from file or prompt.
- **Zeroize** all sensitive buffers immediately after use.
- **mTLS** enforces client identity; API never exposed externally without cert.
- **Envelope encryption** protects DEKs at rest; DB metadata is not encrypted—use disk-level encryption or SQLCipher if needed.

---

## TODO / Roadmap

- [ ] Fine-grained authorization (per-endpoint roles)
- [ ] Healthz & Prometheus metrics
- [ ] RSA signing support
- [ ] Automated key rotation policies
- [ ] Support for HSM-backed master keys

---

## License

This software is licensed under the PolyForm Noncommercial License 1.0.0.  
You may use, modify, and distribute it, but **not** for any commercial purpose.  
See [LICENSE](PolyForm-Noncommercial-1.0.0.txt) for full terms.
