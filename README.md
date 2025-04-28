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


_All endpoints require mTLS client certificates (localhost-only by default).  
All requests and responses use JSON (`Content-Type: application/json`)._


| Method | Path                             | Description                                         |
| ------ |----------------------------------|-----------------------------------------------------|
| `POST` | `/v1/kms/keys`                   | Create **new** key (version 1).                     |
| `GET`  | `/v1/kms/keys/{key_id}`          | List **all** wrapped-key versions (`key_versions`). |
| `DELETE`| `/v1/kms/keys/{key_id}`          | Delete **all** versions of a key.                   |
| `POST` | `/v1/kms/keys/{key_id}/rotate`   | Rotate to a **new** key version (v+1).              |
| `POST` | `/v1/kms/keys/{key_id}/recreate` | Wipe & re-create as version 1 (fresh key).          |
| `POST` | `/v1/kms/encrypt`                | Encrypt base64-plaintext under the latest version of DEK. |
| `POST` | `/v1/kms/decrypt`                | Decrypt base64-ciphertext (parses `vN:` prefix).    |
| `POST` | `/v1/kms/sign`                   | Sign base64-plaintext under the latest version of DSA key. |
| `POST` | `/v1/kms/verify`                 | Verify the signature.                               |



### Key Lifecycle Endpoints

#### Create a New Key
POST /v1/kms/keys  
Body:
{
"purpose":   "encrypt",         # "encrypt" | "sign"
"algorithm": "AES-256-GCM"      # "AES-256-GCM" | "ChaCha20-Poly1305" | "RSA-4096" | "ECDSA-P256"
}

**201 Created**  
{
"key_id":    "UUID",
"purpose":   "encrypt",
"algorithm": "AES-256-GCM",
"version":   1
}

Errors:
- 400 Bad Request: invalid JSON or missing fields
- 409 Conflict: "key already exists"
- 500 Internal Server Error

---

#### List All Keys
GET /v1/kms/keys

**200 OK**  
[
{
"key_id":    "UUID",
"purpose":   "encrypt",
"algorithm": "AES-256-GCM",
"version":   2
},
{
"key_id":    "UUID",
"purpose":   "sign",
"algorithm": "RSA-4096",
"version":   1
}
]

---

#### Get a Single Key
GET /v1/kms/keys/{key_id}

**200 OK**  
(Same schema as one element of the list above)

**404 Not Found**  
{ "error": "record not found" }

---

#### Delete a Key
DELETE /v1/kms/keys/{key_id}

**204 No Content**  
**404 Not Found**

---

#### Rotate a Key
POST /v1/kms/keys/{key_id}/rotate

**200 OK**  
{
"key_id":    "UUID",
"purpose":   "encrypt",
"algorithm": "AES-256-GCM",
"version":   3
}

**404 Not Found**

---

#### Recreate a Key
POST /v1/kms/keys/{key_id}/recreate

_Wipes existing versions and issues a new version 1_

**201 Created**  
(Same schema as Create above, but fresh key_id/version)

**404 Not Found**

---

### Data Operations (RPC-style)

#### Encrypt Data
POST /v1/kms/encrypt  
Body:
{
"key_id":   "UUID",
"plaintext":"BASE64-ENCODED"
}

**200 OK**  
{ "ciphertext":"BASE64(vN:nonce:ciphertext)" }

Errors:
- 400 Bad Request (invalid JSON or base64)
- 500 Internal Server Error

---

#### Decrypt Data
POST /v1/kms/decrypt  
Body:
{
"key_id":     "UUID",
"ciphertext": "BASE64(vN:nonce:ciphertext)"
}

**200 OK**  
{ "plaintext":"BASE64(original)" }

Errors:
- 400 Bad Request
- 500 Internal Server Error

---

#### Sign Data
POST /v1/kms/sign  
Body:
{
"key_id": "UUID",
"message":"BASE64(...)"
}

**200 OK**  
{ "signature":"BASE64(...)" }

Errors:
- 400 Bad Request
- 404 Not Found
- 500 Internal Server Error

---

#### Verify Signature
POST /v1/kms/verify  
Body:
{
"key_id":    "UUID",
"message":   "BASE64(...)",
"signature": "BASE64(...)"
}

**200 OK** (success)  
{ "valid": true }

**200 OK** (failure)  
{ "valid": false, "error": "signature invalid" }


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
