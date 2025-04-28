package kmspec

// KeyPurpose is what you’re using the key for:
// "encrypt" || "sign"
type KeyPurpose string

const (
	PurposeEncrypt KeyPurpose = "encrypt"
	PurposeSign    KeyPurpose = "sign"
)

// KeyAlgorithm is the actual algorithm / curve / key size:
// Supported algorithms "AES-256-GCM" || "ChaCha20-Poly1305" || "RSA-4096" || "ECDSA-P256"
type KeyAlgorithm string

const (
	AlgAES256GCM        KeyAlgorithm = "AES-256-GCM"
	AlgChaCha20Poly1305 KeyAlgorithm = "ChaCha20-Poly1305"
	AlgRSA4096          KeyAlgorithm = "RSA-4096"
	AlgECDSAP256        KeyAlgorithm = "ECDSA-P256"
)

// KeySpec bundles an identity + its intended use + algorithm:
type KeySpec struct {
	KeyID     string
	Purpose   KeyPurpose
	Algorithm KeyAlgorithm
}
