package cryptoutil

import (
	"bytes"
	"testing"
)

func TestPBKDF2Deterministic(t *testing.T) {
	pass, salt := []byte("secret"), []byte("saltysaltsaltys") // 16 bytes
	k1 := DeriveMasterKey(pass, salt)
	k2 := DeriveMasterKey(pass, salt)
	if !bytes.Equal(k1, k2) {
		t.Fatal("master keys should match for same passphrase+salt")
	}
}

func TestWrapUnwrap(t *testing.T) {
	master := DeriveMasterKey([]byte("p"), []byte("somesalt1234567"))
	dek := []byte("this-is-32-byte-long-master-key!!")
	wrapped, err := WrapKey(master, dek)
	if err != nil {
		t.Fatalf("WrapKey error: %v", err)
	}
	out, err := UnwrapKey(master, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey error: %v", err)
	}
	if !bytes.Equal(out, dek) {
		t.Fatal("unwrap did not recover original DEK")
	}
}

func TestZeroize(t *testing.T) {
	b := []byte("sensitive-data")
	Zeroize(b)
	if bytes.Contains(b, []byte("sensitive")) {
		t.Fatal("zeroize did not clear buffer")
	}
}
