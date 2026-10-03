package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// Keyring maps a key id to a trusted Ed25519 public key.
type Keyring map[string]ed25519.PublicKey

// KeyID is the hex SHA-256 of the key's PKIX DER encoding, as Socair computes
// it, so the id is derivable from the public key file alone.
func KeyID(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// ParsePublicKey reads one PKIX PEM Ed25519 public key.
func ParsePublicKey(pemBytes []byte) (string, ed25519.PublicKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil || blk.Type != "PUBLIC KEY" {
		return "", nil, errors.New("not a PEM public key")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return "", nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return "", nil, fmt.Errorf("key is %T, want Ed25519", k)
	}
	id, err := KeyID(pub)
	return id, pub, err
}

// ParseKeyring reads PEM public keys into a keyring. An empty keyring is an
// error: verifying against no keys refuses everything, which is never what a
// caller configuring trust meant.
func ParseKeyring(pems ...[]byte) (Keyring, error) {
	ring := Keyring{}
	for i, p := range pems {
		id, pub, err := ParsePublicKey(p)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		ring[id] = pub
	}
	if len(ring) == 0 {
		return nil, errors.New("no trusted keys")
	}
	return ring, nil
}
