package ec

import (
	"crypto"
	"errors"
	"io"
)

var (
	// ErrECTypeUnsupported means the type of EC is unsupported by our lib yet
	ErrECTypeUnsupported = errors.New("Unknown type of the provided elliptic curve")
	// ErrKeyTampered indicates the private key has been tampered
	ErrKeyTampered = errors.New("the key provided has been tampered")
)

// PrivateKey embeds crypto.PrivateKey and PublicKey to achieve generality
type PrivateKey struct {
	crypto.PrivateKey
	PublicKey
}

// PublicKey embeds crypto.PublicKey to achieve generality
type PublicKey struct {
	crypto.PublicKey
	ecType uint // type enum of the underlying EC
}

// Sig is an alias for []byte for readability
type Sig = []byte

// EC specifies the api for ec package
type EC interface {
	// GenerateKey generates a (priv,pub) EC key pair
	GenerateKey(uint, io.Reader) (*PrivateKey, *PublicKey, error)
	// Sign signs digest with privKey.
	Sign(privKey *PrivateKey, digest []byte) (Sig, error)
	// Verify verifies the signature in sig of hash using the public key, pubKey.
	// Its return value records whether the signature is valid.
	Verify(pubKey *PublicKey, digest []byte, sig Sig) bool
}
