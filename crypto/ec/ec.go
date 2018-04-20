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

// Sig is an alias for []byte for readability
type Sig = []byte

// Worker specifies the api for ec package
type Worker interface {
	// GenerateKey generates a (priv,pub) EC key pair
	GenerateKey(rand io.Reader) (crypto.PrivateKey, crypto.PublicKey, error)
	// Sign signs digest with privKey.
	Sign(privKey crypto.PrivateKey, digest []byte) (Sig, error)
	// Verify verifies the signature in sig of hash using the public key, pubKey.
	// Its return value records whether the signature is valid.
	Verify(pubKey crypto.PublicKey, digest []byte, sig Sig) bool
}
