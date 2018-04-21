// Package ec specifies the exported API
package ec

// all algorithms of the EC category consists of 3 components as
// + Worker.GenerateKey() prepares a (priv,pub) pair for later signing and verifying
// + then Worker.Sign() makes up the signature on the digest of the targeted message based on the private key
// + finally Worker.Verify()

// currently, there are 3 implementations of Worker
// ecdsa.Worker256, ecdsa.Worker512, ed25519.Worker

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
	//ErrWrongVersion indicates the unmarshal version doesn't match the marshal version
	ErrWrongVersion = errors.New("Mismatching unmarshal version")
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

type Marshaller interface {
	MarshalKeys(privKey crypto.PrivateKey) ([]byte, error)
	MarshalSig(sig Sig) ([]byte, error)

	UnmarshalKeys(privKeyBytes []byte) (crypto.PrivateKey, error)
	UnmarshalSig(sigBytes []byte) (Sig, error)
}
