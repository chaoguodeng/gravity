package ec

import (
	"io"

	"golang.org/x/crypto/ed25519"
)

// ED25519 works according to ed25519
type ED25519 struct{}

// GenerateKey generates a (priv,pub) EC key pair
func (ed *ED25519) GenerateKey(rand io.Reader) (*PrivateKey, *PublicKey, error) {
	privKey := new(PrivateKey)
	var err error

	if privKey.PublicKey.PublicKey, privKey.PrivateKey, err = ed25519.GenerateKey(rand); nil != err {
		return nil, nil, err
	}

	return privKey, &privKey.PublicKey, nil
}

// Sign signs digest with privKey.
func (ed *ED25519) Sign(privKey *PrivateKey, digest []byte) (Sig, error) {
	priv, ok := privKey.PrivateKey.(ed25519.PrivateKey)
	if !ok || (len(priv) != ed25519.PrivateKeySize) {
		return nil, ErrKeyTampered
	}

	return ed25519.Sign(priv, digest), nil
}

// Verify verifies the signature in sig of hash using the public key, pubKey.
// Its return value records whether the signature is valid.
func (ed *ED25519) Verify(pubKey *PublicKey, digest []byte, sig Sig) bool {
	pub, ok := pubKey.PublicKey.(ed25519.PublicKey)

	return ok && (len(pub) == ed25519.PublicKeySize) && ed25519.Verify(pub, digest, sig)
}
