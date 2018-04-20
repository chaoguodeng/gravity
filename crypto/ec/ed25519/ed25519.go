package ed25519

import (
	"crypto"
	"io"

	"github.com/sammy00/gravity/crypto/ec"
	stdEd25519 "golang.org/x/crypto/ed25519"
)

type PublicKey = stdEd25519.PublicKey

type PrivateKey struct {
	stdEd25519.PrivateKey
	PublicKey
}

// Worker works according to ed25519
type Worker struct{}

// GenerateKey generates a (priv,pub) EC key pair
func (ed *Worker) GenerateKey(rand io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
	var privKey PrivateKey
	var err error

	if privKey.PublicKey, privKey.PrivateKey, err = stdEd25519.GenerateKey(rand); nil != err {
		return nil, nil, err
	}

	return privKey, privKey.PublicKey, nil
}

// Sign signs digest with privKey.
func (ed *Worker) Sign(privKey crypto.PrivateKey, digest []byte) (ec.Sig, error) {
	priv, ok := privKey.(PrivateKey)
	if !ok || (len(priv.PrivateKey) != stdEd25519.PrivateKeySize) {
		return nil, ec.ErrKeyTampered
	}

	return stdEd25519.Sign(priv.PrivateKey, digest), nil
}

// Verify verifies the signature in sig of hash using the public key, pubKey.
// Its return value records whether the signature is valid.
func (ed *Worker) Verify(pubKey crypto.PublicKey, digest []byte, sig ec.Sig) bool {
	pub, ok := pubKey.(PublicKey)

	return ok && (len(pub) == stdEd25519.PublicKeySize) && stdEd25519.Verify(pub, digest, sig)
}
