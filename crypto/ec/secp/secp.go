package secp

import (
	"crypto"
	"crypto/ecdsa"
	"io"

	localECDSA "github.com/sammy00/gravity/crypto/ec/ecdsa"
	"github.com/sammy00/secp"
	"github.com/sammy00/secp/curve"
)

type PublicKey = ecdsa.PublicKey
type PrivateKey = ecdsa.PrivateKey

// Worker works according SEC over prime fields
type Worker struct {
	localECDSA.Worker256
	curve *secp.KoblitzCurve
}

// New256 produces a worker over P256
func New256() *Worker {
	w := new(Worker)

	w.curve = new(secp.KoblitzCurve)
	w.curve.BitCurve = curve.S256()

	return w
}

// New produces a default worker as New256()
func New() *Worker {
	return New256()
}

// GenerateKey generates a (priv,pub) EC key pair
func (w *Worker) GenerateKey(rand io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
	c := new(secp.KoblitzCurve)
	c.BitCurve = curve.S256()

	priv, err := ecdsa.GenerateKey(c, rand)
	if nil != err {
		return nil, nil, err
	}

	return priv, &priv.PublicKey, nil
}

// GenerateKeyNew generates a (priv,pub) EC key pair
func (w *Worker) GenerateKeyNew(rand io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(w.curve, rand)
	if nil != err {
		return nil, nil, err
	}

	return priv, &priv.PublicKey, nil
}
