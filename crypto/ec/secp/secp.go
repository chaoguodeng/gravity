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
