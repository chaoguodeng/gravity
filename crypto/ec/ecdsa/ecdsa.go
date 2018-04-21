// Package ecdsa implements a wrapper around the standard ecdsa package(ecdsa-256/512) to achieves generality
package ecdsa

import (
	stdEcdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"io"
	"math/big"

	"github.com/sammy00/gravity/crypto/ec"
)

// PublicKey aliases standard public key
type PublicKey = stdEcdsa.PublicKey

// PrivateKey aliases standard private key
type PrivateKey = stdEcdsa.PrivateKey

type worker struct{}

type ecdsaSig struct {
	R, S *big.Int
}

// Sign signs digest with privKey.
func (ed worker) Sign(privKey ec.PrivateKey, digest []byte) (ec.Sig, error) {
	ecdsaPrivKey, ok := privKey.(*PrivateKey)

	if !ok {
		return nil, ec.ErrKeyTampered
	}
	return ecdsaPrivKey.Sign(rand.Reader, digest, nil)
}

// Verify verifies the signature in sig of hash using the public key, pubKey.
// Its return value records whether the signature is valid.
func (ed worker) Verify(pubKey ec.PublicKey, digest []byte, sig ec.Sig) bool {
	ecdsaPubKey, ok := pubKey.(*PublicKey)
	if !ok {
		return false
	}
	// unmarshal the signature for verification
	var decodedSig ecdsaSig
	_, err := asn1.Unmarshal(sig, &decodedSig)
	// verify the signature (r,s) on the digest by the corresponding public key
	return (nil == err) && stdEcdsa.Verify(ecdsaPubKey, digest, decodedSig.R, decodedSig.S)
}

func generateKey(c elliptic.Curve, rand io.Reader) (ec.PrivateKey, error) {
	privKey := new(PrivateKey)
	var err error

	if privKey, err = stdEcdsa.GenerateKey(c, rand); nil != err {
		return nil, err
	}

	return privKey, nil
}

// Worker256 implements ecdsa-256
type Worker256 struct {
	worker
}

// GenerateKey generates a (priv,pub) EC key pair
func (ecdsa256 *Worker256) GenerateKey(rand io.Reader) (ec.PrivateKey, error) {
	return generateKey(elliptic.P256(), rand)
}

// Worker512 implements ecdsa-256
type Worker512 struct {
	worker
}

// GenerateKey generates a (priv,pub) EC key pair
func (ecdsa512 *Worker512) GenerateKey(rand io.Reader) (ec.PrivateKey, error) {
	return generateKey(elliptic.P521(), rand)
}
