// Package ecdsa implements a wrapper around the standard ed25519 package to achieves generality
package ecdsa

import (
	"crypto"
	"crypto/elliptic"
	"encoding/asn1"
	"github.com/sammy00/gravity/crypto/ec"
	"math/big"
)

const (
	marshalVersion   = 1
	unmarshalVersion = 1
)

// Marshaller works for ecdsa  to marshal/unmarshal the privKey, pubKey and sig

type ecdsaBigInt struct {
	D, X, Y *big.Int
}

// MarshalPrivKey marshal privKey to []byte where byte[0] records the marshal version
func (msller *worker) MarshalPrivKey(privKey crypto.PrivateKey) ([]byte, error) {
	priv, ok := privKey.(*PrivateKey)
	if !ok {
		return nil, ec.ErrKeyTampered
	}
	result := make([]byte, 1)
	result[0] = byte(marshalVersion)
	bytes, err := asn1.Marshal(ecdsaBigInt{priv.D, priv.X, priv.Y})
	if nil != err {
		return nil, err
	}
	return append(result, bytes...), nil
}

// UnmarshalPrivKey unmarshal privKeyBytes to privKey
func (msller *Worker256) UnmarshalPrivKey(privKeyBytes []byte) (crypto.PrivateKey, error) {
	if len(privKeyBytes) == 0 || int(privKeyBytes[0]) != unmarshalVersion {
		return nil, ec.ErrWrongVersion
	}
	privKey := new(PrivateKey)

	ecdsaBigIntKey := new(ecdsaBigInt)
	if _, err := asn1.Unmarshal(privKeyBytes[1:], ecdsaBigIntKey); nil != err {
		return nil, err
	}
	privKey.D = ecdsaBigIntKey.D
	privKey.X = ecdsaBigIntKey.X
	privKey.Y = ecdsaBigIntKey.Y
	privKey.PublicKey.Curve = elliptic.P256()
	return privKey, nil
}

// UnmarshalPrivKey unmarshal privKeyBytes to privKey
func (msller *Worker512) UnmarshalPrivKey(privKeyBytes []byte) (crypto.PrivateKey, error) {
	if len(privKeyBytes) == 0 || int(privKeyBytes[0]) != unmarshalVersion {
		return nil, ec.ErrWrongVersion
	}
	privKey := new(PrivateKey)

	ecdsaBigIntKey := new(ecdsaBigInt)
	if _, err := asn1.Unmarshal(privKeyBytes[1:], ecdsaBigIntKey); nil != err {
		return nil, err
	}
	privKey.D = ecdsaBigIntKey.D
	privKey.X = ecdsaBigIntKey.X
	privKey.Y = ecdsaBigIntKey.Y
	privKey.PublicKey.Curve = elliptic.P521()
	return privKey, nil
}

// MarshalPubKey marshal pubKey to []byte where byte[0] records the marshal version
func (msller *worker) MarshalPubKey(pubKey crypto.PublicKey) ([]byte, error) {
	pub, ok := pubKey.(*PublicKey)
	if !ok {
		return nil, ec.ErrKeyTampered
	}
	result := make([]byte, 1)
	result[0] = byte(marshalVersion)
	bytes, err := asn1.Marshal(ecdsaBigInt{D: pub.X, X: pub.X, Y: pub.Y})
	if nil != err {
		return nil, err
	}
	return append(result, bytes...), nil
}

// UnmarshalPubKey unmarshal pubKeyBytes to pubKey
func (msller *Worker256) UnmarshalPubKey(pubKeyBytes []byte) (crypto.PublicKey, error) {
	if len(pubKeyBytes) == 0 || int(pubKeyBytes[0]) != unmarshalVersion {
		return nil, ec.ErrWrongVersion
	}
	pubKey := new(PublicKey)

	ecdsaBigIntKey := new(ecdsaBigInt)
	if _, err := asn1.Unmarshal(pubKeyBytes[1:], ecdsaBigIntKey); nil != err {
		return nil, err
	}
	pubKey.X = ecdsaBigIntKey.X
	pubKey.Y = ecdsaBigIntKey.Y
	pubKey.Curve = elliptic.P256()
	return pubKey, nil
}

// UnmarshalPubKey unmarshal pubKeyBytes to pubKey
func (msller *Worker512) UnmarshalPubKey(pubKeyBytes []byte) (crypto.PublicKey, error) {
	if len(pubKeyBytes) == 0 || int(pubKeyBytes[0]) != unmarshalVersion {
		return nil, ec.ErrWrongVersion
	}
	pubKey := new(PublicKey)

	ecdsaBigIntKey := new(ecdsaBigInt)
	if _, err := asn1.Unmarshal(pubKeyBytes[1:], ecdsaBigIntKey); nil != err {
		return nil, err
	}
	pubKey.X = ecdsaBigIntKey.X
	pubKey.Y = ecdsaBigIntKey.Y
	pubKey.Curve = elliptic.P521()
	return pubKey, nil
}

// MarshalSig marshal sig to []byte where byte[0] records the marshal version
func (msller *worker) MarshalSig(sig ec.Sig) ([]byte, error) {
	result := make([]byte, 1)
	result[0] = byte(marshalVersion)
	return append(result, sig...), nil
}

// UnmarshalSig unmarshal sigBytes to sig
func (msller *worker) UnmarshalSig(sigBytes []byte) (ec.Sig, error) {
	if len(sigBytes) == 0 || int(sigBytes[0]) != unmarshalVersion {
		return nil, ec.ErrWrongVersion
	}

	return sigBytes[1:], nil

}
