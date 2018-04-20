// Package ecdsa implements a wrapper around the standard ed25519 package to achieves generality
package ecdsa

import (
	"crypto"
	"encoding/asn1"
	"github.com/sammy00/gravity/crypto/ec"
)

const (
	marshalVersion   = 1
	unmarshalVersion = 1
)

// Marshaller works for ecdsa  to marshal/unmarshal the privKey, pubKey and sig
type Marshaller struct{}

// MarshalPrivKey marshal privKey to []byte where byte[0] records the marshal version
func (msller *Marshaller) MarshalPrivKey(privKey crypto.PrivateKey) ([]byte, error) {
	priv, ok := privKey.(PrivateKey)
	if !ok {
		return nil, ec.ErrKeyTampered
	}
	result := make([]byte, 1)
	result[0] = byte(marshalVersion)
	privKeyBytes, err := asn1.Marshal(priv)
	if nil != err {
		return nil, err
	}
	return append(result, privKeyBytes...), nil
}

// UnmarshalPrivKey unmarshal privKeyBytes to privKey
func (msller *Marshaller) UnmarshalPrivKey(privKeyBytes []byte) (crypto.PrivateKey, error) {
	if len(privKeyBytes) == 0 || int(privKeyBytes[0]) != unmarshalVersion {
		return nil, ec.ErrWrongVersion
	}
	privKey := new(PrivateKey)
	_, err := asn1.Unmarshal(privKeyBytes[1:], privKey)
	if nil != err {
		return nil, err
	}
	return privKey, nil
}

// MarshalPubKey marshal pubKey to []byte where byte[0] records the marshal version
func (msller *Marshaller) MarshalPubKey(pubKey crypto.PublicKey) ([]byte, error) {
	pub, ok := pubKey.(PublicKey)
	if !ok {
		return nil, ec.ErrKeyTampered
	}
	result := make([]byte, 1)
	result[0] = byte(marshalVersion)
	pubKeyBytes, err := asn1.Marshal(pub)
	if nil != err {
		return nil, err
	}
	return append(result, pubKeyBytes...), nil
}

// UnmarshalPubKey unmarshal pubKeyBytes to pubKey
func (msller *Marshaller) UnmarshalPubKey(pubKeyBytes []byte) (crypto.PublicKey, error) {
	if len(pubKeyBytes) == 0 || int(pubKeyBytes[0]) != unmarshalVersion {
		return nil, ec.ErrWrongVersion
	}
	pubKey := new(PublicKey)
	_, err := asn1.Unmarshal(pubKeyBytes[1:], pubKey)
	if nil != err {
		return nil, err
	}
	return pubKey, nil

}

// MarshalSig marshal sig to []byte where byte[0] records the marshal version
func (msller *Marshaller) MarshalSig(sig ec.Sig) ([]byte, error) {
	result := make([]byte, 1)
	result[0] = byte(marshalVersion)
	return append(result, sig...), nil
}

// UnmarshalSig unmarshal sigBytes to sig
func (msller *Marshaller) UnmarshalSig(sigBytes []byte) (ec.Sig, error) {
	if len(sigBytes) == 0 || int(sigBytes[0]) != unmarshalVersion {
		return nil, ec.ErrWrongVersion
	}

	return sigBytes[1:], nil

}
