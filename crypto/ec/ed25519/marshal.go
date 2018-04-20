// Package ed25519 implements a wrapper around the standard ed25519 package to achieves generality
package ed25519

import (
	"crypto"

	"github.com/sammy00/gravity/crypto/ec"
	stdEd25519 "golang.org/x/crypto/ed25519"
)

const (
	marshalVersion   = 1
	unmarshalVersion = 1
)

// Marshaller works for ed25519 to marshal/unmarshal the privKey, pubKey and sig
type Marshaller struct{}

// MarshalPrivKey marshal privKey to []byte where byte[0] records the marshal version
func (msller *Marshaller) MarshalPrivKey(privKey crypto.PrivateKey) ([]byte, error) {
	priv, ok := privKey.(PrivateKey)
	if !ok || (len(priv.PrivateKey) != stdEd25519.PrivateKeySize) {
		return nil, ec.ErrKeyTampered
	}
	result := make([]byte, 1)
	result[0] = byte(marshalVersion)
	return append(result, priv.PrivateKey...), nil
}

// UnmarshalPrivKey unmarshal privKeyBytes to privKey
func (msller *Marshaller) UnmarshalPrivKey(privKeyBytes []byte) (crypto.PrivateKey, error) {
	if len(privKeyBytes) == 0 || int(privKeyBytes[0]) != unmarshalVersion {
		return nil, ec.ErrWrongVersion
	}
	var privKey PrivateKey
	privKey.PrivateKey = privKeyBytes[1:]
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
	return append(result, pub...), nil
}

// UnmarshalPubKey unmarshal pubKeyBytes to pubKey
func (msller *Marshaller) UnmarshalPubKey(pubKeyBytes []byte) (crypto.PublicKey, error) {
	if len(pubKeyBytes) == 0 || int(pubKeyBytes[0]) != unmarshalVersion {
		return nil, ec.ErrWrongVersion
	}
	var pubKey PublicKey
	pubKey = pubKeyBytes[1:]
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
