package ec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/ed25519"
)

// enumerations of supported types of EC
const (
	ECDSA256 = iota
	ECDSA512
	ED25519
)

var (
	// ErrECTypeUnsupported means the type of EC is unsupported by our lib yet
	ErrECTypeUnsupported = errors.New("Unknown type of the provided elliptic curve")
	// ErrKeyTampered indicates the private key has been tampered
	ErrKeyTampered = errors.New("the key provided has been tampered")
)

// PrivateKey embeds crypto.PrivateKey and PublicKey to achieve generality
type PrivateKey struct {
	crypto.PrivateKey
	PublicKey
}

// PublicKey embeds crypto.PublicKey to achieve generality
type PublicKey struct {
	crypto.PublicKey
	ecType uint // type enum of the underlying EC
}

//ecdsaSig is a type prepared for unmarshalling the ecdsa signature from []byte to *big.Int
type ecdsaSig struct {
	R, S *big.Int
}

// Sig is an alias for []byte for readability
type Sig = []byte

func generateECDSAKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
	ecdsaPrivKey, err := ecdsa.GenerateKey(c, rand)
	if nil != err {
		return nil, err
	}

	privKey := new(PrivateKey)
	privKey.PrivateKey = ecdsaPrivKey
	privKey.PublicKey.PublicKey = &ecdsaPrivKey.PublicKey

	return privKey, nil
}

// GenerateKey generates a (priv,pub) EC key pair
func GenerateKey(ecType uint, rand io.Reader) (*PrivateKey, *PublicKey, error) {
	privKey := new(PrivateKey)
	var err error

	switch ecType {
	case ECDSA256:
		privKey, err = generateECDSAKey(elliptic.P256(), rand)
	case ECDSA512:
		privKey, err = generateECDSAKey(elliptic.P521(), rand)
	case ED25519:
		privKey.PublicKey.PublicKey, privKey.PrivateKey, err = ed25519.GenerateKey(rand)
	default:
		privKey, err = nil, ErrECTypeUnsupported
	}

	if nil != err {
		return nil, nil, err
	}

	privKey.ecType = ecType // don't forget to set the ecType
	return privKey, &privKey.PublicKey, err
}

// Sign signs digest with privKey.
func Sign(privKey *PrivateKey, digest []byte) (Sig, error) {
	var sig Sig
	var err error

	switch privKey.ecType {
	case ECDSA256:
		fallthrough
	case ECDSA512:
		ecdsaPrivKey, ok := privKey.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			err = ErrKeyTampered
			break
		}
		sig, err = ecdsaPrivKey.Sign(rand.Reader, digest, nil)
	case ED25519:
		ed25519PrivKey, ok := privKey.PrivateKey.(ed25519.PrivateKey)
		if !ok || (len(ed25519PrivKey) != ed25519.PrivateKeySize) {
			err = ErrKeyTampered
			break
		}

		sig = Sig(ed25519.Sign(ed25519PrivKey, digest))
	default:
		err = ErrECTypeUnsupported
	}

	return sig, err
}

// Verify verifies the signature in sig of hash using the public key, pubKey.
// Its return value records whether the signature is valid.
func Verify(pubKey *PublicKey, digest []byte, sig Sig) bool {
	if nil == sig {
		return false
	}

	switch pubKey.ecType {
	case ECDSA256:
		fallthrough
	case ECDSA512:
		ecdsaPubKey, ok := pubKey.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			break
		}
		// unmarshal the signature for verification
		var decodedSig ecdsaSig
		if _, err := asn1.Unmarshal(sig, &decodedSig); nil != err {
			break
		}
		// verify the signature (r,s) on the digest by the corresponding public key
		return ecdsa.Verify(ecdsaPubKey, digest, decodedSig.R, decodedSig.S)
	case ED25519:
		ed25519PubKey, ok := pubKey.PublicKey.(ed25519.PublicKey)
		return ok && (len(ed25519PubKey) == ed25519.PublicKeySize) &&
			ed25519.Verify(ed25519PubKey, digest, sig)
	}

	return false
}
