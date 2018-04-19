package ec_test

import (
	"crypto/rand"
	"testing"

	"github.com/sammy00/gravity/crypto/ec"
	"golang.org/x/crypto/sha3"
)

func TestECDSA256(t *testing.T) {
	priv, pub, err := ec.GenerateKey(ec.ECDSA256, rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	rawMsg := []byte("Hello World")
	digest := sha3.Sum256(rawMsg)

	sig, err := ec.Sign(priv, digest[:])
	if nil != err {
		t.Fatal(err)
	}

	// pubKey, digest and sig are all valid
	if !ec.Verify(pub, digest[:], sig) {
		t.Fatal("the signature shouldn't fail")
	}

	// corrupted digest
	digest[11] = ^digest[11]
	if ec.Verify(pub, digest[:], sig) {
		t.Fatal("the signature should fail")
	}
}

func TestECDSA512(t *testing.T) {
	priv, pub, err := ec.GenerateKey(ec.ECDSA512, rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	rawMsg := []byte("Hello World")
	digest := sha3.Sum256(rawMsg)

	sig, err := ec.Sign(priv, digest[:])
	if nil != err {
		t.Fatal(err)
	}

	if !ec.Verify(pub, digest[:], sig) {
		t.Fatal("the signature shouldn't fail")
	}
}

func TestED25519(t *testing.T) {
	priv, pub, err := ec.GenerateKey(ec.ED25519, rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	rawMsg := []byte("Hello World")
	digest := sha3.Sum256(rawMsg)

	sig, err := ec.Sign(priv, digest[:])
	if nil != err {
		t.Fatal(err)
	}

	if !ec.Verify(pub, digest[:], sig) {
		t.Fatal("the signature shouldn't fail")
	}
}
