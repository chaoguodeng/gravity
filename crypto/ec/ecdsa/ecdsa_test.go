package ecdsa_test

import (
	"crypto/rand"
	"testing"

	"github.com/sammy00/gravity/crypto/ec/ecdsa"
	"golang.org/x/crypto/sha3"
)

func TestECDSA256(t *testing.T) {
	wkr256 := new(ecdsa.Worker256)
	priv, pub, err := wkr256.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	rawMsg := []byte("Hello World")
	digest := sha3.Sum256(rawMsg)

	sig, err := wkr256.Sign(priv, digest[:])
	if nil != err {
		t.Fatal(err)
	}

	// pubKey, digest and sig are all valid
	if !wkr256.Verify(&(priv.(*ecdsa.PrivateKey).PublicKey), digest[:], sig) {
		t.Fatal("the verification shouldn't fail")
	}

	// corrupted digest
	digest[11] = ^digest[11]
	if wkr256.Verify(pub, digest[:], sig) {
		t.Fatal("the verification should fail")
	}
}

func TestECDSA512(t *testing.T) {
	wkr512 := new(ecdsa.Worker512)
	priv, pub, err := wkr512.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	rawMsg := []byte("Hello World")
	digest := sha3.Sum256(rawMsg)

	sig, err := wkr512.Sign(priv, digest[:])
	if nil != err {
		t.Fatal(err)
	}

	// pubKey, digest and sig are all valid
	if !wkr512.Verify(pub, digest[:], sig) {
		t.Fatal("the verification shouldn't fail")
	}

	// corrupted digest
	digest[11] = ^digest[11]
	if wkr512.Verify(pub, digest[:], sig) {
		t.Fatal("the verification should fail")
	}
}
