package secp_test

import (
	"crypto/rand"
	"testing"

	"github.com/sammy00/gravity/crypto/ec/secp"
	"golang.org/x/crypto/sha3"
)

func TestSecp256k1(t *testing.T) {
	w := new(secp.Worker)
	priv, pub, err := w.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	rawMsg := []byte("Hello World")
	digest := sha3.Sum256(rawMsg)

	sig, err := w.Sign(priv, digest[:])
	if nil != err {
		t.Fatal(err)
	}

	// pubKey, digest and sig are all valid
	if !w.Verify(pub, digest[:], sig) {
		t.Fatal("the verification shouldn't fail")
	}

	// corrupted digest
	digest[11] = ^digest[11]
	if w.Verify(pub, digest[:], sig) {
		t.Fatal("the verification should fail")
	}
}

func TestSecp256k1New(t *testing.T) {
	w := secp.New256()
	priv, pub, err := w.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	rawMsg := []byte("Hello World")
	digest := sha3.Sum256(rawMsg)

	sig, err := w.Sign(priv, digest[:])
	if nil != err {
		t.Fatal(err)
	}

	// pubKey, digest and sig are all valid
	if !w.Verify(pub, digest[:], sig) {
		t.Fatal("the verification shouldn't fail")
	}

	// corrupted digest
	digest[11] = ^digest[11]
	if w.Verify(pub, digest[:], sig) {
		t.Fatal("the verification should fail")
	}
}
