package ec_test

import (
	"crypto/rand"
	"testing"

	"github.com/sammy00/gravity/crypto/ec"
	"golang.org/x/crypto/sha3"
)

func TestED25519(t *testing.T) {
	worker := new(ec.ED25519)

	priv, pub, err := worker.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	rawMsg := []byte("Hello World")
	digest := sha3.Sum256(rawMsg)

	sig, err := worker.Sign(priv, digest[:])
	if nil != err {
		t.Fatal(err)
	}

	if !worker.Verify(pub, digest[:], sig) {
		t.Fatal("the signature shouldn't fail")
	}

	digest[7] = ^digest[7]
	if worker.Verify(pub, digest[:], sig) {
		t.Fatal("the signature should fail")
	}
}
