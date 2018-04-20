package ed25519_test

import (
	"crypto/rand"
	"testing"

	"github.com/sammy00/gravity/crypto/ec/ed25519"
	"golang.org/x/crypto/sha3"
)

func TestED25519(t *testing.T) {
	worker := new(ed25519.Worker)

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
		t.Fatal("the verification shouldn't fail")
	}

	// corrupt a random byte of the digest
	digest[7] = ^digest[7]
	if worker.Verify(pub, digest[:], sig) {
		t.Fatal("the verification should fail")
	}
}
