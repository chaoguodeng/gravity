package ec_test

import (
	"crypto/rand"
	"testing"

	"github.com/sammy00/gravity/crypto/ec"
	"github.com/sammy00/gravity/crypto/ec/ecdsa"
	"github.com/sammy00/gravity/crypto/ec/ed25519"
	"golang.org/x/crypto/sha3"
)

func runWorker(worker ec.Worker, t *testing.T) {
	priv, err := worker.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	rawMsg := []byte("Hello World")
	digest := sha3.Sum256(rawMsg)

	sig, err := worker.Sign(priv, digest[:])
	if nil != err {
		t.Fatal(err)
	}

	if !worker.Verify(priv.Public(), digest[:], sig) {
		t.Fatal("the verification shouldn't fail")
	}
}

func TestWorker(t *testing.T) {
	ed25519Worker := new(ed25519.Worker)
	runWorker(ed25519Worker, t)

	ecdsa256Worker := new(ecdsa.Worker256)
	runWorker(ecdsa256Worker, t)

	/*
		ecdsa512Worker := new(ecdsa.Worker512)
		runWorker(ecdsa512Worker, t)
	*/

	//secp256k1Worker := new(secp.Worker)
	//runWorker(secp256k1Worker, t)

}
