package ecdsa_test

import (
	"crypto/rand"
	"github.com/sammy00/gravity/crypto/ec/ecdsa"
	"golang.org/x/crypto/sha3"
	"testing"
)

func TestMarshalPrivKey(t *testing.T) {
	//worker := new(ecdsa.Worker256)
	worker := new(ecdsa.Worker512)
	priv, _, err := worker.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	rawMsg := []byte("Hello World")
	digest := sha3.Sum256(rawMsg)

	sig, err := worker.Sign(priv, digest[:])
	if nil != err {
		t.Fatal(err)
	}

	//marshaller := new(ecdsa.Worker256)
	marshaller := new(ecdsa.Worker512)

	//MarshalPrivKey
	privKeyBytes, err := marshaller.MarshalPrivKey(priv)
	if nil != err {
		t.Fatal(err)
	}

	//UnmarshalPrivKey
	priv2, err := marshaller.UnmarshalPrivKey(privKeyBytes)
	if nil != err {
		t.Fatal(err)
	}
	pr1 := priv.(*ecdsa.PrivateKey)
	pr2 := priv2.(*ecdsa.PrivateKey)
	if 0 != pr1.D.Cmp(pr2.D) {
		t.Fatal("D error")
	}
	if 0 != pr1.X.Cmp(pr2.X) {
		t.Fatal("X error")
	}
	if 0 != pr1.Y.Cmp(pr2.Y) {
		t.Fatal("Y error")
	}
	if !worker.Verify(&(pr2.PublicKey), digest[:], sig) {
		t.Fatal("Unmarshal privKey failed")
	}

}
func TestMarshalPubKey(t *testing.T) {
	//worker := new(ecdsa.Worker256)
	worker := new(ecdsa.Worker512)
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

	//marshaller := new(ecdsa.Worker256)
	marshaller := new(ecdsa.Worker512)

	//MarshalPubKey
	pubKeyBytes, err := marshaller.MarshalPubKey(pub)
	if nil != err {
		t.Fatal(err)
	}
	//UnmarshalPubKey
	pub2, err := marshaller.UnmarshalPubKey(pubKeyBytes)
	if nil != err {
		t.Fatal(err)
	}

	pb1 := pub.(*ecdsa.PublicKey)
	pb2 := pub2.(*ecdsa.PublicKey)

	if 0 != pb1.X.Cmp(pb2.X) {
		t.Fatal("X error")
	}
	if 0 != pb1.Y.Cmp(pb2.Y) {
		t.Fatal("Y error")
	}
	if !worker.Verify(pb2, digest[:], sig) {
		t.Fatal("Unmarshal pubKey failed")
	}

}

func TestMarshalSig(t *testing.T) {
	//worker := new(ecdsa.Worker256)
	worker := new(ecdsa.Worker512)

	priv, _, err := worker.GenerateKey(rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	rawMsg := []byte("Hello World")
	digest := sha3.Sum256(rawMsg)

	sig, err := worker.Sign(priv, digest[:])
	if nil != err {
		t.Fatal(err)
	}

	//marshaller := new(ecdsa.Worker256)
	marshaller := new(ecdsa.Worker512)

	//MarshalSig
	sigBytes, err := marshaller.MarshalSig(sig)
	if nil != err {
		t.Fatal(err)
	}
	//UnmarshalSig
	sig2, err := marshaller.UnmarshalSig(sigBytes)
	if nil != err {
		t.Fatal(err)
	}
	if !ByteSliceEqual(sig, sig2) {
		t.Fatal("Unmarshal sig failed")
	}

}

func ByteSliceEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	if (a == nil) != (b == nil) {
		return false
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}

	return true
}
