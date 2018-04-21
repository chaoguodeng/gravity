package ed25519_test

import (
	"crypto/rand"
	"testing"

	"github.com/sammy00/gravity/crypto/ec/ed25519"
	"golang.org/x/crypto/sha3"
)

func TestMarshalPrivKey(t *testing.T) {
	worker := new(ed25519.Worker)

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

	marshaller := new(ed25519.Marshaller)

	//MarshalKeys
	keysBytes, err := marshaller.MarshalPrivKey(priv)
	if nil != err {
		t.Fatal(err)
	}
	//UnmarshalKeys
	priv2, err := marshaller.UnmarshalPrivKey(keysBytes)
	if nil != err {
		t.Fatal(err)
	}
	if !ByteSliceEqual(priv.(ed25519.PrivateKey).PrivateKey, priv2.(ed25519.PrivateKey).PrivateKey) ||
		!ByteSliceEqual(priv.(ed25519.PrivateKey).PublicKey, priv2.(ed25519.PrivateKey).PublicKey) {
		t.Fatal("Unmarshal keys failed")
	}

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

func TestMarshalPubKey(t *testing.T) {
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

	marshaller := new(ed25519.Marshaller)

	//MarshalKeys
	keysBytes, err := marshaller.MarshalPubKey(pub)
	if nil != err {
		t.Fatal(err)
	}
	//UnmarshalKeys
	pub2, err := marshaller.UnmarshalPubKey(keysBytes)
	if nil != err {
		t.Fatal(err)
	}
	if !ByteSliceEqual(pub.(ed25519.PublicKey), pub2.(ed25519.PublicKey)) {
		t.Fatal("Unmarshal keys failed")
	}

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

func TestMarshalSig(t *testing.T) {
	worker := new(ed25519.Worker)

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

	marshaller := new(ed25519.Marshaller)

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
