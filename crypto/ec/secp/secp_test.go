package secp_test

import (
	"crypto/rand"
	"testing"

	"github.com/sammy00/gravity/crypto/ec/secp"

	"golang.org/x/crypto/sha3"

	remoteSECP "github.com/sammy00/secp"
)

func TestSecp256k1(t *testing.T) {
	w := new(secp.Worker)
	priv, err := w.GenerateKey(rand.Reader)
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
	if !w.Verify(priv.Public(), digest[:], sig) {
		t.Fatal("the verification shouldn't fail")
	}

	// corrupted digest
	digest[11] = ^digest[11]
	if w.Verify(priv.Public(), digest[:], sig) {
		t.Fatal("the verification should fail")
	}
}

func TestSecp256k1New(t *testing.T) {
	w := secp.New256()
	priv, err := w.GenerateKey(rand.Reader)
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
	if !w.Verify(priv.Public(), digest[:], sig) {
		t.Fatal("the verification shouldn't fail")
	}

	// corrupted digest
	digest[11] = ^digest[11]
	if w.Verify(priv.Public(), digest[:], sig) {
		t.Fatal("the verification should fail")
	}
}

func TestPublicKeyCodec(t *testing.T) {
	w := secp.New()

	priv, err := w.GenerateKeyNew(rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	pub, ok := priv.Public().(*secp.PublicKey)
	if !ok {
		t.Fatal("type conversion failed")
	}

	pubBytes, err := w.MarshalPubKey(pub)
	if nil != err {
		t.Fatal(err)
	}

	rawPub, err := w.UnmarshalPubKey(pubBytes)
	if nil != err {
		t.Fatal(err)
	}
	pub2, ok := rawPub.(*secp.PublicKey)

	// check curve type
	bc := pub.Curve.(*remoteSECP.KoblitzCurve).BitCurve
	bc2 := pub2.Curve.(*remoteSECP.KoblitzCurve).BitCurve

	if bc != bc2 {
		t.Error("mismatched curve")
	}

	if 0 != pub.X.Cmp(pub2.X) {
		t.Errorf("mismatched X: want %s, got %x\n", pub.X, pub2.X)
	}
	if 0 != pub.Y.Cmp(pub2.Y) {
		t.Errorf("mismatched Y: want %s, got %x\n", pub.Y, pub2.Y)
	}
}
