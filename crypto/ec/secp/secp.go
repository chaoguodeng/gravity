package secp

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/sammy00/gravity/crypto/ec"
	localECDSA "github.com/sammy00/gravity/crypto/ec/ecdsa"
	"github.com/sammy00/secp"
	"github.com/sammy00/secp/curve"
)

const codecVersion = 1

type PublicKey = ecdsa.PublicKey
type PrivateKey = ecdsa.PrivateKey

// Worker works according SEC over prime fields
type Worker struct {
	localECDSA.Worker256
	curve *secp.KoblitzCurve
}

// New256 produces a worker over P256
func New256() *Worker {
	w := new(Worker)

	w.curve = new(secp.KoblitzCurve)
	w.curve.BitCurve = curve.S256()

	return w
}

// New produces a default worker as New256()
func New() *Worker {
	return New256()
}

// GenerateKey generates a (priv,pub) EC key pair
func (w *Worker) GenerateKey(rand io.Reader) (ec.PrivateKey, error) {
	c := new(secp.KoblitzCurve)
	c.BitCurve = curve.S256()

	priv, err := ecdsa.GenerateKey(c, rand)
	if nil != err {
		return nil, err
	}

	return priv, nil
}

// GenerateKeyNew generates a (priv,pub) EC key pair
func (w *Worker) GenerateKeyNew(rand io.Reader) (ec.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(w.curve, rand)
	if nil != err {
		return nil, err
	}

	return priv, nil
}

type localPublicKey struct {
	X, Y *big.Int
}
type localPrivateKey struct {
	PubKey localPublicKey
	D      *big.Int
}

/*
func (w *Worker) MarshalPrivKey(privKey ec.PrivateKey) ([]byte, error) {
	priv, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ec.ErrKeyTampered
	}


}
*/
func (w *Worker) MarshalPubKey(pubKey ec.PublicKey) ([]byte, error) {
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, ec.ErrKeyTampered
	}

	buf := new(bytes.Buffer)

	// version
	buf.WriteByte(byte(codecVersion))
	// bitSize
	bitSize := pub.Curve.Params().BitSize
	buf.WriteByte(byte((bitSize >> 8) & 0xff))
	buf.WriteByte(byte(bitSize & 0xff))

	pubBytes, err := asn1.Marshal(localPublicKey{pub.X, pub.Y})
	if nil != err {
		return nil, err
	}

	if _, err := buf.Write(pubBytes); nil != err {
		return nil, err
	}

	return buf.Bytes(), nil
}

/*
func (w *Worker) MarshalSig(sig Sig) ([]byte, error) {

}

func (w *Worker) UnmarshalPrivKey(privKeyBytes []byte) (ec.PrivateKey, error) {

}
*/
func (w *Worker) UnmarshalPubKey(pubKeyBytes []byte) (ec.PublicKey, error) {
	buf := bytes.NewBuffer(pubKeyBytes)

	version, err := buf.ReadByte()
	if nil != err {
		return nil, err
	}
	if codecVersion != version {
		return nil, ec.ErrWrongVersion
	}

	pubKey := new(ecdsa.PublicKey)
	if err := updateCurve(pubKey, buf); nil != err {
		return nil, err
	}

	localPubKey := new(localPublicKey)
	if _, err := asn1.Unmarshal(buf.Bytes(), localPubKey); nil != err {
		return nil, err
	}

	//pubKey.X.Set(localPubKey.X)
	//pubKey.Y.Set(localPubKey.Y)
	pubKey.X = localPubKey.X
	pubKey.Y = localPubKey.Y

	return pubKey, nil
}

/*
func (w *Worker) UnmarshalSig(sigBytes []byte) (Sig, error) {

}
*/

func updateCurve(pubKey *ecdsa.PublicKey, buf *bytes.Buffer) error {
	bs := make([]byte, 2)
	if n, err := buf.Read(bs); (len(bs) != n) || (nil != err) {
		return errors.New("error in reading BitSize")
	}

	var bitSize int
	bitSize = (int(bs[0]) << 8) | int(bs[1])

	var err error
	switch bitSize {
	case 256:
		pubKey.Curve = &secp.KoblitzCurve{
			BitCurve: curve.S256(),
		}
	default:
		err = errors.New("error: unsupported BitSize")
	}

	return err
}
