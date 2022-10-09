package jwkset

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

const (
	// KeyTypeEC is the key type for ECDSA.
	KeyTypeEC KeyType = "EC"
	// KeyTypeOKP is the key type for EdDSA.
	KeyTypeOKP KeyType = "OKP"
	// KeyTypeRSA is the key type for RSA.
	KeyTypeRSA KeyType = "RSA"
	// KeyTypeOct is the key type for octet sequences, such as HMAC.
	KeyTypeOct KeyType = "oct"
)

// ErrUnsupportedKeyType is an error indicating a key type is not supported.
var ErrUnsupportedKeyType = errors.New("unsupported key type")

// KeyType is a set of "JSON Web Key Types" from https://www.iana.org/assignments/jose/jose.xhtml as mentioned in
// https://www.rfc-editor.org/rfc/rfc7517#section-4.1
type KeyType string

func (kty KeyType) String() string {
	return string(kty)
}

// KeyWithMeta is holds a Key and its metadata.
type KeyWithMeta struct {
	Key   interface{}
	KeyID string
}

// NewKey creates a new KeyWithMeta.
func NewKey(key interface{}, keyID string) KeyWithMeta {
	return KeyWithMeta{
		Key:   key,
		KeyID: keyID,
	}
}

// OtherPrimes is for RSA private keys that have more than 2 primes.
// https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
type OtherPrimes struct {
	CRTFactorExponent    string `json:"d,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.2
	CRTFactorCoefficient string `json:"t,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.3
	PrimeFactor          string `json:"r,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.1
}

// JWKMarshal is used to marshal or unmarshal a JSON Web Key.
// https://www.rfc-editor.org/rfc/rfc7517
// https://www.rfc-editor.org/rfc/rfc7518
// https://www.rfc-editor.org/rfc/rfc8037
type JWKMarshal struct {
	CRV string        `json:"crv,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	D   string        `json:"d,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.1 and https://www.rfc-editor.org/rfc/rfc7518#section-6.2.2.1 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	DP  string        `json:"dp,omitempty"`  // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.4
	DQ  string        `json:"dq,omitempty"`  // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.5
	E   string        `json:"e,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.2
	K   string        `json:"k,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.4.1
	KID string        `json:"kid,omitempty"` // https://www.rfc-editor.org/rfc/rfc7517#section-4.5
	KTY string        `json:"kty,omitempty"` // https://www.rfc-editor.org/rfc/rfc7517#section-4.1
	N   string        `json:"n,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.1
	OTH []OtherPrimes `json:"oth,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
	P   string        `json:"p,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.2
	Q   string        `json:"q,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.3
	QI  string        `json:"qi,omitempty"`  // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.6
	X   string        `json:"x,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.2 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	Y   string        `json:"y,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.3
}

// JWKSMarshal is used to marshal or unmarshal a JSON Web Key Set.
type JWKSMarshal struct {
	Keys []JWKMarshal `json:"keys"`
}

// JWKSet is a set of JSON Web Keys.
type JWKSet struct {
	Store Storage
}

// NewMemory creates a new in-memory JWKSet.
func NewMemory() JWKSet {
	return JWKSet{
		Store: NewMemoryStorage(),
	}
}

// JSON creates the JSON representation of the JWKSet.
func (j JWKSet) JSON(ctx context.Context) (json.RawMessage, error) {
	jwks := JWKSMarshal{}
	options := KeyMarshalOptions{
		EncodePrivate: false,
	}

	keys, err := j.Store.SnapshotKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot of all keys from storage: %w", err)
	}

	for _, meta := range keys {
		jwk, err := KeyMarshal(meta, options)
		if err != nil {
			if errors.Is(err, ErrUnsupportedKeyType) {
				// Ignore the key.
				continue
			}
			return nil, fmt.Errorf("failed to marshal key: %w", err)
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}

	return json.Marshal(jwks)
}

// KeyMarshalOptions are used to specify options for marshalling a JSON Web Key.
type KeyMarshalOptions struct {
	EncodePrivate bool
}

// KeyMarshal transforms a KeyWithMeta into a JWKMarshal, which is used to marshal/unmarshal a JSON Web Key.
func KeyMarshal(meta KeyWithMeta, options KeyMarshalOptions) (JWKMarshal, error) {
	var jwk JWKMarshal
	switch key := meta.Key.(type) {
	case *ecdsa.PrivateKey:
		pub := key.PublicKey
		jwk.CRV = pub.Curve.Params().Name
		jwk.X = bigIntToBase64RawURL(pub.X)
		jwk.Y = bigIntToBase64RawURL(pub.Y)
		jwk.KTY = KeyTypeEC.String()
		if options.EncodePrivate {
			jwk.D = bigIntToBase64RawURL(key.D)
		}
	case ecdsa.PublicKey:
		jwk.CRV = key.Curve.Params().Name
		jwk.X = bigIntToBase64RawURL(key.X)
		jwk.Y = bigIntToBase64RawURL(key.Y)
		jwk.KTY = KeyTypeEC.String()
	case ed25519.PrivateKey:
		pub := key.Public().(ed25519.PublicKey)
		jwk.X = base64.RawURLEncoding.EncodeToString(pub)
		jwk.KTY = KeyTypeOKP.String()
		if options.EncodePrivate {
			jwk.D = base64.RawURLEncoding.EncodeToString(key)
		}
	case ed25519.PublicKey:
		jwk.X = base64.RawURLEncoding.EncodeToString(key)
		jwk.KTY = KeyTypeOKP.String()
	case *rsa.PrivateKey:
		pub := key.PublicKey
		jwk.E = bigIntToBase64RawURL(big.NewInt(int64(pub.E)))
		jwk.N = bigIntToBase64RawURL(pub.N)
		jwk.KTY = KeyTypeRSA.String()
		if options.EncodePrivate {
			jwk.D = bigIntToBase64RawURL(key.D)
			jwk.P = bigIntToBase64RawURL(key.Primes[0])
			jwk.Q = bigIntToBase64RawURL(key.Primes[1])
			jwk.DP = bigIntToBase64RawURL(key.Precomputed.Dp)
			jwk.DQ = bigIntToBase64RawURL(key.Precomputed.Dq)
			jwk.QI = bigIntToBase64RawURL(key.Precomputed.Qinv)
			for i := 2; i < len(key.Primes); i++ {
				jwk.OTH = append(jwk.OTH, OtherPrimes{
					CRTFactorExponent:    bigIntToBase64RawURL(key.Precomputed.CRTValues[i].Exp),
					CRTFactorCoefficient: bigIntToBase64RawURL(key.Precomputed.CRTValues[i].Coeff),
					PrimeFactor:          bigIntToBase64RawURL(key.Precomputed.CRTValues[i].R),
				})
			}
		}
	case rsa.PublicKey:
		jwk.E = bigIntToBase64RawURL(big.NewInt(int64(key.E)))
		jwk.N = bigIntToBase64RawURL(key.N)
		jwk.KTY = KeyTypeRSA.String()
	default:
		return JWKMarshal{}, fmt.Errorf("%w: %T", ErrUnsupportedKeyType, key)
	}
	jwk.KID = meta.KeyID
	return jwk, nil
}

func bigIntToBase64RawURL(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}
