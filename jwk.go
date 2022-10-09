package jwkset

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
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

// otherPrimes is for RSA private keys.
// https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
type otherPrimes struct {
	CRTFactorExponent    string `json:"d,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.2
	CRTFactorCoefficient string `json:"t,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.3
	PrimeFactor          string `json:"r,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.1
}

type jwkMarshal struct {
	CRV string        `json:"crv,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	D   string        `json:"d,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.1 and https://www.rfc-editor.org/rfc/rfc7518#section-6.2.2.1 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	DP  string        `json:"dp,omitempty"`  // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.4
	DQ  string        `json:"dq,omitempty"`  // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.5
	E   string        `json:"e,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.2
	K   string        `json:"k,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.4.1
	KID string        `json:"kid,omitempty"` // https://www.rfc-editor.org/rfc/rfc7517#section-4.5
	KTY string        `json:"kty,omitempty"` // https://www.rfc-editor.org/rfc/rfc7517#section-4.1
	N   string        `json:"n,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.1
	OTH []otherPrimes `json:"oth,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
	P   string        `json:"p,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.2
	Q   string        `json:"q,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.3
	QI  string        `json:"qi,omitempty"`  // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.6
	X   string        `json:"x,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.2 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	Y   string        `json:"y,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.3
}

type jwkSetMarshal struct {
	Keys []jwkMarshal `json:"keys"`
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
	jwks := jwkSetMarshal{}
	encodePrivate := false

	keys, err := j.Store.SnapshotKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot of all keys from storage: %w", err)
	}

	for _, meta := range keys {
		jwk := jwkMarshal{}
		switch meta.Key.(type) {
		case *ecdsa.PrivateKey:
			key := meta.Key.(*ecdsa.PrivateKey)
			pub := key.PublicKey
			jwk.CRV = pub.Curve.Params().Name
			jwk.X = bigIntToBase64RawURL(pub.X)
			jwk.Y = bigIntToBase64RawURL(pub.Y)
			jwk.KTY = KeyTypeEC.String()
			if encodePrivate {
				jwk.D = bigIntToBase64RawURL(key.D)
			}
		case ecdsa.PublicKey:
			key := meta.Key.(ecdsa.PublicKey)
			jwk.CRV = key.Curve.Params().Name
			jwk.X = bigIntToBase64RawURL(key.X)
			jwk.Y = bigIntToBase64RawURL(key.Y)
			jwk.KTY = KeyTypeEC.String()
		case ed25519.PrivateKey:
			key := meta.Key.(ed25519.PrivateKey)
			pub := key.Public().(ed25519.PublicKey)
			jwk.X = base64.RawURLEncoding.EncodeToString(pub)
			jwk.KTY = KeyTypeOKP.String()
			if encodePrivate {
				jwk.D = base64.RawURLEncoding.EncodeToString(key)
			}
		case ed25519.PublicKey:
			key := meta.Key.(ed25519.PublicKey)
			jwk.X = base64.RawURLEncoding.EncodeToString(key)
			jwk.KTY = KeyTypeOKP.String()
		case *rsa.PrivateKey:
			key := meta.Key.(*rsa.PrivateKey)
			pub := key.PublicKey
			jwk.E = bigIntToBase64RawURL(big.NewInt(int64(pub.E)))
			jwk.N = bigIntToBase64RawURL(pub.N)
			jwk.KTY = KeyTypeRSA.String()
			if encodePrivate {
				jwk.D = bigIntToBase64RawURL(key.D)
				jwk.P = bigIntToBase64RawURL(key.Primes[0])
				jwk.Q = bigIntToBase64RawURL(key.Primes[1])
				jwk.DP = bigIntToBase64RawURL(key.Precomputed.Dp)
				jwk.DQ = bigIntToBase64RawURL(key.Precomputed.Dq)
				jwk.QI = bigIntToBase64RawURL(key.Precomputed.Qinv)
				for i := 2; i < len(key.Primes); i++ {
					jwk.OTH = append(jwk.OTH, otherPrimes{
						CRTFactorExponent:    bigIntToBase64RawURL(key.Precomputed.CRTValues[i].Exp),
						CRTFactorCoefficient: bigIntToBase64RawURL(key.Precomputed.CRTValues[i].Coeff),
						PrimeFactor:          bigIntToBase64RawURL(key.Precomputed.CRTValues[i].R),
					})
				}
			}
		case rsa.PublicKey:
			key := meta.Key.(rsa.PublicKey)
			jwk.E = bigIntToBase64RawURL(big.NewInt(int64(key.E)))
			jwk.N = bigIntToBase64RawURL(key.N)
			jwk.KTY = KeyTypeRSA.String()
		default:
			// Skip key.
			continue
		}
		jwk.KID = meta.KeyID
		jwks.Keys = append(jwks.Keys, jwk)
	}

	return json.Marshal(jwks)
}

func bigIntToBase64RawURL(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}
