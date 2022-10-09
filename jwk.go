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
	CRTFactorExponent    string `json:"d,omitempty"`
	CRTFactorCoefficient string `json:"t,omitempty"`
	PrimeFactor          string `json:"r,omitempty"`
}

type jwkMarshal struct {
	CRTCoefficient1 string        `json:"qi,omitempty"`
	CRTExponent1    string        `json:"dp,omitempty"`
	CRTExponent2    string        `json:"dq,omitempty"`
	Curve           string        `json:"crv,omitempty"`
	D               string        `json:"d,omitempty"`
	Exponent        string        `json:"e,omitempty"`
	K               string        `json:"k,omitempty"`
	ID              string        `json:"kid,omitempty"`
	Modulus         string        `json:"n,omitempty"`
	OtherPrimes     []otherPrimes `json:"oth,omitempty"`
	Prime1          string        `json:"p,omitempty"`
	Prime2          string        `json:"q,omitempty"`
	Type            string        `json:"kty,omitempty"`
	X               string        `json:"x,omitempty"`
	Y               string        `json:"y,omitempty"`
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
			jwk.Curve = pub.Curve.Params().Name
			jwk.X = bigIntToBase64RawURL(pub.X)
			jwk.Y = bigIntToBase64RawURL(pub.Y)
			jwk.Type = KeyTypeEC.String()
			if encodePrivate {
				jwk.D = bigIntToBase64RawURL(key.D)
			}
		case ecdsa.PublicKey:
			key := meta.Key.(ecdsa.PublicKey)
			jwk.Curve = key.Curve.Params().Name
			jwk.X = bigIntToBase64RawURL(key.X)
			jwk.Y = bigIntToBase64RawURL(key.Y)
			jwk.Type = KeyTypeEC.String()
		case ed25519.PrivateKey:
			key := meta.Key.(ed25519.PrivateKey)
			pub := key.Public().(ed25519.PublicKey)
			jwk.X = base64.RawURLEncoding.EncodeToString(pub)
			jwk.Type = KeyTypeOKP.String()
			if encodePrivate {
				jwk.D = base64.RawURLEncoding.EncodeToString(key)
			}
		case ed25519.PublicKey:
			key := meta.Key.(ed25519.PublicKey)
			jwk.X = base64.RawURLEncoding.EncodeToString(key)
			jwk.Type = KeyTypeOKP.String()
		case *rsa.PrivateKey:
			key := meta.Key.(*rsa.PrivateKey)
			pub := key.PublicKey
			jwk.Exponent = bigIntToBase64RawURL(big.NewInt(int64(pub.E)))
			jwk.Modulus = bigIntToBase64RawURL(pub.N)
			jwk.Type = KeyTypeRSA.String()
			if encodePrivate {
				jwk.D = bigIntToBase64RawURL(key.D)
				jwk.Prime1 = bigIntToBase64RawURL(key.Primes[0])
				jwk.Prime2 = bigIntToBase64RawURL(key.Primes[1])
				jwk.CRTExponent1 = bigIntToBase64RawURL(key.Precomputed.Dp)
				jwk.CRTExponent2 = bigIntToBase64RawURL(key.Precomputed.Dq)
				jwk.CRTCoefficient1 = bigIntToBase64RawURL(key.Precomputed.Qinv)
				for i := 2; i < len(key.Primes); i++ {
					jwk.OtherPrimes = append(jwk.OtherPrimes, otherPrimes{
						CRTFactorExponent:    bigIntToBase64RawURL(key.Precomputed.CRTValues[i].Exp),
						CRTFactorCoefficient: bigIntToBase64RawURL(key.Precomputed.CRTValues[i].Coeff),
						PrimeFactor:          bigIntToBase64RawURL(key.Precomputed.CRTValues[i].R),
					})
				}
			}
		case rsa.PublicKey:
			key := meta.Key.(rsa.PublicKey)
			jwk.Exponent = bigIntToBase64RawURL(big.NewInt(int64(key.E)))
			jwk.Modulus = bigIntToBase64RawURL(key.N)
			jwk.Type = KeyTypeRSA.String()
		default:
			// Skip key.
			continue
		}
		jwk.ID = meta.KeyID
		jwks.Keys = append(jwks.Keys, jwk)
	}

	return json.Marshal(jwks)
}

func bigIntToBase64RawURL(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}
