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

type jwkMarshal struct {
	Curve    string `json:"crv,omitempty"`
	Exponent string `json:"e,omitempty"`
	K        string `json:"k,omitempty"`
	ID       string `json:"kid,omitempty"`
	Modulus  string `json:"n,omitempty"`
	Type     string `json:"kty,omitempty"`
	X        string `json:"x,omitempty"`
	Y        string `json:"y,omitempty"`
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
