package jwkset

import (
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

var ErrThumbprintNotSupported = errors.New("thumbprint not supported")

// thumbprint implements [RFC 7638: JSON Web Key (JWK) Thumbprint] for private and public keys.
//
// Keys are canonicalized into thumbprint JSON and then hashed. The hash function is user-defined. A default of
// SHA-256 is used if nil is provided.
//
// [RFC 7638: JSON Web Key (JWK) Thumbprint]: https://www.rfc-editor.org/info/rfc7638/
func thumbprint(key any, h hash.Hash) (string, error) {
	var json string
	switch k := key.(type) {
	case crypto.Signer:
		// the thumbprint for private signing keys is the thumbprint of its corresponding public key
		return thumbprint(k.Public(), h)
	case *ecdsa.PublicKey:
		crv, err := func() (string, error) {
			switch k.Curve {
			case elliptic.P256():
				return "P-256", nil
			case elliptic.P384():
				return "P-384", nil
			case elliptic.P521():
				return "P-521", nil
			default:
				return "", fmt.Errorf("%w: curve not supported", ErrThumbprintNotSupported)
			}
		}()
		if err != nil {
			return "", err
		}
		raw, err := k.Bytes()
		if err != nil {
			return "", err
		}
		coordLen := (k.Curve.Params().BitSize + 7) / 8
		x := base64.RawURLEncoding.EncodeToString(raw[1 : 1+coordLen])
		y := base64.RawURLEncoding.EncodeToString(raw[1+coordLen:])
		json = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, crv, x, y)
	case *rsa.PublicKey:
		json = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()), base64.RawURLEncoding.EncodeToString(k.N.Bytes()))
	case ed25519.PublicKey:
		json = fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, base64.RawURLEncoding.EncodeToString(k))
	case []byte:
		json = fmt.Sprintf(`{"k":%q,"kty":"oct"}`, base64.RawURLEncoding.EncodeToString(k))
	default:
		return "", fmt.Errorf("%w: key type supported", ErrThumbprintNotSupported)
	}

	h = cmp.Or(h, sha256.New())
	_, _ = h.Write([]byte(json))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
