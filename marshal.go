package jwkset

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var (
	// ErrKeyUnmarshalParameter indicates that a JWK's attributes are invalid and cannot be unmarshaled.
	ErrKeyUnmarshalParameter = errors.New("unable to unmarshal JWK due to invalid attributes")
	// ErrUnsupportedKeyType indicates a key type is not supported.
	ErrUnsupportedKeyType = errors.New("unsupported key type")
)

// OtherPrimes is for RSA private keys that have more than 2 primes.
// https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
type OtherPrimes struct {
	D string `json:"d,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.2
	R string `json:"r,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.1
	T string `json:"t,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.3
}

// JWKMarshal is used to marshal or unmarshal a JSON Web Key.
// https://www.rfc-editor.org/rfc/rfc7517
// https://www.rfc-editor.org/rfc/rfc7518
// https://www.rfc-editor.org/rfc/rfc8037
type JWKMarshal struct {
	// TODO Check that ALG field is utilized fully.
	ALG ALG    `json:"alg,omitempty"` // https://www.rfc-editor.org/rfc/rfc7517#section-4.4 and https://www.rfc-editor.org/rfc/rfc7518#section-4.1
	CRV CRV    `json:"crv,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	D   string `json:"d,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.1 and https://www.rfc-editor.org/rfc/rfc7518#section-6.2.2.1 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	DP  string `json:"dp,omitempty"`  // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.4
	DQ  string `json:"dq,omitempty"`  // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.5
	E   string `json:"e,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.2
	K   string `json:"k,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.4.1
	// TODO Use KEYOPS field.
	// KEYOPTS []string `json:"key_ops,omitempty"` // https://www.rfc-editor.org/rfc/rfc7517#section-4.3
	KID string        `json:"kid,omitempty"` // https://www.rfc-editor.org/rfc/rfc7517#section-4.5
	KTY KTY           `json:"kty,omitempty"` // https://www.rfc-editor.org/rfc/rfc7517#section-4.1
	N   string        `json:"n,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.1
	OTH []OtherPrimes `json:"oth,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
	P   string        `json:"p,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.2
	Q   string        `json:"q,omitempty"`   // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.3
	QI  string        `json:"qi,omitempty"`  // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.6
	// TODO Use USE field.
	// USE USE        `json:"use,omitempty"` // https://www.rfc-editor.org/rfc/rfc7517#section-4.2
	X string `json:"x,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.2 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	// TODO X.509 related fields.
	Y string `json:"y,omitempty"` // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.3
}

// JWKSMarshal is used to marshal or unmarshal a JSON Web Key Set.
type JWKSMarshal struct {
	Keys []JWKMarshal `json:"keys"`
}

// KeyMarshalOptions are used to specify options for marshaling a JSON Web Key.
type KeyMarshalOptions struct {
	AsymmetricPrivate bool
	Symmetric         bool
}

// KeyMarshal transforms a KeyWithMeta into a JWKMarshal, which is used to marshal/unmarshal a JSON Web Key.
func KeyMarshal[CustomKeyMeta any](meta KeyWithMeta[CustomKeyMeta], options KeyMarshalOptions) (JWKMarshal, error) {
	var jwk JWKMarshal
	switch key := meta.Key.(type) {
	case *ecdsa.PrivateKey:
		pub := key.PublicKey
		jwk.CRV = CRV(pub.Curve.Params().Name)
		jwk.X = bigIntToBase64RawURL(pub.X)
		jwk.Y = bigIntToBase64RawURL(pub.Y)
		jwk.KTY = KtyEC
		if options.AsymmetricPrivate {
			jwk.D = bigIntToBase64RawURL(key.D)
		}
	case *ecdsa.PublicKey:
		jwk.CRV = CRV(key.Curve.Params().Name)
		jwk.X = bigIntToBase64RawURL(key.X)
		jwk.Y = bigIntToBase64RawURL(key.Y)
		jwk.KTY = KtyEC
	case ed25519.PrivateKey:
		pub := key.Public().(ed25519.PublicKey)
		jwk.ALG = AlgEdDSA
		jwk.CRV = CrvEd25519
		jwk.X = base64.RawURLEncoding.EncodeToString(pub)
		jwk.KTY = KtyOKP
		if options.AsymmetricPrivate {
			jwk.D = base64.RawURLEncoding.EncodeToString(key[:32])
		}
	case ed25519.PublicKey:
		jwk.ALG = AlgEdDSA
		jwk.CRV = CrvEd25519
		jwk.X = base64.RawURLEncoding.EncodeToString(key)
		jwk.KTY = KtyOKP
	case *rsa.PrivateKey:
		pub := key.PublicKey
		jwk.E = bigIntToBase64RawURL(big.NewInt(int64(pub.E)))
		jwk.N = bigIntToBase64RawURL(pub.N)
		jwk.KTY = KtyRSA
		if options.AsymmetricPrivate {
			jwk.D = bigIntToBase64RawURL(key.D)
			jwk.P = bigIntToBase64RawURL(key.Primes[0])
			jwk.Q = bigIntToBase64RawURL(key.Primes[1])
			jwk.DP = bigIntToBase64RawURL(key.Precomputed.Dp)
			jwk.DQ = bigIntToBase64RawURL(key.Precomputed.Dq)
			jwk.QI = bigIntToBase64RawURL(key.Precomputed.Qinv)
			if len(key.Precomputed.CRTValues) > 0 {
				jwk.OTH = make([]OtherPrimes, len(key.Precomputed.CRTValues))
				for i := 0; i < len(key.Precomputed.CRTValues); i++ {
					jwk.OTH[i] = OtherPrimes{
						D: bigIntToBase64RawURL(key.Precomputed.CRTValues[i].Exp),
						T: bigIntToBase64RawURL(key.Precomputed.CRTValues[i].Coeff),
						R: bigIntToBase64RawURL(key.Primes[i+2]),
					}
				}
			}
		}
	case *rsa.PublicKey:
		jwk.E = bigIntToBase64RawURL(big.NewInt(int64(key.E)))
		jwk.N = bigIntToBase64RawURL(key.N)
		jwk.KTY = KtyRSA
	case []byte:
		if options.Symmetric {
			jwk.KTY = KtyOct
			jwk.K = base64.RawURLEncoding.EncodeToString(key)
		} else {
			return JWKMarshal{}, fmt.Errorf("%w: incorrect options to marshal symmetric key (oct)", ErrUnsupportedKeyType)
		}
	default:
		return JWKMarshal{}, fmt.Errorf("%w: %T", ErrUnsupportedKeyType, key)
	}
	if meta.ALG != "" {
		jwk.ALG = meta.ALG
	}
	jwk.KID = meta.KeyID
	return jwk, nil
}

// KeyUnmarshalOptions are used to specify options for unmarshaling a JSON Web Key.
type KeyUnmarshalOptions struct {
	AsymmetricPrivate bool
	Symmetric         bool
}

// KeyUnmarshal transforms a JWKMarshal into a KeyWithMeta, which contains the correct Go type for the cryptographic
// key.
func KeyUnmarshal[CustomKeyMeta any](jwk JWKMarshal, options KeyUnmarshalOptions) (KeyWithMeta[CustomKeyMeta], error) {
	var meta KeyWithMeta[CustomKeyMeta]
	switch jwk.KTY {
	case KtyEC:
		if jwk.CRV == "" || jwk.X == "" || jwk.Y == "" {
			return meta, fmt.Errorf(`%w: %s requires parameters "crv", "x", and "y"`, ErrKeyUnmarshalParameter, KtyEC)
		}
		x, err := base64urlTrailingPadding(jwk.X)
		if err != nil {
			return meta, fmt.Errorf(`failed to decode %s key parameter "x": %w`, KtyEC, err)
		}
		y, err := base64urlTrailingPadding(jwk.Y)
		if err != nil {
			return meta, fmt.Errorf(`failed to decode %s key parameter "y": %w`, KtyEC, err)
		}
		publicKey := &ecdsa.PublicKey{
			X: new(big.Int).SetBytes(x),
			Y: new(big.Int).SetBytes(y),
		}
		switch jwk.CRV {
		case CrvP256:
			publicKey.Curve = elliptic.P256()
		case CrvP384:
			publicKey.Curve = elliptic.P384()
		case CrvP521:
			publicKey.Curve = elliptic.P521()
		default:
			return meta, fmt.Errorf("%w: unsupported curve type %q", ErrKeyUnmarshalParameter, jwk.CRV)
		}
		if options.AsymmetricPrivate && jwk.D != "" {
			d, err := base64urlTrailingPadding(jwk.D)
			if err != nil {
				return meta, fmt.Errorf(`failed to decode %s key parameter "d": %w`, KtyEC, err)
			}
			privateKey := &ecdsa.PrivateKey{
				PublicKey: *publicKey,
				D:         new(big.Int).SetBytes(d),
			}
			meta.Key = privateKey
		} else {
			meta.Key = publicKey
		}
	case KtyOKP:
		if jwk.CRV != CrvEd25519 {
			return meta, fmt.Errorf("%w: %s key type should have %q curve", ErrKeyUnmarshalParameter, KtyOKP, CrvEd25519)
		}
		if jwk.X == "" {
			return meta, fmt.Errorf(`%w: %s requires parameter "x"`, ErrKeyUnmarshalParameter, KtyOKP)
		}
		public, err := base64urlTrailingPadding(jwk.X)
		if err != nil {
			return meta, fmt.Errorf(`failed to decode %s key parameter "x": %w`, KtyOKP, err)
		}
		if len(public) != ed25519.PublicKeySize {
			return meta, fmt.Errorf("%w: %s key should be %d bytes", ErrKeyUnmarshalParameter, KtyOKP, ed25519.PublicKeySize)
		}
		if options.AsymmetricPrivate && jwk.D != "" {
			private, err := base64urlTrailingPadding(jwk.D)
			if err != nil {
				return meta, fmt.Errorf(`failed to decode %s key parameter "d": %w`, KtyOKP, err)
			}
			private = append(private, public...)
			if len(private) != ed25519.PrivateKeySize {
				return meta, fmt.Errorf("%w: %s key should be %d bytes", ErrKeyUnmarshalParameter, KtyOKP, ed25519.PrivateKeySize)
			}
			meta.Key = ed25519.PrivateKey(private)
		} else {
			meta.Key = ed25519.PublicKey(public)
		}
	case KtyRSA:
		if jwk.N == "" || jwk.E == "" {
			return meta, fmt.Errorf(`%w: %s requires parameters "n" and "e"`, ErrKeyUnmarshalParameter, KtyRSA)
		}
		n, err := base64urlTrailingPadding(jwk.N)
		if err != nil {
			return meta, fmt.Errorf(`failed to decode %s key parameter "n": %w`, KtyRSA, err)
		}
		e, err := base64urlTrailingPadding(jwk.E)
		if err != nil {
			return meta, fmt.Errorf(`failed to decode %s key parameter "e": %w`, KtyRSA, err)
		}
		publicKey := rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Uint64()),
		}
		if options.AsymmetricPrivate && jwk.D != "" && jwk.P != "" && jwk.Q != "" && jwk.DP != "" && jwk.DQ != "" && jwk.QI != "" { // TODO Only "d" is required, but if one of the others is present, they all must be.
			d, err := base64urlTrailingPadding(jwk.D)
			if err != nil {
				return meta, fmt.Errorf(`failed to decode %s key parameter "d": %w`, KtyRSA, err)
			}
			p, err := base64urlTrailingPadding(jwk.P)
			if err != nil {
				return meta, fmt.Errorf(`failed to decode %s key parameter "p": %w`, KtyRSA, err)
			}
			q, err := base64urlTrailingPadding(jwk.Q)
			if err != nil {
				return meta, fmt.Errorf(`failed to decode %s key parameter "q": %w`, KtyRSA, err)
			}
			dp, err := base64urlTrailingPadding(jwk.DP)
			if err != nil {
				return meta, fmt.Errorf(`failed to decode %s key parameter "dp": %w`, KtyRSA, err)
			}
			dq, err := base64urlTrailingPadding(jwk.DQ)
			if err != nil {
				return meta, fmt.Errorf(`failed to decode %s key parameter "dq": %w`, KtyRSA, err)
			}
			qi, err := base64urlTrailingPadding(jwk.QI)
			if err != nil {
				return meta, fmt.Errorf(`failed to decode %s key parameter "qi": %w`, KtyRSA, err)
			}
			var oth []rsa.CRTValue
			primes := []*big.Int{
				new(big.Int).SetBytes(p),
				new(big.Int).SetBytes(q),
			}
			if len(jwk.OTH) > 0 {
				oth = make([]rsa.CRTValue, len(jwk.OTH))
				for i, otherPrimes := range jwk.OTH {
					if otherPrimes.R == "" || otherPrimes.D == "" || otherPrimes.T == "" {
						return meta, fmt.Errorf(`%w: %s requires parameters "r", "d", and "t" for each "oth"`, ErrKeyUnmarshalParameter, KtyRSA)
					}
					othD, err := base64urlTrailingPadding(otherPrimes.D)
					if err != nil {
						return meta, fmt.Errorf(`failed to decode %s key parameter "d": %w`, KtyRSA, err)
					}
					othT, err := base64urlTrailingPadding(otherPrimes.T)
					if err != nil {
						return meta, fmt.Errorf(`failed to decode %s key parameter "t": %w`, KtyRSA, err)
					}
					othR, err := base64urlTrailingPadding(otherPrimes.R)
					if err != nil {
						return meta, fmt.Errorf(`failed to decode %s key parameter "r": %w`, KtyRSA, err)
					}
					primes = append(primes, new(big.Int).SetBytes(othR))
					oth[i] = rsa.CRTValue{
						Exp:   new(big.Int).SetBytes(othD),
						Coeff: new(big.Int).SetBytes(othT),
						R:     new(big.Int).SetBytes(othR),
					}
				}
			}
			privateKey := &rsa.PrivateKey{
				PublicKey: publicKey,
				D:         new(big.Int).SetBytes(d),
				Primes:    primes,
				Precomputed: rsa.PrecomputedValues{
					Dp:        new(big.Int).SetBytes(dp),
					Dq:        new(big.Int).SetBytes(dq),
					Qinv:      new(big.Int).SetBytes(qi),
					CRTValues: oth,
				},
			}
			err = privateKey.Validate()
			if err != nil {
				return meta, fmt.Errorf(`failed to validate %s key: %w`, KtyRSA, err)
			}
			meta.Key = privateKey
		} else if !options.AsymmetricPrivate {
			meta.Key = &publicKey
		}
	case KtyOct:
		if options.Symmetric {
			if jwk.K == "" {
				return meta, fmt.Errorf(`%w: %s requires parameter "k"`, ErrKeyUnmarshalParameter, KtyOct)
			}
			key, err := base64urlTrailingPadding(jwk.K)
			if err != nil {
				return meta, fmt.Errorf(`failed to decode %s key parameter "k": %w`, KtyOct, err)
			}
			meta.Key = key
		} else {
			return meta, fmt.Errorf("%w: incorrect options to unmarshal symmetric key (%s)", ErrUnsupportedKeyType, KtyOct)
		}
	default:
		return meta, fmt.Errorf("%w: %s", ErrUnsupportedKeyType, jwk.KTY)
	}
	meta.ALG = jwk.ALG
	meta.KeyID = jwk.KID
	return meta, nil
}

// base64urlTrailingPadding removes trailing padding before decoding a string from base64url. Some non-RFC compliant
// JWKS contain padding at the end values for base64url encoded public keys.
//
// Trailing padding is required to be removed from base64url encoded keys.
// RFC 7517 defines base64url the same as RFC 7515 Section 2:
// https://datatracker.ietf.org/doc/html/rfc7517#section-1.1
// https://datatracker.ietf.org/doc/html/rfc7515#section-2
func base64urlTrailingPadding(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}

func bigIntToBase64RawURL(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}
