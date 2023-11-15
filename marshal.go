package jwkset

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// TODO Implement https://datatracker.ietf.org/doc/html/rfc7517#section-7 JWK Set encryption?

var (
	// ErrOptions indicates that the given options caused an error.
	ErrOptions = errors.New("the given options caused an error")
	// ErrKeyUnmarshalParameter indicates that a JWK's attributes are invalid and cannot be unmarshaled.
	ErrKeyUnmarshalParameter = errors.New("unable to unmarshal JWK due to invalid attributes")
	// ErrUnsupportedKey indicates a key is not supported.
	ErrUnsupportedKey = errors.New("unsupported key")
)

type JWK interface {
	Key() any
	Marshal() *JWKMarshal
	X509() JWKX509Options
}

// JWKMarshalOptions are used to specify options for JSON marshaling a JWK.
type JWKMarshalOptions struct {
	// MarshalAsymmetricPrivate is used to indicate that the JWK's asymmetric private key should be JSON marshaled.
	MarshalAsymmetricPrivate bool
	// MarshalSymmetric is used to indicate that the JWK's symmetric (private) key should be JSON marshaled.
	MarshalSymmetric bool

	// UnmarshalAsymmetricPrivate is used to indicate that the JWK's asymmetric private key should be JSON unmarshalled.
	UnmarshalAsymmetricPrivate bool
	// UnmarshalSymmetric is used to indicate that the JWK's symmetric (private) key should be JSON unmarshalled.
	UnmarshalSymmetric bool
}

// JWKX509Options holds the X.509 certificate information for a JWK. This data structure is not used for JSON marshaling.
type JWKX509Options struct {
	// X5C contains a chain of one or more PKIX certificates. The PKIX certificate containing the key value MUST be the
	// first certificate.
	X5C []*x509.Certificate // The PKIX certificate containing the key value MUST be the first certificate.

	// X5T is calculated automatically.
	// X5TS256 is calculated automatically.

	// X5U Is a URI that refers to a resource for an X.509 public key certificate or certificate chain.
	X5U string // https://www.rfc-editor.org/rfc/rfc7517#section-4.6
}

// JWKOptions are used to specify options for marshaling a JSON Web Key.
type JWKOptions struct {
	Marshal JWKMarshalOptions
	X509    JWKX509Options
}

type jwk struct {
	key     any
	marshal *JWKMarshal
	options JWKOptions
}

func NewJWKFromKey(key any, options JWKMarshalOptions) (JWK, error) {
	opts := JWKOptions{
		Marshal: options,
	}
	marshal, err := keyMarshal(key, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON Web Key: %w", err)
	}
	j := &jwk{
		key:     key,
		marshal: marshal,
		options: opts,
	}
	return j, nil
}

func NewJWKFromMarshal(marshal *JWKMarshal, options JWKMarshalOptions) (JWK, error) {
	j, err := keyUnmarshal(marshal, options)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON Web Key: %w", err)
	}
	return j, nil
}

func NewJWKFromX509(options JWKOptions) (JWK, error) {
	if len(options.X509.X5C) == 0 {
		return nil, fmt.Errorf("%w: no X.509 certificates provided", ErrOptions)
	}
	marshal, err := keyMarshal(options.X509.X5C[0].PublicKey, options)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON Web Key: %w", err)
	}
	j := &jwk{
		key:     options.X509.X5C[0].PublicKey,
		marshal: marshal,
		options: options,
	}
	return j, nil
}

func (j *jwk) Key() any {
	return j.key
}
func (j *jwk) Marshal() *JWKMarshal {
	return j.marshal
}
func (j *jwk) X509() JWKX509Options { // TODO Remove?
	return j.options.X509
}
func (j *jwk) MarshalJSON() ([]byte, error) {
	return json.Marshal(j.marshal) // TODO Manipulation needed.
}
func (j *jwk) UnmarshalJSON(bytes []byte) error {
	return json.Unmarshal(bytes, j.marshal) // TODO Manipulation needed.
}

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
type JWKMarshal struct { // TODO Remove "KeyWithMeta" and use a JSON ignored field to get the key that is unexported. Use method to get key.
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
	X       string   `json:"x,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.2 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	X5C     []string `json:"x5c,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.7 TODO Needs to marshal to standard base64.
	X5T     string   `json:"x5t,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.8 TODO Needs to marshal to base64url.
	X5TS256 string   `json:"x5t#S256,omitempty"` // https://www.rfc-editor.org/rfc/rfc7517#section-4.9 TODO Needs to marshal to base64url.
	X5U     string   `json:"x5u,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.6
	Y       string   `json:"y,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.3
}

// JWKSMarshal is used to marshal or unmarshal a JSON Web Key Set.
type JWKSMarshal struct {
	Keys []JWKMarshal `json:"keys"`
}

// KeyMarshal transforms a KeyWithMeta into a JWKMarshal, which is used to marshal/unmarshal a JSON Web Key.
func KeyMarshal[CustomKeyMeta any](meta KeyWithMeta[CustomKeyMeta], options JWKOptions) (JWKMarshal, error) { // TODO Turn into method. And for reverse.
	var jwk JWKMarshal
	marshal, err := keyMarshal(meta, options, jwk)
	if err != nil {
		return marshal, err
	}
	if meta.ALG != "" {
		jwk.ALG = meta.ALG
	}
	jwk.KID = meta.KeyID
	jwk.X5C = meta.X5C
	jwk.X5T = meta.X5T
	jwk.X5TS256 = meta.X5TS256
	jwk.X5U = meta.X5U
	return jwk, nil
}

func keyMarshal(key any, options JWKOptions) (*JWKMarshal, error) {
	m := &JWKMarshal{}
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		pub := key.PublicKey
		m.CRV = CRV(pub.Curve.Params().Name)
		m.X = bigIntToBase64RawURL(pub.X)
		m.Y = bigIntToBase64RawURL(pub.Y)
		m.KTY = KtyEC
		if options.Marshal.MarshalAsymmetricPrivate {
			m.D = bigIntToBase64RawURL(key.D)
		}
	case *ecdsa.PublicKey:
		m.CRV = CRV(key.Curve.Params().Name)
		m.X = bigIntToBase64RawURL(key.X)
		m.Y = bigIntToBase64RawURL(key.Y)
		m.KTY = KtyEC
	case ed25519.PrivateKey:
		pub := key.Public().(ed25519.PublicKey)
		m.ALG = AlgEdDSA
		m.CRV = CrvEd25519
		m.X = base64.RawURLEncoding.EncodeToString(pub)
		m.KTY = KtyOKP
		if options.Marshal.MarshalAsymmetricPrivate {
			m.D = base64.RawURLEncoding.EncodeToString(key[:32])
		}
	case ed25519.PublicKey:
		m.ALG = AlgEdDSA
		m.CRV = CrvEd25519
		m.X = base64.RawURLEncoding.EncodeToString(key)
		m.KTY = KtyOKP
	case *rsa.PrivateKey:
		pub := key.PublicKey
		m.E = bigIntToBase64RawURL(big.NewInt(int64(pub.E)))
		m.N = bigIntToBase64RawURL(pub.N)
		m.KTY = KtyRSA
		if options.Marshal.MarshalAsymmetricPrivate {
			m.D = bigIntToBase64RawURL(key.D)
			m.P = bigIntToBase64RawURL(key.Primes[0])
			m.Q = bigIntToBase64RawURL(key.Primes[1])
			m.DP = bigIntToBase64RawURL(key.Precomputed.Dp)
			m.DQ = bigIntToBase64RawURL(key.Precomputed.Dq)
			m.QI = bigIntToBase64RawURL(key.Precomputed.Qinv)
			if len(key.Precomputed.CRTValues) > 0 {
				m.OTH = make([]OtherPrimes, len(key.Precomputed.CRTValues))
				for i := 0; i < len(key.Precomputed.CRTValues); i++ {
					m.OTH[i] = OtherPrimes{
						D: bigIntToBase64RawURL(key.Precomputed.CRTValues[i].Exp),
						T: bigIntToBase64RawURL(key.Precomputed.CRTValues[i].Coeff),
						R: bigIntToBase64RawURL(key.Primes[i+2]),
					}
				}
			}
		}
	case *rsa.PublicKey:
		m.E = bigIntToBase64RawURL(big.NewInt(int64(key.E)))
		m.N = bigIntToBase64RawURL(key.N)
		m.KTY = KtyRSA
	case []byte:
		if options.Marshal.MarshalSymmetric {
			m.KTY = KtyOct
			m.K = base64.RawURLEncoding.EncodeToString(key)
		} else {
			return nil, fmt.Errorf("%w: incorrect options to marshal symmetric key (oct)", ErrOptions)
		}
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, key)
	}
	for i, cert := range options.X509.X5C {
		m.X5C = append(m.X5C, base64.StdEncoding.EncodeToString(cert.Raw))
		if i == 0 {
			h1 := sha1.Sum(cert.Raw)
			m.X5T = base64.RawURLEncoding.EncodeToString(h1[:])
			h256 := sha256.Sum256(cert.Raw)
			m.X5TS256 = base64.RawURLEncoding.EncodeToString(h256[:])
		}
	}
	m.X5U = options.X509.X5U
	return m, nil
}

// KeyUnmarshal transforms a JWKMarshal into a KeyWithMeta, which contains the correct Go type for the cryptographic
// key.
func KeyUnmarshal[CustomKeyMeta any](jwk JWKMarshal, options JWKMarshalOptions) (KeyWithMeta[CustomKeyMeta], error) {
	var meta KeyWithMeta[CustomKeyMeta]
	keyUnmarshal(&jwk, options, &meta)
	meta.ALG = jwk.ALG
	meta.KeyID = jwk.KID
	return meta, nil
}

func keyUnmarshal(marshal *JWKMarshal, options JWKMarshalOptions) (*jwk, error) {
	var key any
	switch marshal.KTY {
	case KtyEC:
		if marshal.CRV == "" || marshal.X == "" || marshal.Y == "" {
			return nil, fmt.Errorf(`%w: %s requires parameters "crv", "x", and "y"`, ErrKeyUnmarshalParameter, KtyEC)
		}
		x, err := base64urlTrailingPadding(marshal.X)
		if err != nil {
			return nil, fmt.Errorf(`failed to decode %s key parameter "x": %w`, KtyEC, err)
		}
		y, err := base64urlTrailingPadding(marshal.Y)
		if err != nil {
			return nil, fmt.Errorf(`failed to decode %s key parameter "y": %w`, KtyEC, err)
		}
		publicKey := &ecdsa.PublicKey{
			X: new(big.Int).SetBytes(x),
			Y: new(big.Int).SetBytes(y),
		}
		switch marshal.CRV {
		case CrvP256:
			publicKey.Curve = elliptic.P256()
		case CrvP384:
			publicKey.Curve = elliptic.P384()
		case CrvP521:
			publicKey.Curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("%w: unsupported curve type %q", ErrKeyUnmarshalParameter, marshal.CRV)
		}
		if options.UnmarshalAsymmetricPrivate && marshal.D != "" {
			d, err := base64urlTrailingPadding(marshal.D)
			if err != nil {
				return nil, fmt.Errorf(`failed to decode %s key parameter "d": %w`, KtyEC, err)
			}
			privateKey := &ecdsa.PrivateKey{
				PublicKey: *publicKey,
				D:         new(big.Int).SetBytes(d),
			}
			key = privateKey
		} else {
			key = publicKey
		}
	case KtyOKP:
		if marshal.CRV != CrvEd25519 {
			return nil, fmt.Errorf("%w: %s key type should have %q curve", ErrKeyUnmarshalParameter, KtyOKP, CrvEd25519)
		}
		if marshal.X == "" {
			return nil, fmt.Errorf(`%w: %s requires parameter "x"`, ErrKeyUnmarshalParameter, KtyOKP)
		}
		public, err := base64urlTrailingPadding(marshal.X)
		if err != nil {
			return nil, fmt.Errorf(`failed to decode %s key parameter "x": %w`, KtyOKP, err)
		}
		if len(public) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: %s key should be %d bytes", ErrKeyUnmarshalParameter, KtyOKP, ed25519.PublicKeySize)
		}
		if options.UnmarshalAsymmetricPrivate && marshal.D != "" {
			private, err := base64urlTrailingPadding(marshal.D)
			if err != nil {
				return nil, fmt.Errorf(`failed to decode %s key parameter "d": %w`, KtyOKP, err)
			}
			private = append(private, public...)
			if len(private) != ed25519.PrivateKeySize {
				return nil, fmt.Errorf("%w: %s key should be %d bytes", ErrKeyUnmarshalParameter, KtyOKP, ed25519.PrivateKeySize)
			}
			key = ed25519.PrivateKey(private)
		} else {
			key = ed25519.PublicKey(public)
		}
	case KtyRSA:
		if marshal.N == "" || marshal.E == "" {
			return nil, fmt.Errorf(`%w: %s requires parameters "n" and "e"`, ErrKeyUnmarshalParameter, KtyRSA)
		}
		n, err := base64urlTrailingPadding(marshal.N)
		if err != nil {
			return nil, fmt.Errorf(`failed to decode %s key parameter "n": %w`, KtyRSA, err)
		}
		e, err := base64urlTrailingPadding(marshal.E)
		if err != nil {
			return nil, fmt.Errorf(`failed to decode %s key parameter "e": %w`, KtyRSA, err)
		}
		publicKey := rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Uint64()),
		}
		if options.UnmarshalAsymmetricPrivate && marshal.D != "" && marshal.P != "" && marshal.Q != "" && marshal.DP != "" && marshal.DQ != "" && marshal.QI != "" { // TODO Only "d" is required, but if one of the others is present, they all must be.
			d, err := base64urlTrailingPadding(marshal.D)
			if err != nil {
				return nil, fmt.Errorf(`failed to decode %s key parameter "d": %w`, KtyRSA, err)
			}
			p, err := base64urlTrailingPadding(marshal.P)
			if err != nil {
				return nil, fmt.Errorf(`failed to decode %s key parameter "p": %w`, KtyRSA, err)
			}
			q, err := base64urlTrailingPadding(marshal.Q)
			if err != nil {
				return nil, fmt.Errorf(`failed to decode %s key parameter "q": %w`, KtyRSA, err)
			}
			dp, err := base64urlTrailingPadding(marshal.DP)
			if err != nil {
				return nil, fmt.Errorf(`failed to decode %s key parameter "dp": %w`, KtyRSA, err)
			}
			dq, err := base64urlTrailingPadding(marshal.DQ)
			if err != nil {
				return nil, fmt.Errorf(`failed to decode %s key parameter "dq": %w`, KtyRSA, err)
			}
			qi, err := base64urlTrailingPadding(marshal.QI)
			if err != nil {
				return nil, fmt.Errorf(`failed to decode %s key parameter "qi": %w`, KtyRSA, err)
			}
			var oth []rsa.CRTValue
			primes := []*big.Int{
				new(big.Int).SetBytes(p),
				new(big.Int).SetBytes(q),
			}
			if len(marshal.OTH) > 0 {
				oth = make([]rsa.CRTValue, len(marshal.OTH))
				for i, otherPrimes := range marshal.OTH {
					if otherPrimes.R == "" || otherPrimes.D == "" || otherPrimes.T == "" {
						return nil, fmt.Errorf(`%w: %s requires parameters "r", "d", and "t" for each "oth"`, ErrKeyUnmarshalParameter, KtyRSA)
					}
					othD, err := base64urlTrailingPadding(otherPrimes.D)
					if err != nil {
						return nil, fmt.Errorf(`failed to decode %s key parameter "d": %w`, KtyRSA, err)
					}
					othT, err := base64urlTrailingPadding(otherPrimes.T)
					if err != nil {
						return nil, fmt.Errorf(`failed to decode %s key parameter "t": %w`, KtyRSA, err)
					}
					othR, err := base64urlTrailingPadding(otherPrimes.R)
					if err != nil {
						return nil, fmt.Errorf(`failed to decode %s key parameter "r": %w`, KtyRSA, err)
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
				return nil, fmt.Errorf(`failed to validate %s key: %w`, KtyRSA, err)
			}
			key = privateKey
		} else if !options.UnmarshalAsymmetricPrivate {
			key = &publicKey
		}
	case KtyOct:
		if options.UnmarshalSymmetric {
			if marshal.K == "" {
				return nil, fmt.Errorf(`%w: %s requires parameter "k"`, ErrKeyUnmarshalParameter, KtyOct)
			}
			k, err := base64urlTrailingPadding(marshal.K)
			if err != nil {
				return nil, fmt.Errorf(`failed to decode %s key parameter "k": %w`, KtyOct, err)
			}
			key = k
		} else {
			return nil, fmt.Errorf("%w: incorrect options to unmarshal symmetric key (%s)", ErrOptions, KtyOct)
		}
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKey, marshal.KTY)
	}
	x5c := make([]*x509.Certificate, len(marshal.X5C))
	for i, cert := range marshal.X5C {
		raw, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to Base64 decode X.509 certificate: %w", err)
		}
		x5c[i], err = x509.ParseCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
		}
	}
	jwkX509 := JWKX509Options{
		X5C: x5c,
		X5U: marshal.X5U,
	} // TODO Make a validate method so that the X.509 certificates match the key and thumbprints?
	opts := JWKOptions{
		Marshal: options,
		X509:    jwkX509,
	}
	j := &jwk{
		key:     key,
		marshal: marshal,
		options: opts,
	}
	return j, nil
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
