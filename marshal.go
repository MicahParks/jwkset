package jwkset

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"
)

// TODO Implement https://datatracker.ietf.org/doc/html/rfc7517#section-7 JWK Set encryption?

var (
	// ErrGetX5U indicates there was an error getting the X5U remote resource.
	ErrGetX5U = errors.New("X5U URI timed out")
	// ErrJWKValidation indicates that a JWK failed to validate.
	ErrJWKValidation = errors.New("failed to validate JWK")
	// ErrKeyUnmarshalParameter indicates that a JWK's attributes are invalid and cannot be unmarshaled.
	ErrKeyUnmarshalParameter = errors.New("unable to unmarshal JWK due to invalid attributes")
	// ErrOptions indicates that the given options caused an error.
	ErrOptions = errors.New("the given options caused an error")
	// ErrUnsupportedKey indicates a key is not supported.
	ErrUnsupportedKey = errors.New("unsupported key")
	// ErrX509Mismatch indicates that the X.509 certificate does not match the key.
	ErrX509Mismatch = errors.New("the X.509 certificate does not match Golang key type")
)

// JWK TODO
type JWK struct {
	key     any
	marshal JWKMarshal
	options JWKOptions
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

// JWKValidateOptions are used to specify options for validating a JWK.
type JWKValidateOptions struct {
	/*
		This package intentionally does not confirm if certificate's usage or compare that to the JWK's use parameter.
		Please open a GitHub issue if you think this should be an option.
	*/
	// CheckX509ValidTime is used to indicate that the X.509 certificate's valid time should be checked.
	CheckX509ValidTime bool
	// GetX5U is used to get and validate the X.509 certificate from the X5U URI. Use DefaultGetX5U for the default
	// behavior.
	GetX5U func(x5u *url.URL) ([]*x509.Certificate, error)
	// SkipAll is used to skip all validation.
	SkipAll bool
	// SkipKeyOps is used to skip validation of the key operations (key_ops).
	SkipKeyOps bool
	// SkipMetadata skips checking if the JWKMetadataOptions match the JWKMarshal.
	SkipMetadata bool
	// SkipUse is used to skip validation of the key use (use).
	SkipUse bool
	// SkipX5UScheme is used to skip checking if the X5U URI scheme is https.
	SkipX5UScheme bool
}

// JWKMetadataOptions are direct passthroughs into the JWKMarshal.
type JWKMetadataOptions struct {
	// KID is the key ID (kid).
	KID string
	// KEYOPS is the key operations (key_ops).
	KEYOPS []KEYOPS
	// USE is the key use (use).
	USE USE
}

// JWKOptions are used to specify options for marshaling a JSON Web Key.
type JWKOptions struct {
	Marshal  JWKMarshalOptions
	Metadata JWKMetadataOptions
	Validate JWKValidateOptions
	X509     JWKX509Options
}

// NewJWKFromKey uses the given key and options to create a JWK. It is possible to provide a private key with an X.509
// certificate, which will be validated to contain the correct public key.
func NewJWKFromKey(key any, options JWKOptions) (JWK, error) {
	marshal, err := keyMarshal(key, options)
	if err != nil {
		return JWK{}, fmt.Errorf("failed to marshal JSON Web Key: %w", err)
	}
	j := JWK{
		key:     key,
		marshal: marshal,
		options: options,
	}
	err = j.Validate()
	if err != nil {
		return JWK{}, fmt.Errorf("failed to validate JSON Web Key: %w", err)
	}
	return j, nil
}

// NewJWKFromMarshal transforms a JWKMarshal into a JWK.
func NewJWKFromMarshal(marshal JWKMarshal, marshalOptions JWKMarshalOptions, validateOptions JWKValidateOptions) (JWK, error) {
	j, err := keyUnmarshal(marshal, marshalOptions, validateOptions)
	if err != nil {
		return JWK{}, fmt.Errorf("failed to unmarshal JSON Web Key: %w", err)
	}
	err = j.Validate()
	if err != nil {
		return JWK{}, fmt.Errorf("failed to validate JSON Web Key: %w", err)
	}
	return j, nil
}

// NewJWKFromX509 uses the X.509 information in the options to create a JWK.
func NewJWKFromX509(options JWKOptions) (JWK, error) {
	if len(options.X509.X5C) == 0 {
		return JWK{}, fmt.Errorf("%w: no X.509 certificates provided", ErrOptions)
	}
	marshal, err := keyMarshal(options.X509.X5C[0].PublicKey, options)
	if err != nil {
		return JWK{}, fmt.Errorf("failed to marshal JSON Web Key: %w", err)
	}
	j := JWK{
		key:     options.X509.X5C[0].PublicKey,
		marshal: marshal,
		options: options,
	}
	err = j.Validate()
	if err != nil {
		return JWK{}, fmt.Errorf("failed to validate JSON Web Key: %w", err)
	}
	return j, nil
}

func (j JWK) Key() any {
	return j.key
}
func (j JWK) Marshal() JWKMarshal {
	return j.marshal
}
func (j JWK) X509() JWKX509Options {
	return j.options.X509
}
func (j JWK) Validate() error {
	if j.options.Validate.SkipAll {
		return nil
	}
	if j.marshal == (JWKMarshal{}) {
		return fmt.Errorf("%w: marhsal is nil", ErrJWKValidation)
	}

	if !j.options.Validate.SkipKeyOps {
		for _, o := range j.marshal.KEYOPS {
			if !o.valid() {
				return fmt.Errorf("%w: invalid or unsupported key_opt %q", ErrJWKValidation, o)
			}
		}
	}

	if !j.options.Validate.SkipUse && !j.marshal.USE.valid() {
		return fmt.Errorf("%w: invalid or unsupported key use %q", ErrJWKValidation, j.marshal.USE)
	}

	if !j.options.Validate.SkipMetadata {
		if j.marshal.KID != j.options.Metadata.KID {
			return fmt.Errorf("%w: KID in marshal does not match KID in options", errors.Join(ErrJWKValidation, ErrOptions))
		}
		if !slices.Equal(j.marshal.KEYOPS, j.options.Metadata.KEYOPS) {
			return fmt.Errorf("%w: KEYOPS in marshal does not match KEYOPS in options", errors.Join(ErrJWKValidation, ErrOptions))
		}
		if j.marshal.USE != j.options.Metadata.USE {
			return fmt.Errorf("%w: USE in marshal does not match USE in options", errors.Join(ErrJWKValidation, ErrOptions))
		}
	}

	if len(j.options.X509.X5C) > 0 {
		cert := j.options.X509.X5C[0]
		i := cert.PublicKey
		switch k := j.key.(type) {
		case *ecdsa.PrivateKey:
			pub, ok := i.(*ecdsa.PublicKey)
			if !ok {
				return fmt.Errorf("%w: Golang key is type *ecdsa.Private but X.509 public key was of type %T", errors.Join(ErrJWKValidation, ErrX509Mismatch), i)
			}
			if !k.PublicKey.Equal(pub) {
				return fmt.Errorf("%w: Golang *ecdsa.PrivateKey's public key does not match the X.509 public key", errors.Join(ErrJWKValidation, ErrX509Mismatch))
			}
		case *ecdsa.PublicKey:
			pub, ok := i.(*ecdsa.PublicKey)
			if !ok {
				return fmt.Errorf("%w: Golang key is type *ecdsa.Public but X.509 public key was of type %T", errors.Join(ErrJWKValidation, ErrX509Mismatch), i)
			}
			if !k.Equal(pub) {
				return fmt.Errorf("%w: Golang *ecdsa.PublicKey does not match the X.509 public key", errors.Join(ErrJWKValidation, ErrX509Mismatch))
			}
		case ed25519.PrivateKey:
			pub, ok := i.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("%w: Golang key is type ed25519.PrivateKey but X.509 public key was of type %T", errors.Join(ErrJWKValidation, ErrX509Mismatch), i)
			}
			if !bytes.Equal(k.Public().(ed25519.PublicKey), pub) {
				return fmt.Errorf("%w: Golang ed25519.PrivateKey's public key does not match the X.509 public key", errors.Join(ErrJWKValidation, ErrX509Mismatch))
			}
		case ed25519.PublicKey:
			pub, ok := i.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("%w: Golang key is type ed25519.PublicKey but X.509 public key was of type %T", errors.Join(ErrJWKValidation, ErrX509Mismatch), i)
			}
			if !bytes.Equal(k, pub) {
				return fmt.Errorf("%w: Golang ed25519.PublicKey does not match the X.509 public key", errors.Join(ErrJWKValidation, ErrX509Mismatch))
			}
		case *rsa.PrivateKey:
			pub, ok := i.(*rsa.PublicKey)
			if !ok {
				return fmt.Errorf("%w: Golang key is type *rsa.PrivateKey but X.509 public key was of type %T", errors.Join(ErrJWKValidation, ErrX509Mismatch), i)
			}
			if !k.PublicKey.Equal(pub) {
				return fmt.Errorf("%w: Golang *rsa.PrivateKey's public key does not match the X.509 public key", errors.Join(ErrJWKValidation, ErrX509Mismatch))
			}
		case *rsa.PublicKey:
			pub, ok := i.(*rsa.PublicKey)
			if !ok {
				return fmt.Errorf("%w: Golang key is type *rsa.PublicKey but X.509 public key was of type %T", errors.Join(ErrJWKValidation, ErrX509Mismatch), i)
			}
			if !k.Equal(pub) {
				return fmt.Errorf("%w: Golang *rsa.PublicKey does not match the X.509 public key", errors.Join(ErrJWKValidation, ErrX509Mismatch))
			}
		case []byte:
			return fmt.Errorf("%w: Golang key is type []byte, which is only used for symmectric key cryptography, but X.509 certificates were given, which are only used for public key cryptrography", errors.Join(ErrJWKValidation, ErrX509Mismatch))
		default:
			return fmt.Errorf("%w: Golang key is type %T, which is not supported, so it cannot be compared to given X.509 certificates", errors.Join(ErrJWKValidation, ErrUnsupportedKey, ErrX509Mismatch), j.key)
		}
		const badAlgoErrMsg = " %w: X.509 certificate signature algorithm does not match JWK algorithm %q"
		switch cert.SignatureAlgorithm {
		case x509.ECDSAWithSHA256:
			if j.marshal.ALG != AlgES256 {
				return fmt.Errorf(badAlgoErrMsg, errors.Join(ErrJWKValidation, ErrX509Mismatch), j.marshal.ALG)
			}
		case x509.ECDSAWithSHA384:
			if j.marshal.ALG != AlgES384 {
				return fmt.Errorf(badAlgoErrMsg, errors.Join(ErrJWKValidation, ErrX509Mismatch), j.marshal.ALG)
			}
		case x509.ECDSAWithSHA512:
			if j.marshal.ALG != AlgES512 {
				return fmt.Errorf(badAlgoErrMsg, errors.Join(ErrJWKValidation, ErrX509Mismatch), j.marshal.ALG)
			}
		case x509.PureEd25519:
			if j.marshal.ALG != AlgEdDSA {
				return fmt.Errorf(badAlgoErrMsg, errors.Join(ErrJWKValidation, ErrX509Mismatch), j.marshal.ALG)
			}
		case x509.SHA256WithRSA:
			if j.marshal.ALG != AlgRS256 {
				return fmt.Errorf(badAlgoErrMsg, errors.Join(ErrJWKValidation, ErrX509Mismatch), j.marshal.ALG)
			}
		case x509.SHA384WithRSA:
			if j.marshal.ALG != AlgRS384 {
				return fmt.Errorf(badAlgoErrMsg, errors.Join(ErrJWKValidation, ErrX509Mismatch), j.marshal.ALG)
			}
		case x509.SHA512WithRSA:
			if j.marshal.ALG != AlgRS512 {
				return fmt.Errorf(badAlgoErrMsg, errors.Join(ErrJWKValidation, ErrX509Mismatch), j.marshal.ALG)
			}
		case x509.SHA256WithRSAPSS:
			if j.marshal.ALG != AlgPS256 {
				return fmt.Errorf(badAlgoErrMsg, errors.Join(ErrJWKValidation, ErrX509Mismatch), j.marshal.ALG)
			}
		case x509.SHA384WithRSAPSS:
			if j.marshal.ALG != AlgPS384 {
				return fmt.Errorf(badAlgoErrMsg, errors.Join(ErrJWKValidation, ErrX509Mismatch), j.marshal.ALG)
			}
		case x509.SHA512WithRSAPSS:
			if j.marshal.ALG != AlgPS512 {
				return fmt.Errorf(badAlgoErrMsg, errors.Join(ErrJWKValidation, ErrX509Mismatch), j.marshal.ALG)
			}
		default:
			return fmt.Errorf("%w: X.509 certificate signature algorithm %q is not supported", errors.Join(ErrJWKValidation, ErrX509Mismatch), cert.SignatureAlgorithm)
		}
		if j.options.Validate.CheckX509ValidTime {
			now := time.Now()
			if now.Before(cert.NotBefore) {
				return fmt.Errorf("%w: X.509 certificate is not yet valid", ErrJWKValidation)
			}
			if now.After(cert.NotAfter) {
				return fmt.Errorf("%w: X.509 certificate is expired", ErrJWKValidation)
			}
		}
	}

	marshal, err := keyMarshal(j.key, j.options)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON Web Key: %w", errors.Join(ErrJWKValidation, err))
	}
	ok := reflect.DeepEqual(j.marshal, marshal)
	if !ok {
		return fmt.Errorf("%w: marshaled JWK does not match original JWK", ErrJWKValidation)
	}

	if j.marshal.X5U != "" || j.options.X509.X5U != "" {
		if j.marshal.X5U != j.options.X509.X5U {
			return fmt.Errorf("%w: X5U in marshal does not match X5U in options", errors.Join(ErrJWKValidation, ErrOptions))
		}
		u, err := url.ParseRequestURI(j.marshal.X5U)
		if err != nil {
			return fmt.Errorf("failed to parse X5U URI: %w", errors.Join(ErrJWKValidation, ErrOptions, err))
		}
		if !j.options.Validate.SkipX5UScheme && u.Scheme != "https" {
			return fmt.Errorf("%w: X5U URI scheme must be https", errors.Join(ErrJWKValidation, ErrOptions))
		}
		if j.options.Validate.GetX5U != nil {
			certs, err := j.options.Validate.GetX5U(u)
			if err != nil {
				return fmt.Errorf("failed to get X5U URI: %w", errors.Join(ErrJWKValidation, ErrOptions, err))
			}
			if len(certs) == 0 {
				return fmt.Errorf("%w: X5U URI did not return any certificates", errors.Join(ErrJWKValidation, ErrOptions))
			}
			larger := certs
			smaller := j.options.X509.X5C
			if len(j.options.X509.X5C) > len(certs) {
				larger = j.options.X509.X5C
				smaller = certs
			}
			for i, c := range smaller {
				if !c.Equal(larger[i]) {
					return fmt.Errorf("%w: the X5C and X5U (remote resource) parameters are not a full or partial match", errors.Join(ErrJWKValidation, ErrOptions))
				}
			}
		}
	}

	return nil
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
type JWKMarshal struct {
	ALG     ALG           `json:"alg,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.4 and https://www.rfc-editor.org/rfc/rfc7518#section-4.1
	CRV     CRV           `json:"crv,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	D       string        `json:"d,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.1 and https://www.rfc-editor.org/rfc/rfc7518#section-6.2.2.1 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	DP      string        `json:"dp,omitempty"`       // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.4
	DQ      string        `json:"dq,omitempty"`       // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.5
	E       string        `json:"e,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.2
	K       string        `json:"k,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.4.1
	KEYOPS  []KEYOPS      `json:"key_ops,omitempty"`  // https://www.rfc-editor.org/rfc/rfc7517#section-4.3
	KID     string        `json:"kid,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.5
	KTY     KTY           `json:"kty,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.1
	N       string        `json:"n,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.1
	OTH     []OtherPrimes `json:"oth,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
	P       string        `json:"p,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.2
	Q       string        `json:"q,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.3
	QI      string        `json:"qi,omitempty"`       // https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.6
	USE     USE           `json:"use,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.2
	X       string        `json:"x,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.2 and https://www.rfc-editor.org/rfc/rfc8037.html#section-2
	X5C     []string      `json:"x5c,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.7
	X5T     string        `json:"x5t,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.8
	X5TS256 string        `json:"x5t#S256,omitempty"` // https://www.rfc-editor.org/rfc/rfc7517#section-4.9
	X5U     string        `json:"x5u,omitempty"`      // https://www.rfc-editor.org/rfc/rfc7517#section-4.6
	Y       string        `json:"y,omitempty"`        // https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.3
}

// JWKSMarshal is used to marshal or unmarshal a JSON Web Key Set.
type JWKSMarshal struct {
	Keys []JWKMarshal `json:"keys"`
}

func keyMarshal(key any, options JWKOptions) (JWKMarshal, error) {
	m := JWKMarshal{}
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
			return JWKMarshal{}, fmt.Errorf("%w: incorrect options to marshal symmetric key (oct)", ErrOptions)
		}
	default:
		return JWKMarshal{}, fmt.Errorf("%w: %T", ErrUnsupportedKey, key)
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
	m.KID = options.Metadata.KID
	m.KEYOPS = options.Metadata.KEYOPS
	m.USE = options.Metadata.USE
	m.X5U = options.X509.X5U
	return m, nil
}

func keyUnmarshal(marshal JWKMarshal, options JWKMarshalOptions, validateOptions JWKValidateOptions) (JWK, error) {
	var key any
	switch marshal.KTY {
	case KtyEC:
		if marshal.CRV == "" || marshal.X == "" || marshal.Y == "" {
			return JWK{}, fmt.Errorf(`%w: %s requires parameters "crv", "x", and "y"`, ErrKeyUnmarshalParameter, KtyEC)
		}
		x, err := base64urlTrailingPadding(marshal.X)
		if err != nil {
			return JWK{}, fmt.Errorf(`failed to decode %s key parameter "x": %w`, KtyEC, err)
		}
		y, err := base64urlTrailingPadding(marshal.Y)
		if err != nil {
			return JWK{}, fmt.Errorf(`failed to decode %s key parameter "y": %w`, KtyEC, err)
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
			return JWK{}, fmt.Errorf("%w: unsupported curve type %q", ErrKeyUnmarshalParameter, marshal.CRV)
		}
		if options.UnmarshalAsymmetricPrivate && marshal.D != "" {
			d, err := base64urlTrailingPadding(marshal.D)
			if err != nil {
				return JWK{}, fmt.Errorf(`failed to decode %s key parameter "d": %w`, KtyEC, err)
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
			return JWK{}, fmt.Errorf("%w: %s key type should have %q curve", ErrKeyUnmarshalParameter, KtyOKP, CrvEd25519)
		}
		if marshal.X == "" {
			return JWK{}, fmt.Errorf(`%w: %s requires parameter "x"`, ErrKeyUnmarshalParameter, KtyOKP)
		}
		public, err := base64urlTrailingPadding(marshal.X)
		if err != nil {
			return JWK{}, fmt.Errorf(`failed to decode %s key parameter "x": %w`, KtyOKP, err)
		}
		if len(public) != ed25519.PublicKeySize {
			return JWK{}, fmt.Errorf("%w: %s key should be %d bytes", ErrKeyUnmarshalParameter, KtyOKP, ed25519.PublicKeySize)
		}
		if options.UnmarshalAsymmetricPrivate && marshal.D != "" {
			private, err := base64urlTrailingPadding(marshal.D)
			if err != nil {
				return JWK{}, fmt.Errorf(`failed to decode %s key parameter "d": %w`, KtyOKP, err)
			}
			private = append(private, public...)
			if len(private) != ed25519.PrivateKeySize {
				return JWK{}, fmt.Errorf("%w: %s key should be %d bytes", ErrKeyUnmarshalParameter, KtyOKP, ed25519.PrivateKeySize)
			}
			key = ed25519.PrivateKey(private)
		} else {
			key = ed25519.PublicKey(public)
		}
	case KtyRSA:
		if marshal.N == "" || marshal.E == "" {
			return JWK{}, fmt.Errorf(`%w: %s requires parameters "n" and "e"`, ErrKeyUnmarshalParameter, KtyRSA)
		}
		n, err := base64urlTrailingPadding(marshal.N)
		if err != nil {
			return JWK{}, fmt.Errorf(`failed to decode %s key parameter "n": %w`, KtyRSA, err)
		}
		e, err := base64urlTrailingPadding(marshal.E)
		if err != nil {
			return JWK{}, fmt.Errorf(`failed to decode %s key parameter "e": %w`, KtyRSA, err)
		}
		publicKey := rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Uint64()),
		}
		if options.UnmarshalAsymmetricPrivate && marshal.D != "" && marshal.P != "" && marshal.Q != "" && marshal.DP != "" && marshal.DQ != "" && marshal.QI != "" { // TODO Only "d" is required, but if one of the others is present, they all must be.
			d, err := base64urlTrailingPadding(marshal.D)
			if err != nil {
				return JWK{}, fmt.Errorf(`failed to decode %s key parameter "d": %w`, KtyRSA, err)
			}
			p, err := base64urlTrailingPadding(marshal.P)
			if err != nil {
				return JWK{}, fmt.Errorf(`failed to decode %s key parameter "p": %w`, KtyRSA, err)
			}
			q, err := base64urlTrailingPadding(marshal.Q)
			if err != nil {
				return JWK{}, fmt.Errorf(`failed to decode %s key parameter "q": %w`, KtyRSA, err)
			}
			dp, err := base64urlTrailingPadding(marshal.DP)
			if err != nil {
				return JWK{}, fmt.Errorf(`failed to decode %s key parameter "dp": %w`, KtyRSA, err)
			}
			dq, err := base64urlTrailingPadding(marshal.DQ)
			if err != nil {
				return JWK{}, fmt.Errorf(`failed to decode %s key parameter "dq": %w`, KtyRSA, err)
			}
			qi, err := base64urlTrailingPadding(marshal.QI)
			if err != nil {
				return JWK{}, fmt.Errorf(`failed to decode %s key parameter "qi": %w`, KtyRSA, err)
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
						return JWK{}, fmt.Errorf(`%w: %s requires parameters "r", "d", and "t" for each "oth"`, ErrKeyUnmarshalParameter, KtyRSA)
					}
					othD, err := base64urlTrailingPadding(otherPrimes.D)
					if err != nil {
						return JWK{}, fmt.Errorf(`failed to decode %s key parameter "d": %w`, KtyRSA, err)
					}
					othT, err := base64urlTrailingPadding(otherPrimes.T)
					if err != nil {
						return JWK{}, fmt.Errorf(`failed to decode %s key parameter "t": %w`, KtyRSA, err)
					}
					othR, err := base64urlTrailingPadding(otherPrimes.R)
					if err != nil {
						return JWK{}, fmt.Errorf(`failed to decode %s key parameter "r": %w`, KtyRSA, err)
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
				return JWK{}, fmt.Errorf(`failed to validate %s key: %w`, KtyRSA, err)
			}
			key = privateKey
		} else if !options.UnmarshalAsymmetricPrivate {
			key = &publicKey
		}
	case KtyOct:
		if options.UnmarshalSymmetric {
			if marshal.K == "" {
				return JWK{}, fmt.Errorf(`%w: %s requires parameter "k"`, ErrKeyUnmarshalParameter, KtyOct)
			}
			k, err := base64urlTrailingPadding(marshal.K)
			if err != nil {
				return JWK{}, fmt.Errorf(`failed to decode %s key parameter "k": %w`, KtyOct, err)
			}
			key = k
		} else {
			return JWK{}, fmt.Errorf("%w: incorrect options to unmarshal symmetric key (%s)", ErrOptions, KtyOct)
		}
	default:
		return JWK{}, fmt.Errorf("%w: %s", ErrUnsupportedKey, marshal.KTY)
	}
	x5c := make([]*x509.Certificate, len(marshal.X5C))
	for i, cert := range marshal.X5C {
		raw, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return JWK{}, fmt.Errorf("failed to Base64 decode X.509 certificate: %w", err)
		}
		x5c[i], err = x509.ParseCertificate(raw)
		if err != nil {
			return JWK{}, fmt.Errorf("failed to parse X.509 certificate: %w", err)
		}
	}
	jwkX509 := JWKX509Options{
		X5C: x5c,
		X5U: marshal.X5U,
	}
	metadata := JWKMetadataOptions{
		KID:    marshal.KID,
		KEYOPS: slices.Clone(marshal.KEYOPS),
		USE:    marshal.USE,
	}
	opts := JWKOptions{
		Metadata: metadata,
		Marshal:  options,
		Validate: validateOptions,
		X509:     jwkX509,
	}
	j := JWK{
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
