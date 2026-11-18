package jwkset

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var (
	// ErrX509Infer is returned when the key type cannot be inferred from the PEM block type.
	ErrX509Infer = errors.New("failed to infer X509 key type")
)

// LoadCertificate loads an X509 certificate from a PEM block.
func LoadCertificate(pemBlock []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificates: %w", err)
	}
	_, err = x509PublicKey(cert)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// LoadCertificates loads X509 certificates from raw PEM data. It can be useful in loading X5U remote resources.
func LoadCertificates(rawPEM []byte) ([]*x509.Certificate, error) {
	b := make([]byte, 0)
	for {
		block, rest := pem.Decode(rawPEM)
		if block == nil {
			break
		}
		rawPEM = rest
		if block.Type == "CERTIFICATE" {
			b = append(b, block.Bytes...)
		}
	}
	certs, err := x509.ParseCertificates(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificates: %w", err)
	}
	for _, cert := range certs {
		_, err = x509PublicKey(cert)
		if err != nil {
			return nil, err
		}
	}
	return certs, nil
}

// x509PublicKey returns the public key of a supported X.509 certificate. Go leaves the certificate's PublicKey nil for
// X25519 keys, so it is parsed from the certificate's SubjectPublicKeyInfo.
func x509PublicKey(cert *x509.Certificate) (any, error) {
	pub := cert.PublicKey
	if pub == nil {
		var err error
		pub, err = x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnsupportedKey, err)
		}
	}
	switch pub.(type) {
	case *ecdh.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
	return pub, nil
}

// x509KeyMatch confirms that the given public or private key matches the public key in the X.509 certificate.
func x509KeyMatch(key any, cert *x509.Certificate) error {
	certPub, err := x509PublicKey(cert)
	if err != nil {
		return fmt.Errorf("%w: %w", errors.Join(ErrJWKValidation, ErrX509Mismatch), err)
	}
	if private, ok := key.(interface{ Public() crypto.PublicKey }); ok {
		key = private.Public()
	}
	// Certificates hold P-256, P-384, and P-521 keys as ECDSA keys, even when they are used for ECDH.
	if _, ok := key.(*ecdh.PublicKey); ok {
		if ecdsaPub, ok := certPub.(*ecdsa.PublicKey); ok {
			certPub, err = ecdsaPub.ECDH()
			if err != nil {
				return fmt.Errorf("%w: %w", errors.Join(ErrJWKValidation, ErrX509Mismatch), err)
			}
		}
	}
	pub, ok := key.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("%w: Golang key is type %T, which is not supported, so it cannot be compared to given X.509 certificates", errors.Join(ErrJWKValidation, ErrUnsupportedKey, ErrX509Mismatch), key)
	}
	if !pub.Equal(certPub) {
		return fmt.Errorf("%w: Golang key of type %T does not match the X.509 public key of type %T", errors.Join(ErrJWKValidation, ErrX509Mismatch), key, certPub)
	}
	return nil
}

// LoadX509KeyInfer loads an X509 key from a PEM block.
func LoadX509KeyInfer(pemBlock *pem.Block) (key any, err error) {
	switch pemBlock.Type {
	case "EC PRIVATE KEY":
		key, err = loadECPrivate(pemBlock)
	case "RSA PRIVATE KEY":
		key, err = loadPKCS1Private(pemBlock)
	case "RSA PUBLIC KEY":
		key, err = loadPKCS1Public(pemBlock)
	case "PRIVATE KEY":
		key, err = loadPKCS8Private(pemBlock)
	case "PUBLIC KEY":
		key, err = loadPKIXPublic(pemBlock)
	default:
		return nil, ErrX509Infer
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load key from inferred format %q: %w", key, err)
	}
	return key, nil
}
func loadECPrivate(pemBlock *pem.Block) (priv *ecdsa.PrivateKey, err error) {
	priv, err = x509.ParseECPrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}
	return priv, nil
}
func loadPKCS1Public(pemBlock *pem.Block) (pub *rsa.PublicKey, err error) {
	pub, err = x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS1 public key: %w", err)
	}
	return pub, nil
}
func loadPKCS1Private(pemBlock *pem.Block) (priv *rsa.PrivateKey, err error) {
	priv, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
	}
	return priv, nil
}
func loadPKCS8Private(pemBlock *pem.Block) (priv any, err error) {
	priv, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}
	switch priv.(type) {
	case *ecdh.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, *rsa.PrivateKey:
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, priv)
	}
	return priv, nil
}
func loadPKIXPublic(pemBlock *pem.Block) (pub any, err error) {
	pub, err = x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}
	switch pub.(type) {
	case *ecdh.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
	return pub, nil
}
