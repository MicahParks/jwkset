package jwkset

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

func LoadECPrivate(pemBlock []byte) (priv any, err error) {
	priv, err = x509.ParseECPrivateKey(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private Key: %w", err)
	}
	switch priv.(type) {
	case *ecdsa.PrivateKey:
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, priv)
	}
	return priv, nil
}

func LoadPKCS1Public(pemBlock []byte) (pub any, err error) {
	pub, err = x509.ParsePKCS1PublicKey(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS1 public Key: %w", err)
	}
	switch pub.(type) {
	case *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
	return pub, nil
}

func LoadPKCS1Private(pemBlock []byte) (priv any, err error) {
	priv, err = x509.ParsePKCS1PrivateKey(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS1 private Key: %w", err)
	}
	switch priv.(type) {
	case *rsa.PrivateKey:
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, priv)
	}
	return priv, nil
}

func LoadPKCS8Private(pemBlock []byte) (priv any, err error) {
	priv, err = x509.ParsePKCS8PrivateKey(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private Key: %w", err)
	}
	switch priv.(type) {
	case *ecdsa.PrivateKey, ed25519.PrivateKey, *rsa.PrivateKey:
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, priv)
	}
	return priv, nil
}

func LoadPKIXPublic(pemBlock []byte) (pub any, err error) {
	pub, err = x509.ParsePKIXPublicKey(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public Key: %w", err)
	}
	switch pub.(type) {
	case *ecdsa.PublicKey, ed25519.PublicKey, *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
	return pub, nil
}

func LoadCertificates(pemBlock []byte) ([]*x509.Certificate, error) {
	certs, err := x509.ParseCertificates(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificates: %w", err)
	}
	for _, cert := range certs {
		switch cert.PublicKey.(type) {
		case *ecdsa.PublicKey, ed25519.PublicKey, *rsa.PublicKey:
		default:
			return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, cert.PublicKey)
		}
	}
	return certs, nil
}
