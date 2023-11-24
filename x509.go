package jwkset

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

var (
	ErrX509Infer = errors.New("failed to infer X509 key type")
)

func LoadECPrivate(pemBlock []byte) (priv *ecdsa.PrivateKey, err error) {
	priv, err = x509.ParseECPrivateKey(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}
	return priv, nil
}

func LoadPKCS1Public(pemBlock []byte) (pub *rsa.PublicKey, err error) {
	pub, err = x509.ParsePKCS1PublicKey(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS1 public key: %w", err)
	}
	return pub, nil
}

func LoadPKCS1Private(pemBlock []byte) (priv *rsa.PrivateKey, err error) {
	priv, err = x509.ParsePKCS1PrivateKey(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
	}
	return priv, nil
}

func LoadPKCS8Private(pemBlock []byte) (priv any, err error) {
	priv, err = x509.ParsePKCS8PrivateKey(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
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
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
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

func LoadX509KeyInfer(pemBlock []byte) (key any, err error) {
	switch {
	case bytes.Contains(pemBlock, []byte("EC PRIVATE KEY")):
		key, err = LoadECPrivate(pemBlock)
	case bytes.Contains(pemBlock, []byte("RSA PRIVATE KEY")):
		key, err = LoadPKCS1Private(pemBlock)
	case bytes.Contains(pemBlock, []byte("RSA PUBLIC KEY")):
		key, err = LoadPKCS1Public(pemBlock)
	case bytes.Contains(pemBlock, []byte("PRIVATE KEY")):
		key, err = LoadPKCS8Private(pemBlock)
	case bytes.Contains(pemBlock, []byte("PUBLIC KEY")):
		key, err = LoadPKIXPublic(pemBlock)
	default:
		return nil, ErrX509Infer
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load key from inferred format %q: %w", key, err)
	}
	return key, nil
}
