package jwkset

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var (
	ErrX509Infer = errors.New("failed to infer X509 key type")
)

func LoadECPrivate(pemBlock *pem.Block) (priv *ecdsa.PrivateKey, err error) {
	priv, err = x509.ParseECPrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}
	return priv, nil
}

func LoadPKCS1Public(pemBlock *pem.Block) (pub *rsa.PublicKey, err error) {
	pub, err = x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS1 public key: %w", err)
	}
	return pub, nil
}

func LoadPKCS1Private(pemBlock *pem.Block) (priv *rsa.PrivateKey, err error) {
	priv, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
	}
	return priv, nil
}

func LoadPKCS8Private(pemBlock *pem.Block) (priv any, err error) {
	priv, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
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

func LoadPKIXPublic(pemBlock *pem.Block) (pub any, err error) {
	pub, err = x509.ParsePKIXPublicKey(pemBlock.Bytes)
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

func LoadCertificates(rawPEM []byte) ([]*x509.Certificate, error) {
	var b []byte
	for {
		var block *pem.Block
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
		switch cert.PublicKey.(type) {
		case *ecdsa.PublicKey, ed25519.PublicKey, *rsa.PublicKey:
		default:
			return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, cert.PublicKey)
		}
	}
	return certs, nil
}

func LoadX509KeyInfer(pemBlock *pem.Block) (key any, err error) { // TODO Won't work with PEM encoding.
	switch pemBlock.Type {
	case "EC PRIVATE KEY":
		key, err = LoadECPrivate(pemBlock)
	case "RSA PRIVATE KEY":
		key, err = LoadPKCS1Private(pemBlock)
	case "RSA PUBLIC KEY":
		key, err = LoadPKCS1Public(pemBlock)
	case "PRIVATE KEY":
		key, err = LoadPKCS8Private(pemBlock)
	case "PUBLIC KEY":
		key, err = LoadPKIXPublic(pemBlock)
	default:
		return nil, ErrX509Infer
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load key from inferred format %q: %w", key, err)
	}
	return key, nil
}
