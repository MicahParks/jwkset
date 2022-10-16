package jwkset_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/MicahParks/jwkset"
)

const (
	hmacSecret    = "myHMACSecret"
	invalidB64URL = "&"
	myKeyID       = "myKeyID"
)

func TestMarshalECDSA(t *testing.T) {
	const (
		dString = "GpanYiHB-TeCKFmfAwqzIJVhziUH6QX77obHwDPERGo"
		xString = "IZrURsAt0DcSytZRCBQ4SjCcbIhLLQvg53uSkRdETZ4"
		yString = "Uy2iBhx7jMXB4n8fPASCOaNjnUPd8C1toVwytGeAEdU"
	)

	checkMarshal := func(marshal jwkset.JWKMarshal, options jwkset.KeyMarshalOptions) {
		// TODO Check ALG.
		if marshal.CRV != jwkset.CurveP256.String() {
			t.Fatalf(`Should get curve "%s". %s`, jwkset.CurveP256.String(), marshal.CRV)
		}
		if options.AsymmetricPrivate {
			if marshal.D != dString {
				t.Fatalf("Private key does not match original key.")
			}
		} else {
			if marshal.D != "" {
				t.Fatalf("Asymmetric private key should be unsupported for given options.")
			}
		}
		if marshal.KTY != jwkset.KeyTypeEC.String() {
			t.Fatalf("Key type does not match original key.")
		}
		if marshal.X != xString {
			t.Fatalf("Public key does not match original key.")
		}
		if marshal.Y != yString {
			t.Fatalf("Public key does not match original key.")
		}
	}

	d, err := base64.RawURLEncoding.DecodeString(dString)
	if err != nil {
		t.Fatalf("Failed to decode private key. %s", err)
	}
	x, err := base64.RawURLEncoding.DecodeString(xString)
	if err != nil {
		t.Fatalf("Failed to decode x coordinate. %s", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(yString)
	if err != nil {
		t.Fatalf("Failed to decode y coordinate. %s", err)
	}
	metaP256 := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		D: new(big.Int).SetBytes(d),
	}

	meta := jwkset.KeyWithMeta{
		Key: metaP256,
	}

	options := jwkset.KeyMarshalOptions{}
	marshal, err := jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
	checkMarshal(marshal, options)

	options.AsymmetricPrivate = true
	marshal, err = jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
	checkMarshal(marshal, options)

	publicMeta := jwkset.KeyWithMeta{
		Key: metaP256.Public(),
	}
	options.AsymmetricPrivate = false
	marshal, err = jwkset.KeyMarshal(publicMeta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}

	checkMarshal(marshal, options)
}

func TestMarshalEdDSA(t *testing.T) {
	const (
		privateString = "5hT6NTzNJyUCaG7mqtq2ru0EsA2z5SwnnkP0pBycP64"
		publicString  = "VYk14QSFla7FKnL_okf6TqLIyV2X6DPaDi26UpAMVnM"
	)
	checkMarshal := func(marshal jwkset.JWKMarshal, options jwkset.KeyMarshalOptions) {
		// TODO Check ALG.
		if marshal.CRV != jwkset.CurveEd25519.String() {
			t.Fatalf(`Should get curve "%s". %s`, jwkset.CurveEd25519.String(), marshal.CRV)
		}
		if options.AsymmetricPrivate {
			if marshal.D != privateString {
				t.Fatalf("Private key does not match original key.")
			}
		} else {
			if marshal.D != "" {
				t.Fatalf("Asymmetric private key should be unsupported for given options.")
			}
		}
		if marshal.KTY != jwkset.KeyTypeOKP.String() {
			t.Fatalf("Key type does not match original key.")
		}
		if marshal.X != publicString {
			t.Fatalf("Public key does not match original key.")
		}
	}

	privateBytes, err := base64.RawURLEncoding.DecodeString(privateString)
	if err != nil {
		t.Fatalf("Failed to decode private key. %s", err)
	}
	publicBytes, err := base64.RawURLEncoding.DecodeString(publicString)
	if err != nil {
		t.Fatalf("Failed to decode public key. %s", err)
	}
	private := ed25519.PrivateKey(append(privateBytes, publicBytes...))

	meta := jwkset.KeyWithMeta{
		Key: private,
	}

	options := jwkset.KeyMarshalOptions{}
	marshal, err := jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
	checkMarshal(marshal, options)

	options.AsymmetricPrivate = true
	marshal, err = jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
	checkMarshal(marshal, options)

	publicMeta := jwkset.KeyWithMeta{
		Key: private.Public(),
	}
	options.AsymmetricPrivate = false
	marshal, err = jwkset.KeyMarshal(publicMeta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
	checkMarshal(marshal, options)
}

func TestUnmarshalEdDSA(t *testing.T) {
	const privateString = "5hT6NTzNJyUCaG7mqtq2ru0EsA2z5SwnnkP0pBycP64"
	const publicString = "VYk14QSFla7FKnL_okf6TqLIyV2X6DPaDi26UpAMVnM"
	privateBytes, err := base64.RawURLEncoding.DecodeString(privateString)
	if err != nil {
		t.Fatalf("Failed to decode private key. %s", err)
	}
	publicBytes, err := base64.RawURLEncoding.DecodeString(publicString)
	if err != nil {
		t.Fatalf("Failed to decode public key. %s", err)
	}
	private := ed25519.PrivateKey(append(privateBytes, publicBytes...))

	jwk := jwkset.JWKMarshal{
		CRV: jwkset.CurveEd25519.String(),
		D:   privateString,
		KID: myKeyID,
		KTY: jwkset.KeyTypeOKP.String(),
		X:   publicString,
	}

	options := jwkset.KeyUnmarshalOptions{}
	meta, err := jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}

	switch meta.Key.(type) {
	case ed25519.PrivateKey:
		t.Fatal("Private key should not be key type.")
	case ed25519.PublicKey:
		// Do nothing.
	default:
		t.Fatalf("Key type does not match original key.")
	}

	options.AsymmetricPrivate = true
	meta, err = jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	if !bytes.Equal(private, meta.Key.(ed25519.PrivateKey)) {
		t.Fatalf("Unmarshaled key does not match original key.")
	}
	if meta.KeyID != myKeyID {
		t.Fatalf("Unmarshaled key ID does not match original key ID.")
	}

	jwk.D = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "D" is invalid raw Base64URL. %s`, err)
	}

	jwk.X = ""
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "X" is empty. %s`, err)
	}

	jwk.X = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "X" is invalid raw Base64URL. %s`, err)
	}

	jwk.CRV = ""
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "CRV" is empty. %s`, err)
	}
	jwk.CRV = jwkset.CurveEd25519.String()

	invalidSize := base64.RawURLEncoding.EncodeToString([]byte("invalidSize"))
	jwk.X = invalidSize
	jwk.D = privateString
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "X" is invalid size. %s`, err)
	}
	jwk.X = publicString

	jwk.D = invalidSize
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "D" is invalid size. %s`, err)
	}
}

func TestMarshalOct(t *testing.T) {
	meta := jwkset.KeyWithMeta{
		Key: []byte(hmacSecret),
	}

	options := jwkset.KeyMarshalOptions{}
	_, err := jwkset.KeyMarshal(meta, options)
	if !errors.Is(err, jwkset.ErrUnsupportedKeyType) {
		t.Fatalf("Symmetric key should be unsupported for given options. %s", err)
	}

	options.Symmetric = true
	marshal, err := jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}

	if marshal.K != base64.RawURLEncoding.EncodeToString(meta.Key.([]byte)) {
		t.Fatalf("Unmarshaled key does not match original key.")
	}
	if marshal.KTY != jwkset.KeyTypeOct.String() {
		t.Fatalf("Key type does not match original key.")
	}
}

func TestUnmarshalOct(t *testing.T) {
	jwk := jwkset.JWKMarshal{
		K:   base64.RawURLEncoding.EncodeToString([]byte(hmacSecret)),
		KID: myKeyID,
		KTY: jwkset.KeyTypeOct.String(),
	}

	options := jwkset.KeyUnmarshalOptions{}
	meta, err := jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrUnsupportedKeyType) {
		t.Fatalf("Symmetric key should be unsupported for given options. %s", err)
	}

	options.Symmetric = true
	meta, err = jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	if !bytes.Equal([]byte(hmacSecret), meta.Key.([]byte)) {
		t.Fatalf("Unmarshaled key does not match original key.")
	}
	if meta.KeyID != myKeyID {
		t.Fatalf("Unmarshaled key ID does not match original key ID.")
	}

	jwk.K = ""
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "K" is empty. %s`, err)
	}

	jwk.K = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "K" is invalid raw Base64URL. %s`, err)
	}
}
