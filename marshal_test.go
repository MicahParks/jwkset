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
	ecdsaP256D    = "GpanYiHB-TeCKFmfAwqzIJVhziUH6QX77obHwDPERGo"
	ecdsaP256X    = "IZrURsAt0DcSytZRCBQ4SjCcbIhLLQvg53uSkRdETZ4"
	ecdsaP256Y    = "Uy2iBhx7jMXB4n8fPASCOaNjnUPd8C1toVwytGeAEdU"
	ecdsaP384D    = "P0mnrdElxUwAOcYeRlEz6uUNM6v_Bj4iBB4qxfEQ0xpKiAI5wM1lhzyoXibfWRHo"
	ecdsaP384X    = "qL8wKJLZT5qowOGc8FMYqMWurcdVL15VxHqYV5JmJYj0EjBiPv14iwUrnhEEHVS9"
	ecdsaP384Y    = "5qSWUmTjYNREUNCjDyAxu-ymHUGOtnEzO2z_pxtl5vd4W5Eb_9QcK9E9z3G3Xxjp"
	ecdsaP521D    = "AE4nfzwC69AYJhoJav6VH_rCFodPqcy5Li-6ISmJsLBZwvHX-2S0EYxsPuuk5shfxSFHJbXaD_t85doozgcsV_8t"
	ecdsaP521X    = "ARxti_MdbyBVgT4N-08XzYBx5c8ZUPtZXshNHu_AoMwQqXq0WjZznL5b2175hv8nsUvRshjHpHaj_7SWQl5vH9f0"
	ecdsaP521Y    = "AYx5MdFtiuPA1_IVS0A0z8MhLmQNJOxKd1hnhSRlod1sd7sz17WSXz-DggJwK5gj0qFp9_8dsVvI1Yn688myoImU"
	eddsaPrivate  = "5hT6NTzNJyUCaG7mqtq2ru0EsA2z5SwnnkP0pBycP64"
	eddsaPublic   = "VYk14QSFla7FKnL_okf6TqLIyV2X6DPaDi26UpAMVnM"
	hmacSecret    = "myHMACSecret"
	invalidB64URL = "&"
	myKeyID       = "myKeyID"
)

func TestMarshalECDSA(t *testing.T) {
	p256 := makeECDSAP256(t)
	checkMarshal := func(marshal jwkset.JWKMarshal, options jwkset.KeyMarshalOptions) {
		// TODO Check ALG.
		if marshal.CRV != jwkset.CurveP256.String() {
			t.Fatalf(`Should get curve "%s". %s`, jwkset.CurveP256.String(), marshal.CRV)
		}
		if options.AsymmetricPrivate {
			if marshal.D != ecdsaP256D {
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
		if marshal.X != ecdsaP256X {
			t.Fatalf("Public key does not match original key.")
		}
		if marshal.Y != ecdsaP256Y {
			t.Fatalf("Public key does not match original key.")
		}
	}

	meta := jwkset.KeyWithMeta{
		Key: p256,
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
		Key: p256.Public(),
	}
	options.AsymmetricPrivate = false
	marshal, err = jwkset.KeyMarshal(publicMeta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}

	checkMarshal(marshal, options)
}

func TestUnmarshalECDSA(t *testing.T) {
	checkUnmarshal := func(meta jwkset.KeyWithMeta, options jwkset.KeyUnmarshalOptions, original *ecdsa.PrivateKey) {
		var public *ecdsa.PublicKey
		var ok bool
		if options.AsymmetricPrivate {
			private, ok := meta.Key.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatal("Unmarshalled key should be a private key.")
			}
			if private.D.Cmp(original.D) != 0 {
				t.Fatal(`Unmarshalled key parameter "d" does not match original key.`)
			}
			public = private.Public().(*ecdsa.PublicKey)
		} else {
			public, ok = meta.Key.(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Unmarshalled key should be a public key.")
			}
		}
		if public.Curve != original.PublicKey.Curve {
			t.Fatal(`Unmarshalled key parameter "crv" does not match original key.`)
		}
		if public.X.Cmp(original.PublicKey.X) != 0 {
			t.Fatal(`Unmarshalled key parameter "x" does not match original key.`)
		}
		if public.Y.Cmp(original.PublicKey.Y) != 0 {
			t.Fatal(`Unmarshalled key parameter "y" does not match original key.`)
		}
	}

	jwk := jwkset.JWKMarshal{
		CRV: jwkset.CurveP256.String(),
		D:   ecdsaP256D,
		KTY: jwkset.KeyTypeEC.String(),
		X:   ecdsaP256X,
		Y:   ecdsaP256Y,
	}

	key := makeECDSAP256(t)
	options := jwkset.KeyUnmarshalOptions{}
	meta, err := jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, key)

	options.AsymmetricPrivate = true
	meta, err = jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, key)

	key = makeECDSAP384(t)
	jwk.CRV = jwkset.CurveP384.String()
	jwk.D = ecdsaP384D
	jwk.X = ecdsaP384X
	jwk.Y = ecdsaP384Y
	meta, err = jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, key)

	key = makeECDSAP521(t)
	jwk.CRV = jwkset.CurveP521.String()
	jwk.D = ecdsaP521D
	jwk.X = ecdsaP521X
	jwk.Y = ecdsaP521Y
	meta, err = jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, key)

	jwk.CRV = ""
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "crv" is empty. %s`, err)
	}

	jwk.CRV = "invalid"
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "crv" is invalid. %s`, err)
	}
	jwk.CRV = jwkset.CurveP521.String()

	jwk.D = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "d" is invalid raw Base64 URL. %s`, err)
	}
	jwk.D = ecdsaP521D

	jwk.X = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "x" is invalid raw Base64 URL. %s`, err)
	}
	jwk.X = ecdsaP521X

	jwk.Y = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "y" is invalid raw Base64 URL. %s`, err)
	}
	jwk.Y = ecdsaP521Y
}

func TestMarshalEdDSA(t *testing.T) {
	checkMarshal := func(marshal jwkset.JWKMarshal, options jwkset.KeyMarshalOptions) {
		// TODO Check ALG.
		if marshal.CRV != jwkset.CurveEd25519.String() {
			t.Fatalf(`Should get curve "%s". %s`, jwkset.CurveEd25519.String(), marshal.CRV)
		}
		if options.AsymmetricPrivate {
			if marshal.D != eddsaPrivate {
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
		if marshal.X != eddsaPublic {
			t.Fatalf("Public key does not match original key.")
		}
	}
	private := makeEdDSA(t)

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
	private := makeEdDSA(t)

	jwk := jwkset.JWKMarshal{
		CRV: jwkset.CurveEd25519.String(),
		D:   eddsaPrivate,
		KID: myKeyID,
		KTY: jwkset.KeyTypeOKP.String(),
		X:   eddsaPublic,
	}

	options := jwkset.KeyUnmarshalOptions{}
	meta, err := jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	switch meta.Key.(type) {
	case ed25519.PublicKey:
		// Do nothing.
	default:
		t.Fatal("Key type should be public key.")
	}

	options.AsymmetricPrivate = true
	meta, err = jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	if !bytes.Equal(private, meta.Key.(ed25519.PrivateKey)) {
		t.Fatalf("Unmarshalled key does not match original key.")
	}
	if meta.KeyID != myKeyID {
		t.Fatalf("Unmarshalled key ID does not match original key ID.")
	}

	jwk.D = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "d" is invalid raw Base64URL. %s`, err)
	}

	jwk.X = ""
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "x" is empty. %s`, err)
	}

	jwk.X = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "x" is invalid raw Base64URL. %s`, err)
	}

	jwk.CRV = ""
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "crv" is empty. %s`, err)
	}
	jwk.CRV = jwkset.CurveEd25519.String()

	invalidSize := base64.RawURLEncoding.EncodeToString([]byte("invalidSize"))
	jwk.X = invalidSize
	jwk.D = eddsaPrivate
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "x" is invalid size. %s`, err)
	}
	jwk.X = eddsaPublic

	jwk.D = invalidSize
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "d" is invalid size. %s`, err)
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
		t.Fatalf("Unmarshalled key does not match original key.")
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
		t.Fatalf("Unmarshalled key does not match original key.")
	}
	if meta.KeyID != myKeyID {
		t.Fatalf("Unmarshalled key ID does not match original key ID.")
	}

	jwk.K = ""
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "k" is empty. %s`, err)
	}

	jwk.K = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "k" is invalid raw Base64URL. %s`, err)
	}
}

func TestMarshalUnsupported(t *testing.T) {
	meta := jwkset.KeyWithMeta{
		Key: "unsupported",
	}

	options := jwkset.KeyMarshalOptions{}
	_, err := jwkset.KeyMarshal(meta, options)
	if !errors.Is(err, jwkset.ErrUnsupportedKeyType) {
		t.Fatalf("Unsupported key type should be unsupported for given options. %s", err)
	}
}

func TestUnmarshalUnsupported(t *testing.T) {
	jwk := jwkset.JWKMarshal{
		KTY: "unsupported",
	}

	options := jwkset.KeyUnmarshalOptions{}
	_, err := jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrUnsupportedKeyType) {
		t.Fatalf("Unsupported key type should return ErrUnsupportedKeyType. %s", err)
	}
}

func makeECDSAP256(t *testing.T) *ecdsa.PrivateKey {
	d, err := base64.RawURLEncoding.DecodeString(ecdsaP256D)
	if err != nil {
		t.Fatalf("Failed to decode private key. %s", err)
	}
	x, err := base64.RawURLEncoding.DecodeString(ecdsaP256X)
	if err != nil {
		t.Fatalf("Failed to decode x coordinate. %s", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(ecdsaP256Y)
	if err != nil {
		t.Fatalf("Failed to decode y coordinate. %s", err)
	}
	privateP256 := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		D: new(big.Int).SetBytes(d),
	}
	return privateP256
}

func makeECDSAP384(t *testing.T) *ecdsa.PrivateKey {
	d, err := base64.RawURLEncoding.DecodeString(ecdsaP384D)
	if err != nil {
		t.Fatalf("Failed to decode private key. %s", err)
	}
	x, err := base64.RawURLEncoding.DecodeString(ecdsaP384X)
	if err != nil {
		t.Fatalf("Failed to decode x coordinate. %s", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(ecdsaP384Y)
	if err != nil {
		t.Fatalf("Failed to decode y coordinate. %s", err)
	}
	privateP256 := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		D: new(big.Int).SetBytes(d),
	}
	return privateP256
}

func makeECDSAP521(t *testing.T) *ecdsa.PrivateKey {
	d, err := base64.RawURLEncoding.DecodeString(ecdsaP521D)
	if err != nil {
		t.Fatalf("Failed to decode private key. %s", err)
	}
	x, err := base64.RawURLEncoding.DecodeString(ecdsaP521X)
	if err != nil {
		t.Fatalf("Failed to decode x coordinate. %s", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(ecdsaP521Y)
	if err != nil {
		t.Fatalf("Failed to decode y coordinate. %s", err)
	}
	privateP256 := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		D: new(big.Int).SetBytes(d),
	}
	return privateP256
}

func makeEdDSA(t *testing.T) ed25519.PrivateKey {
	privateBytes, err := base64.RawURLEncoding.DecodeString(eddsaPrivate)
	if err != nil {
		t.Fatalf("Failed to decode private key. %s", err)
	}
	publicBytes, err := base64.RawURLEncoding.DecodeString(eddsaPublic)
	if err != nil {
		t.Fatalf("Failed to decode public key. %s", err)
	}
	private := ed25519.PrivateKey(append(privateBytes, publicBytes...))
	return private
}
