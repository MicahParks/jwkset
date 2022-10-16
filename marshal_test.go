package jwkset_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/MicahParks/jwkset"
)

const myKeyID = "myKeyID"

func TestMarshalEdDSA(t *testing.T) {
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

	meta := jwkset.KeyWithMeta{
		Key: private,
	}

	options := jwkset.KeyMarshalOptions{}
	marshal, err := jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}

	if marshal.D != "" {
		t.Fatalf("Symmetric key should be unsupported for given options.")
	}

	options.AsymmetricPrivate = true
	marshal, err = jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}

	// TODO Check ALG.
	if marshal.CRV != jwkset.CurveEd25519.String() {
		t.Fatalf(`Should get curve "%s". %s`, jwkset.CurveEd25519.String(), marshal.CRV)
	}
	if marshal.D != privateString {
		t.Fatalf("Private key does not match original key.")
	}
	if marshal.KTY != jwkset.KeyTypeOKP.String() {
		t.Fatalf("Key type does not match original key.")
	}
	if marshal.X != publicString {
		t.Fatalf("Public key does not match original key.")
	}
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

	jwk.D = "&"
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "D" is invalid raw Base64URL. %s`, err)
	}

	jwk.X = ""
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "X" is empty. %s`, err)
	}

	jwk.X = "&"
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
		Key: []byte("myHMACSecret"),
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
	const hmacSecret = "myHMACSecret"

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

	jwk.K = "&"
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "K" is invalid raw Base64URL. %s`, err)
	}
}
