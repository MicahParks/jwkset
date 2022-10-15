package jwkset_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/MicahParks/jwkset"
)

func TestMarshalOct(t *testing.T) {
	meta := jwkset.KeyWithMeta{
		Key:   []byte("myHMACSecret"),
		KeyID: "",
	}

	options := jwkset.KeyMarshalOptions{}
	_, err := jwkset.KeyMarshal(meta, options)
	if !errors.Is(err, jwkset.ErrUnsupportedKeyType) {
		t.Fatalf("Symmetric key should be unsupported for given options. %s", err)
	}

	options.Symmetric = true
	_, err = jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
}

func TestUnmarshalOct(t *testing.T) {
	const hmacSecret = "myHMACSecret"
	const keyID = "myKeyID"
	jwk := jwkset.JWKMarshal{
		K:   base64.RawURLEncoding.EncodeToString([]byte(hmacSecret)),
		KID: keyID,
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
	if meta.KeyID != keyID {
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
