package jwkset

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

const (
	kidMissing  = "kid missing"
	kidWritten  = "kid written"
	kidWritten2 = "kid written 2"
)

var (
	hmacKey1 = []byte("hamc key 1")
	hmacKey2 = []byte("hamc key 2")
)

type storageTestParams struct {
	ctx    context.Context
	cancel context.CancelFunc
	jwks   Storage
}

func TestMemoryKeyDelete(t *testing.T) {
	params := setupMemory()
	defer params.cancel()
	store := params.jwks

	jwk := newStorageTestJWK(t, hmacKey1, kidWritten)
	err := store.KeyWrite(params.ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to write key. %s", err)
	}

	ok, err := store.KeyDelete(params.ctx, kidMissing)
	if err != nil {
		t.Fatalf("Failed to delete missing key. %s", err)
	}
	if ok {
		t.Fatalf("Deleted missing key.")
	}

	ok, err = store.KeyDelete(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to delete written key. %s", err)
	}
	if !ok {
		t.Fatalf("Failed to delete written key.")
	}
}

func TestMemoryKeyRead(t *testing.T) {
	params := setupMemory()
	defer params.cancel()
	store := params.jwks

	jwk := newStorageTestJWK(t, hmacKey1, kidWritten)
	err := store.KeyWrite(params.ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to write key. %s", err)
	}

	_, err = store.KeyRead(params.ctx, kidMissing)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Should have specific error when reading missing key.\n  Actual: %s\n  Expected: %s", err, ErrKeyNotFound)
	}

	key, err := store.KeyRead(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to read written key. %s", err)
	}

	if !bytes.Equal(key.Key().([]byte), hmacKey1) {
		t.Fatalf("Read key does not match written key.")
	}
	ok, err := store.KeyDelete(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to delete written key. %s", err)
	}
	if !ok {
		t.Fatalf("Failed to delete written key.")
	}

	jwk = newStorageTestJWK(t, hmacKey2, kidWritten)
	err = store.KeyWrite(params.ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to overwrite key. %s", err)
	}

	key, err = store.KeyRead(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to read written key. %s", err)
	}

	if !bytes.Equal(key.Key().([]byte), hmacKey2) {
		t.Fatalf("Read key does not match written key.")
	}

	ok, err = store.KeyDelete(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to delete written key. %s", err)
	}
	if !ok {
		t.Fatalf("Failed to delete written key.")
	}

	_, err = store.KeyRead(params.ctx, kidWritten)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Should have specific error when reading missing key.\n  Actual: %s\n  Expected: %s", err, ErrKeyNotFound)
	}
}

func TestMemoryKeyReadAll(t *testing.T) {
	params := setupMemory()
	defer params.cancel()
	store := params.jwks

	jwk := newStorageTestJWK(t, hmacKey1, kidWritten)
	err := store.KeyWrite(params.ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to write key 1. %s", err)
	}

	jwk = newStorageTestJWK(t, hmacKey2, kidWritten2)
	err = store.KeyWrite(params.ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to write key 2. %s", err)
	}

	keys, err := store.KeyReadAll(params.ctx)
	if err != nil {
		t.Fatalf("Failed to snapshot keys. %s", err)
	}
	if len(keys) != 2 {
		t.Fatalf("Snapshot should have 2 keys. %d", len(keys))
	}

	kid1Found := false
	kid2Found := false
	for _, jwk := range keys {
		if !kid1Found && jwk.Marshal().KID == kidWritten {
			kid1Found = true
			if !bytes.Equal(jwk.Key().([]byte), hmacKey1) {
				t.Fatalf("Snapshot key does not match written key.")
			}
		} else if !kid2Found && jwk.Marshal().KID == kidWritten2 {
			kid2Found = true
			if !bytes.Equal(jwk.Key().([]byte), hmacKey2) {
				t.Fatalf("Snapshot key does not match written key.")
			}
		} else {
			t.Fatalf("Snapshot key has unexpected key ID.")
		}
	}
}

func TestMemoryKeyReplaceAll(t *testing.T) {
	params := setupMemory()
	defer params.cancel()
	store := params.jwks

	jwk1 := newStorageTestJWK(t, hmacKey1, kidWritten)
	err := store.KeyWrite(params.ctx, jwk1)
	if err != nil {
		t.Fatalf("Failed to write key 1.\nError: %s", err)
	}

	jwk2 := newStorageTestJWK(t, hmacKey2, kidWritten2)
	err = store.KeyWrite(params.ctx, jwk2)
	if err != nil {
		t.Fatalf("Failed to write key 2.\nError: %s", err)
	}

	keys, err := store.KeyReadAll(params.ctx)
	if err != nil {
		t.Fatalf("Failed to read all keys.\nError: %s", err)
	}
	if len(keys) != 2 {
		t.Fatalf("Expected 2 keys before replace, got %d.", len(keys))
	}

	given := newStorageTestJWK(t, []byte("new key"), "new-kid")
	err = store.KeyReplaceAll(params.ctx, []JWK{given})
	if err != nil {
		t.Fatalf("Failed to replace all keys.\nError: %s", err)
	}

	keys, err = store.KeyReadAll(params.ctx)
	if err != nil {
		t.Fatalf("Failed to read all keys after replace.\nError: %s", err)
	}
	if len(keys) != 1 {
		t.Fatalf("Expected 1 key after replace, got %d.", len(keys))
	}
	if keys[0].Marshal().KID != "new-kid" {
		t.Fatalf("Unexpected key ID after replace. Got %q, expected %q.", keys[0].Marshal().KID, "new-kid")
	}
	if !bytes.Equal(keys[0].Key().([]byte), []byte("new key")) {
		t.Fatalf("Unexpected key material after replace.")
	}
}

func TestMemoryKeyWrite(t *testing.T) {
	params := setupMemory()
	defer params.cancel()
	store := params.jwks

	jwk := newStorageTestJWK(t, hmacKey1, kidWritten)
	err := store.KeyWrite(params.ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to write key. %s", err)
	}

	jwk = newStorageTestJWK(t, hmacKey2, kidWritten)
	err = store.KeyWrite(params.ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to overwrite key. %s", err)
	}
}

func setupMemory() (params storageTestParams) {
	jwkSet := NewMemoryStorage()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	params = storageTestParams{
		ctx:    ctx,
		cancel: cancel,
		jwks:   jwkSet,
	}
	return params
}

func newStorageTestJWK(t *testing.T, key any, keyID string) JWK {
	marshal := JWKMarshalOptions{
		Private: true,
	}
	metadata := JWKMetadataOptions{
		KID: keyID,
	}
	options := JWKOptions{
		Marshal:  marshal,
		Metadata: metadata,
	}
	jwk, err := NewJWKFromKey(key, options)
	if err != nil {
		t.Fatalf("Failed to create JWK. %s", err)
	}
	return jwk
}
