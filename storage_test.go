package jwkset

import (
	"bytes"
	"context"
	"errors"
	"sync"
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
	key, err := store.KeyRead(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to read overwritten key. %s", err)
	}
	if !bytes.Equal(key.Key().([]byte), hmacKey2) {
		t.Fatal("Read the original key after overwriting it.")
	}
}

func TestMemoryKeyWriteOverwrite(t *testing.T) {
	ids := []string{"first", "middle", "last"}
	for index, id := range ids {
		t.Run(id, func(t *testing.T) {
			ctx := context.Background()
			store := NewMemoryStorage()
			for _, keyID := range ids {
				if err := store.KeyWrite(ctx, newStorageTestJWK(t, hmacKey1, keyID)); err != nil {
					t.Fatal(err)
				}
			}
			before, err := store.KeyReadAll(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for rotation := 0; rotation < 10; rotation++ {
				secret := []byte{byte(rotation)}
				if err := store.KeyWrite(ctx, newStorageTestJWK(t, secret, id)); err != nil {
					t.Fatal(err)
				}
				key, err := store.KeyRead(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(key.Key().([]byte), secret) {
					t.Fatal("Read the original key after overwriting it.")
				}
				keys, err := store.KeyReadAll(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if len(keys) != len(ids) {
					t.Fatalf("Expected %d keys after overwrite, got %d.", len(ids), len(keys))
				}
				for i, key := range keys {
					if key.Marshal().KID != ids[i] {
						t.Fatal("Overwrite changed the order of stored keys.")
					}
					want := hmacKey1
					if i == index {
						want = secret
					}
					if !bytes.Equal(key.Key().([]byte), want) {
						t.Fatal("Snapshot contains incorrect key material.")
					}
				}
			}
			if !bytes.Equal(before[index].Key().([]byte), hmacKey1) {
				t.Fatal("Overwrite changed an earlier snapshot.")
			}
			if ok, err := store.KeyDelete(ctx, id); err != nil || !ok {
				t.Fatalf("Failed to delete overwritten key: %v, %v.", ok, err)
			}
			if _, err := store.KeyRead(ctx, id); !errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("Overwritten key remains after deletion: %v.", err)
			}
		})
	}
}

func TestMemoryKeyWriteWithoutID(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStorage()
	for _, secret := range [][]byte{hmacKey1, hmacKey2} {
		if err := store.KeyWrite(ctx, newStorageTestJWK(t, secret, "")); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := store.KeyReadAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("Expected both unnamed keys, got %d.", len(keys))
	}
	if !bytes.Equal(keys[0].Key().([]byte), hmacKey1) || !bytes.Equal(keys[1].Key().([]byte), hmacKey2) {
		t.Fatal("Unnamed keys changed.")
	}
}

func TestMemoryKeyWriteConcurrent(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStorage()
	keys := []JWK{newStorageTestJWK(t, hmacKey1, kidWritten), newStorageTestJWK(t, hmacKey2, kidWritten)}
	if err := store.KeyWrite(ctx, keys[0]); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, key := range keys {
		wg.Add(1)
		go func(key JWK) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if err := store.KeyWrite(ctx, key); err != nil {
					t.Error(err)
					return
				}
				all, err := store.KeyReadAll(ctx)
				if err != nil || len(all) != 1 {
					t.Errorf("Expected one key during concurrent overwrites: %d, %v.", len(all), err)
					return
				}
			}
		}(key)
	}
	wg.Wait()
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
