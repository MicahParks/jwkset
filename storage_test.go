package jwkset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestCustomStorage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	secret := []byte("my-hmac-secret")
	jwk, err := NewJWKFromKey(secret, JWKOptions{
		Marshal:  JWKMarshalOptions{Private: true},
		Metadata: JWKMetadataOptions{KID: "my-key-id"},
	})
	if err != nil {
		t.Fatalf("Failed to create a JWK from the given HMAC secret.\nError: %s", err)
	}
	serverStore := NewMemoryStorage()
	err = serverStore.KeyWrite(ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to write the given JWK to the store.\nError: %s", err)
	}
	rawJWKS, err := serverStore.JSON(ctx)
	if err != nil {
		t.Fatalf("Failed to get the JSON.\nError: %s", err)
	}

	rawJWKSMux := sync.RWMutex{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawJWKSMux.RLock()
		defer rawJWKSMux.RUnlock()
		_, _ = w.Write(rawJWKS)
	}))
	defer server.Close()

	store, err := NewCustomStorage(CustomStorageOptions{
		RequestJWKSetFunc: getJWKSFromHTTP(server.URL),
	})
	if err != nil {
		t.Fatalf("Failed to create custom storage: %s", err)
	}

	jwks, err := store.KeyReadAll(ctx)
	if err != nil {
		t.Fatalf("Failed to read the JWK.\nError: %s", err)
	}
	if len(jwks) != 1 {
		t.Fatalf("Expected to read 1 JWK, but got %d.", len(jwks))
	}
	if !bytes.Equal(jwks[0].Key().([]byte), secret) {
		t.Fatalf("The key read from the HTTP client did not match the original key.")
	}

}

func getJWKSFromHTTP(remoteJWKSetURL string) func(ctx context.Context) (JWKSMarshal, error) {
	return func(ctx context.Context) (JWKSMarshal, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", remoteJWKSetURL, nil)
		if err != nil {
			return JWKSMarshal{}, fmt.Errorf("failed to create HTTP request for JWK Set refresh: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return JWKSMarshal{}, fmt.Errorf("failed to perform HTTP request for JWK Set refresh: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return JWKSMarshal{}, fmt.Errorf("%w: %d", ErrInvalidHTTPStatusCode, resp.StatusCode)
		}

		var jwks JWKSMarshal
		err = json.NewDecoder(resp.Body).Decode(&jwks)
		if err != nil {
			return JWKSMarshal{}, fmt.Errorf("failed to decode JWK Set response: %w", err)
		}
		return jwks, nil
	}
}
