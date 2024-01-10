package jwkset

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kid := "my-key-id"
	secret := []byte("my-hmac-secret")
	serverStore := NewMemoryStorage()
	marshalOptions := JWKMarshalOptions{
		Private: true,
	}
	metadata := JWKMetadataOptions{
		KID: kid,
	}
	options := JWKOptions{
		Marshal:  marshalOptions,
		Metadata: metadata,
	}
	jwk, err := NewJWKFromKey(secret, options)
	if err != nil {
		t.Fatalf("Failed to create a JWK from the given HMAC secret.\nError: %s", err)
	}
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

	clientStore, err := NewDefaultHTTPClient([]string{server.URL})
	if err != nil {
		t.Fatalf("Failed to create a new HTTP client.\nError: %s", err)
	}

	jwk, err = clientStore.KeyRead(ctx, kid)
	if err != nil {
		t.Fatalf("Failed to read the JWK.\nError: %s", err)
	}

	if !bytes.Equal(jwk.Key().([]byte), secret) {
		t.Fatalf("The key read from the HTTP client did not match the original key.")
	}

	jwks, err := clientStore.KeyReadAll(ctx)
	if err != nil {
		t.Fatalf("Failed to read all the JWKs.\nError: %s", err)
	}
	if len(jwks) != 1 {
		t.Fatalf("Expected to read 1 JWK, but got %d.", len(jwks))
	}
	if !bytes.Equal(jwks[0].Key().([]byte), secret) {
		t.Fatalf("The key read from the HTTP client did not match the original key.")
	}

	ok, err := clientStore.KeyDelete(ctx, kid)
	if err != nil {
		t.Fatalf("Failed to delete the JWK.\nError: %s", err)
	}
	if !ok {
		t.Fatalf("Expected the key to be deleted.")
	}

	err = clientStore.KeyWrite(ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to write the JWK.\nError: %s", err)
	}
	jwk, err = clientStore.KeyRead(ctx, kid)
	if err != nil {
		t.Fatalf("Failed to read the JWK.\nError: %s", err)
	}
	if !bytes.Equal(jwk.Key().([]byte), secret) {
		t.Fatalf("The key read from the HTTP client did not match the original key.")
	}

	otherKeyID := myKeyID + "2"
	options.Metadata.KID = otherKeyID
	otherSecret := []byte("my-other-hmac-secret")
	jwk, err = NewJWKFromKey(otherSecret, options)
	if err != nil {
		t.Fatalf("Failed to create a JWK from the given HMAC secret.\nError: %s", err)
	}
	err = serverStore.KeyWrite(ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to write the given JWK to the store.\nError: %s", err)
	}
	rawJWKSMux.Lock()
	rawJWKS, err = serverStore.JSON(ctx)
	rawJWKSMux.Unlock()
	if err != nil {
		t.Fatalf("Failed to get the JSON.\nError: %s", err)
	}

	jwk, err = clientStore.KeyRead(ctx, otherKeyID)
	if err != nil {
		t.Fatalf("Failed to read the JWK.\nError: %s", err)
	}
	if !bytes.Equal(jwk.Key().([]byte), otherSecret) {
		t.Fatalf("The key read from the HTTP client did not match the original key.")
	}

	otherOtherKey := myKeyID + "3"
	options.Metadata.KID = otherOtherKey
	otherOtherSecret := []byte("my-other-other-hmac-secret")
	jwk, err = NewJWKFromKey(otherOtherSecret, options)
	if err != nil {
		t.Fatalf("Failed to create a JWK from the given HMAC secret.\nError: %s", err)
	}
	err = serverStore.KeyWrite(ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to write the given JWK to the store.\nError: %s", err)
	}
	rawJWKSMux.Lock()
	rawJWKS, err = serverStore.JSON(ctx)
	rawJWKSMux.Unlock()
	if err != nil {
		t.Fatalf("Failed to get the JSON.\nError: %s", err)
	}
	shortCtx, shortCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer shortCancel()
	jwk, err = clientStore.KeyRead(shortCtx, otherOtherKey)
	if err == nil || !strings.HasSuffix(err.Error(), "rate: Wait(n=1) would exceed context deadline") {
		t.Fatalf("Expected to exceed context deadline, but got %s.", err)
	}
}

func TestClientError(t *testing.T) {
	_, err := NewHTTPClient(HTTPClientOptions{})
	if err == nil {
		t.Fatalf("Expected an error when creating a new HTTP client without any URLs.")
	}
}

func TestClientJSON(t *testing.T) {
	c := httpClient{
		given: NewMemoryStorage(),
	}
	testJSON(context.Background(), t, c)
}
