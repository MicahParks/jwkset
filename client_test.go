package jwkset

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	testJSON(t, context.Background(), c)
}
