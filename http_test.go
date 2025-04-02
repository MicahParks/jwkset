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

func TestClientCacheReplacement(t *testing.T) {
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
	defer server.Close()

	refreshInterval := 50 * time.Millisecond
	httpOptions := HTTPClientStorageOptions{
		Ctx:             ctx,
		RefreshInterval: refreshInterval,
	}
	clientStore, err := NewStorageFromHTTP(server.URL, httpOptions)
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
	ok, err := serverStore.KeyDelete(ctx, kid)
	if err != nil {
		t.Fatalf("Failed to delete the given JWK from the store.\nError: %s", err)
	}
	if !ok {
		t.Fatalf("Expected the key to be deleted.")
	}
	rawJWKSMux.Lock()
	rawJWKS, err = serverStore.JSON(ctx)
	rawJWKSMux.Unlock()
	if err != nil {
		t.Fatalf("Failed to get the JSON.\nError: %s", err)
	}
	time.Sleep(2 * refreshInterval)

	jwks, err = clientStore.KeyReadAll(ctx)
	if err != nil {
		t.Fatalf("Failed to read the JWK.\nError: %s", err)
	}
	if len(jwks) != 1 {
		t.Fatalf("Expected to read 1 JWK, but got %d.", len(jwks))
	}
	if jwks[0].marshal.KID != otherKeyID {
		t.Fatalf("The key read from the HTTP client did not match the original key.")
	}
	if !bytes.Equal(jwks[0].Key().([]byte), otherSecret) {
		t.Fatalf("The key read from the HTTP client did not match the original key.")
	}
}

func TestClientHTTPURLs(t *testing.T) {
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
	defer server.Close()

	clientOptions := HTTPClientOptions{
		HTTPURLs: map[string]Storage{server.URL: nil},
	}
	store, err := NewHTTPClient(clientOptions)
	if err != nil {
		t.Fatalf("Failed to create a new HTTP client.\nError: %s", err)
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

func TestHTTPClientKeyReplaceAll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	givenStore := NewMemoryStorage()
	givenKey := newStorageTestJWK(t, hmacKey1, kidWritten)
	err := givenStore.KeyWrite(ctx, givenKey)
	if err != nil {
		t.Fatalf("Failed to write key to given store.\nError: %s", err)
	}

	httpStore := NewMemoryStorage()
	httpKey := newStorageTestJWK(t, hmacKey2, kidWritten2)
	err = httpStore.KeyWrite(ctx, httpKey)
	if err != nil {
		t.Fatalf("Failed to write key to HTTP store.\nError: %s", err)
	}

	client := httpClient{
		given:    givenStore,
		httpURLs: map[string]Storage{"https://example.com": httpStore},
	}

	keys, err := client.KeyReadAll(ctx)
	if err != nil {
		t.Fatalf("Failed to read all keys before replace.\nError: %s", err)
	}
	if len(keys) != 2 {
		t.Fatalf("Expected 2 keys before replace, got %d.", len(keys))
	}

	newKey := newStorageTestJWK(t, []byte("new key"), "new-kid")
	err = client.KeyReplaceAll(ctx, []JWK{newKey})
	if err != nil {
		t.Fatalf("KeyReplaceAll failed.\nError: %s", err)
	}

	givenKeys, err := givenStore.KeyReadAll(ctx)
	if err != nil {
		t.Fatalf("Failed to read all keys from given store after replace.\nError: %s", err)
	}
	if len(givenKeys) != 1 {
		t.Fatalf("Expected 1 key in given store after replace, got %d.", len(givenKeys))
	}
	if givenKeys[0].Marshal().KID != "new-kid" {
		t.Fatalf("Unexpected key ID in given store after replace. Got %q, expected %q.", givenKeys[0].Marshal().KID, "new-kid")
	}

	httpKeys, err := httpStore.KeyReadAll(ctx)
	if err != nil {
		t.Fatalf("Failed to read all keys from HTTP store after replace.\nError: %s", err)
	}
	if len(httpKeys) != 0 {
		t.Fatalf("Expected 0 keys in HTTP store after replace, got %d.", len(httpKeys))
	}

	allKeys, err := client.KeyReadAll(ctx)
	if err != nil {
		t.Fatalf("Failed to read all keys after replace.\nError: %s", err)
	}
	if len(allKeys) != 1 {
		t.Fatalf("Expected 1 key after replace, got %d.", len(allKeys))
	}
	if allKeys[0].Marshal().KID != "new-kid" {
		t.Fatalf("Unexpected key ID after replace. Got %q, expected %q.", allKeys[0].Marshal().KID, "new-kid")
	}
	if !bytes.Equal(allKeys[0].Key().([]byte), []byte("new key")) {
		t.Fatalf("Unexpected key material after replace.")
	}
}
