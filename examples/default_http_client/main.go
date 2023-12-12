package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/MicahParks/jwkset"
)

const myKeyID = "my-key-id"

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up the server.
	serverStore := jwkset.NewMemoryStorage()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key pair for server. Error: %s", err)
	}
	metadata := jwkset.JWKMetadataOptions{
		KID: myKeyID,
	}
	jwkOptions := jwkset.JWKOptions{
		Metadata: metadata,
	}
	jwk, err := jwkset.NewJWKFromKey(priv, jwkOptions)
	if err != nil {
		log.Fatalf("Failed to create JWK for server. Error: %s", err)
	}
	err = serverStore.KeyWrite(ctx, jwk)
	if err != nil {
		log.Fatalf("Failed to write JWK for server. Error: %s", err)
	}
	rawJWKS, err := serverStore.JSONPrivate(ctx)
	if err != nil {
		log.Fatalf("Failed to get JWK set for server. Error: %s", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(rawJWKS)
	}))

	// Create a JWK Set client from the server's HTTP URL.
	jwks, err := jwkset.NewDefaultHTTPClient([]string{server.URL})
	if err != nil {
		log.Fatalf("Failed to create client JWK set. Error: %s", err)
	}

	// Read a key from the client.
	jwk, err = jwks.KeyRead(ctx, myKeyID)
	if err != nil {
		log.Fatalf("Failed to read key from client JWK set. Error: %s", err)
	}

	// Verify the key is correct. (Optional)
	if !bytes.Equal(jwk.Key().(ed25519.PrivateKey), priv) {
		log.Fatalf("Client JWK set returned the wrong key.")
	}
	println("The correct key was returned and is ready to be used from the client storage.")
}
