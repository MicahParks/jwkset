package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"os"

	"github.com/MicahParks/jwkset"
)

const (
	logFmt = "%s\nError: %s"
)

func main() {
	ctx := context.Background()
	logger := log.New(os.Stdout, "", 0)

	jwkSet := jwkset.NewMemoryStorage()

	// Create an RSA key.
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to generate RSA key.", err)
	}

	// Create the JWK options.
	metadata := jwkset.JWKMetadataOptions{
		KID: "my-key-id", // Not technically required, but is required for JWK Set operations using this package.
	}
	options := jwkset.JWKOptions{
		Metadata: metadata,
	}

	// Create the JWK from the key and options.
	jwk, err := jwkset.NewJWKFromKey(key, options)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to create JWK from key.", err)
	}

	// Write the key to the JWK Set storage.
	err = jwkSet.KeyWrite(ctx, jwk)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to store RSA key.", err)
	}

	http.HandleFunc("/jwks.json", func(writer http.ResponseWriter, request *http.Request) {
		// TODO Cache the JWK Set so storage isn't called for every request.
		response, err := jwkSet.JSONPublic(request.Context())
		if err != nil {
			logger.Printf(logFmt, "Failed to get JWK Set JSON.", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(response)
	})

	logger.Print("Visit: http://localhost:8080/jwks.json")
	logger.Fatalf("Failed to listen and serve: %s", http.ListenAndServe(":8080", nil))
}
