package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log"
	"os"

	"github.com/MicahParks/jwkset"
)

const logFmt = "%s\nError: %s"

func main() {
	logger := log.New(os.Stdout, "", 0)

	// Create an EdDSA key.
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to generate EdDSA key.", err)
	}

	// Create the JWK options.
	metadata := jwkset.JWKMetadataOptions{
		KID: "my-key-id", // Not technically required, but is required for JWK Set operations using this package.
	}
	options := jwkset.JWKOptions{
		Metadata: metadata,
	}

	// Create the JWK from the key and options.
	jwk, err := jwkset.NewJWKFromKey(public, options)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to create JWK from key.", err)
	}

	// Use the marshal type to marshal the key into a raw JSON.
	j, err := json.MarshalIndent(jwk.Marshal(), "", "  ")
	if err != nil {
		logger.Fatalf(logFmt, "Failed to marshal JSON.", err)
	}
	println(string(j))

	// Create a new JWK from the raw JSON.
	jwk, err = jwkset.NewJWKFromRawJSON(j, jwkset.JWKMarshalOptions{}, jwkset.JWKValidateOptions{})
	if err != nil {
		logger.Fatalf(logFmt, "Failed to create JWK from raw JSON.", err)
	}
	println(jwk.Marshal().KID)
}
