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
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to generate EdDSA key.", err)
	}

	// Wrap the key in the appropriate Go type.
	meta := jwkset.NewKey[any](private, "my-key-id")

	// Create the approrpiate options to include the private key material in the JSON representation.
	options := jwkset.JWKOptions{
		AsymmetricPrivate: true,
	}

	// Marshal the key to a different Go type that can be serialized to JSON.
	marshal, err := jwkset.KeyMarshal(meta, options)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to marshal key.", err)
	}

	// Marshal the new type to JSON.
	j, err := json.MarshalIndent(marshal, "", "  ")
	if err != nil {
		logger.Fatalf(logFmt, "Failed to marshal JSON.", err)
	}
	println(string(j))

	// Unmarshal the raw JSON into a Go type that can be deserialized into a key.
	err = json.Unmarshal(j, &marshal)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to unmarshal JSON.", err)
	}

	// Create the appropriate options to include the private key material in the deserialization.
	//
	// If this option is not provided, the resulting key will be of the type ed25519.PublicKey.
	unmarshalOptions := jwkset.JWKMarshalOptions{
		AsymmetricPrivate: true,
	}

	// Convert the Go type back into a key with metadata.
	meta, err = jwkset.KeyUnmarshal[any](marshal, unmarshalOptions)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to unmarshal key.", err)
	}

	// Print the key ID.
	println(meta.KeyID)
}
