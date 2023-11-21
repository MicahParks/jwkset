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

	// Give this EdDSA key a key ID.
	metadata := jwkset.JWKMetadataOptions{
		KID: "my-key-id",
	}

	// Specify options for marshalling and unmarshalling this key from JSON.
	marshalOptions := jwkset.JWKMarshalOptions{
		MarshalAsymmetricPrivate:   true, // Required to marshal the EdDSA private key.
		MarshalSymmetric:           true, // Unused in this example, EdDSA is asymmetric.
		UnmarshalAsymmetricPrivate: true, // Required to unmarshal the EdDSA private key.
		UnmarshalSymmetric:         true, // Unused in this example, EdDSA is asymmetric.
	}

	// Create the JWK from the key and provided options.
	options := jwkset.JWKOptions{
		Marshal:  marshalOptions,
		Metadata: metadata,
	}
	jwk, err := jwkset.NewJWKFromKey(private, options)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to create JWK.", err)
	}

	// Marshal the JWK to JSON.
	raw, err := json.MarshalIndent(jwk.Marshal(), "", "  ")
	if err != nil {
		logger.Fatalf(logFmt, "Failed to marshal JSON.", err)
	}
	println(string(raw))

	// Unmarshal the raw JSON into the jwkset.JWKMarshal type.
	var marshal jwkset.JWKMarshal
	err = json.Unmarshal(raw, &marshal)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to unmarshal JSON.", err)
	}

	// Use the jwkset.JWKMarshal type to create a JWK.
	//
	// The options for JSON marshalling and unmarshalling are copied from earlier in the example.
	// The default validation options have been used.
	options.Marshal.UnmarshalAsymmetricPrivate = false
	jwk, err = jwkset.NewJWKFromMarshal(marshal, options.Marshal, jwkset.JWKValidateOptions{})
	if err != nil {
		logger.Fatalf(logFmt, "Failed to create JWK.", err)
	}

	// Print the key ID.
	println(jwk.Marshal().KID)
}
