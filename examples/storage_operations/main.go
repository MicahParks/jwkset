package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"log"
	"os"

	"github.com/google/uuid"

	"github.com/MicahParks/jwkset"
)

const logFmt = "%s\nError: %s"

func main() {
	ctx := context.Background()
	logger := log.New(os.Stdout, "", 0)

	// Create a new JWK Set using memory-backed storage.
	jwkSet := jwkset.NewMemory[any]()

	// Create a new ECDSA key and store it in the JWK Set.
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to generate ECDSA key.", err)
	}
	ecID := uuid.NewString()
	err = jwkSet.Store.WriteKey(ctx, jwkset.NewKey[any](ec, ecID))
	if err != nil {
		logger.Fatalf(logFmt, "Failed to store ECDSA key.", err)
	}

	// Create a new EdDSA key and store it in the JWK Set.
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to generate EdDSA key.", err)
	}
	edID := uuid.NewString()
	err = jwkSet.Store.WriteKey(ctx, jwkset.NewKey[any](ed, edID))
	if err != nil {
		logger.Fatalf(logFmt, "Failed to store EdDSA key.", err)
	}

	// Create a new RSA key and store it in the JWK Set.
	r, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to generate RSA key.", err)
	}
	rID := uuid.NewString()
	err = jwkSet.Store.WriteKey(ctx, jwkset.NewKey[any](r, rID))
	if err != nil {
		logger.Fatalf(logFmt, "Failed to store RSA key.", err)
	}

	// Create a new HMAC key and store it in the JWK Set.
	hmacSecret := []byte("my_hmac_secret")
	hid := uuid.NewString()
	err = jwkSet.Store.WriteKey(ctx, jwkset.KeyWithMeta[any]{
		Key:   hmacSecret,
		KeyID: hid,
	})

	// Print the JSON representation of the JWK Set.
	jsonRepresentation, err := jwkSet.JSONPublic(ctx)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to get JSON representation.", err)
	}
	logger.Println("Initial JSON representation:")
	logger.Println(string(jsonRepresentation))

	// Delete the previously added RSA key from the JWK Set, then reprint the JSON representation.
	_, err = jwkSet.Store.DeleteKey(ctx, rID)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to delete RSA key.", err)
	}
	jsonRepresentation, err = jwkSet.JSONPublic(ctx)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to get JSON representation.", err)
	}
	logger.Println("Deleted RSA key:")
	logger.Println(string(jsonRepresentation))

	// Delete the previously added ECDSA key from the JWK Set, add a new one, then reprint the JSON representation.
	_, err = jwkSet.Store.DeleteKey(ctx, ecID)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to delete ECDSA key.", err)
	}
	ec, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to generate ECDSA key.", err)
	}
	err = jwkSet.Store.WriteKey(ctx, jwkset.NewKey[any](ec, uuid.NewString()))
	if err != nil {
		logger.Fatalf(logFmt, "Failed to store ECDSA key.", err)
	}
	jsonRepresentation, err = jwkSet.JSONPublic(ctx)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to get JSON representation.", err)
	}
	logger.Println("Deleted ECDSA key and added a new one:")
	logger.Println(string(jsonRepresentation))

	// Read the previously added EdDSA key from the JWK Set, the print its private key.
	meta, err := jwkSet.Store.ReadKey(ctx, edID)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to read EdDSA key.", err)
	}
	edKey, ok := meta.Key.(ed25519.PrivateKey)
	if !ok {
		logger.Fatalf(logFmt, "Failed to cast EdDSA key.", err)
	}
	logger.Printf("Retrieved EdDSA private key Base64RawURL: %s", base64.RawURLEncoding.EncodeToString(edKey))

	// Read the previously added HMAC key from the JWK Set, the print it.
	meta, err = jwkSet.Store.ReadKey(ctx, hid)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to read HMAC key.", err)
	}
	hKey, ok := meta.Key.([]byte)
	if !ok {
		logger.Fatalf(logFmt, "Failed to cast HMAC key.", err)
	}
	logger.Printf("Retrieved HMAC secret: %s", hKey)
}
