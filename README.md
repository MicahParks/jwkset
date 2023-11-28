[![Go Reference](https://pkg.go.dev/badge/github.com/MicahParks/jwkset.svg)](https://pkg.go.dev/github.com/MicahParks/jwkset)

# JWK Set (JSON Web Key Set)

This project is a JWK Set (JSON Web Key Set) implementation written in Golang. Server and client side code is provided.

If you would like to run a JWK Set server without writing any Golang code, please visit the Docker server section below.
TODO

If you would like to have a JWK Set client without writing any Golang code, you can use the
[JWK Set Client Proxy (JCP) project](https://github.com/MicahParks/jcp) perform JWK Set client operations in the
lanaguage of your choice using an OpenAPI interface.

This project aims to implement the relevant RFCs to the fullest extent possible using the Go standard library, but does
not implement any cryptographic algorithms itself. Since the Go standard library does not support Ed448, neither does
this project. Please reference the [Notes](#notes) section for other important details.

# Generating a JWK Set

If you would like to generate a JWK Set without writing Golang code, this project publishes utilities to generate a JWK
Set from:

* PEM encoded X.509 Certificates
* PEM encoded public keys
* PEM encoded private keys

The PEM block type is used to infer which key type to decode. Reference the below table for

## Website

Please visit [https://jwkset.com](https://jwkset.com) to use the web interface for this project. You can self-host this
website by following the instructions in the [github.com/MicahParks/jwksetcom](https://github.com/MicahParks/jwksetcom).

## Command line

Gather your PEM encoded files and use the `cmd/jwksetinfer` command line tool to generate a JWK Set. This tool will
consume

TODO Add example.

# Supported keys

This project supports the following key types:

* [Edwards-curve Digital Signature Algorithm (EdDSA)](https://en.wikipedia.org/wiki/EdDSA) (Ed25519 only)
* [Elliptic-curve Diffie–Hellman (ECDH)](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) (X25519
  only)
* [Elliptic Curve Digital Signature Algorithm (ECDSA)](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
* [Rivest–Shamir–Adleman (RSA)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
* [HMAC](https://en.wikipedia.org/wiki/HMAC), [AES Key Wrap](https://en.wikipedia.org/wiki/Key_Wrap), and other
  symmetric keys.

Cryptographic keys can be added, deleted, and read from the JWK Set. A JSON representation of the JWK Set can be created
for hosting via HTTPS. This project includes an in-memory storage implementation, but an interface is provided for more
advanced use cases. For this implementation, a key ID (`kid`) is required.

This project only depends on packages from the standard Go library. It has no external dependencies.

The following key types have a JSON representation:

| Key type | Go private key type                                                  | Go public key type                                                 | External link                                                                                                                  |
|----------|----------------------------------------------------------------------|--------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| `EC`     | [`*ecdsa.PrivateKey`](https://pkg.go.dev/crypto/ecdsa#PrivateKey)    | [`*ecdsa.PublicKey`](https://pkg.go.dev/crypto/ecdsa#PublicKey)    | [Elliptic Curve Digital Signature Algorithm (ECDSA)](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) |
| `OKP`    | [`ed25519.PrivateKey`](https://pkg.go.dev/crypto/ed25519#PrivateKey) | [`ed25519.PublicKey`](https://pkg.go.dev/crypto/ed25519#PublicKey) | [Edwards-curve Digital Signature Algorithm (EdDSA)](https://en.wikipedia.org/wiki/EdDSA)                                       |
| `RSA`    | [`*rsa.PrivateKey`](https://pkg.go.dev/crypto/rsa#PrivateKey)        | [`*rsa.PublicKey`](https://pkg.go.dev/crypto/rsa#PublicKey)        | [Rivest–Shamir–Adleman (RSA)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))                                                |
| `oct`    | `[]byte`                                                             | none                                                               |                                                                                                                                |

Only the Go types listed in this table have a JSON representation. If you would like support for another key type,
please open an issue on GitHub.

# Example HTTP server

```go
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

	jwkSet := jwkset.NewMemory()

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to generate RSA key.", err)
	}

	err = jwkSet.Store.WriteKey(ctx, jwkset.NewKey(key, "my-key-id"))
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
```

# Example for marshalling a single key to a JSON Web Key

```go
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
	meta := jwkset.NewKey(private, "my-key-id")

	// Create the approrpiate options to include the private key material in the JSON representation.
	options := jwkset.KeyMarshalOptions{
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
	unmarshalOptions := jwkset.KeyUnmarshalOptions{
		AsymmetricPrivate: true,
	}

	// Convert the Go type back into a key with metadata.
	meta, err = jwkset.KeyUnmarshal(marshal, unmarshalOptions)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to unmarshal key.", err)
	}

	// Print the key ID.
	println(meta.KeyID)
}
```

# Notes

* RFC 8037 adds support for `Ed448`, `X448`, and `secp256k1`, but there is no Golang standard library support for these
  key types.
* RFC 7518 specifies that `Base64urlUInt` must use the "minimum number of octets" to represent the number. This can lead
  to a problem with parsing JWK made by other projects that may contain leading zeros in the
  non-compliant `Base64urlUInt` encoding. This error happens during JWK validation and will look
  like: `failed to validate JWK: marshaled JWK does not match original JWK`. To work around this, please modify the
  JWK's JSON to remove the leading zeros for a proper `Base64urlUInt` encoding. If you need help doing this, please open
  a GitHub issue.
* This project does not currently support JWK Set encryption using JWE. This would involve implementing the relevant JWE
  specifications. It may be implemented in the future if there is interest.

# Test coverage

TODO

# References

This project was built and tested using various RFCs and services. The services are listed below:

* [mkjwk.org](https://github.com/mitreid-connect/mkjwk.org)

See also:

* [`github.com/MicahParks/keyfunc`](https://github.com/MicahParks/keyfunc)
* [`github.com/golang-jwt/jwt/v4`](https://github.com/golang-jwt/jwt)
