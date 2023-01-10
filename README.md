[![Go Report Card](https://goreportcard.com/badge/github.com/MicahParks/jwkset)](https://goreportcard.com/report/github.com/MicahParks/jwkset) [![Go Reference](https://pkg.go.dev/badge/github.com/MicahParks/jwkset.svg)](https://pkg.go.dev/github.com/MicahParks/jwkset)
# JWK Set
This is a JWK Set (JWKS or jwks) implementation. For a JWK Set client,
see [`github.com/MicahParks/keyfunc`](https://github.com/MicahParks/keyfunc). Cryptographic keys can be added, deleted,
and read from the JWK Set. A JSON representation of the JWK Set can be created for hosting via HTTPS. This project
includes an in-memory storage implementation, but an interface is provided for more advanced use cases. For this
implementation, a key ID (`kid`) is required.

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

	jwkSet := jwkset.NewMemory[any]()

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		logger.Fatalf(logFmt, "Failed to generate RSA key.", err)
	}

	err = jwkSet.Store.WriteKey(ctx, jwkset.NewKey[any](key, "my-key-id"))
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

# Test coverage
Test coverage is currently `99%`.

```
$ go test -cover -race
PASS
coverage: 98.5% of statements
ok      github.com/MicahParks/jwkset    0.031s
```

# References
This project was built and tested using various RFCs and services. The services are listed below:
* [mkjwk.org](https://github.com/mitreid-connect/mkjwk.org)

See also:
* [`github.com/MicahParks/keyfunc`](https://github.com/MicahParks/keyfunc)
* [`github.com/golang-jwt/jwt/v4`](https://github.com/golang-jwt/jwt)
