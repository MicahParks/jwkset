[![Go Report Card](https://goreportcard.com/badge/github.com/MicahParks/jwkset)](https://goreportcard.com/report/github.com/MicahParks/jwkset) [![Go Reference](https://pkg.go.dev/badge/github.com/MicahParks/jwkset.svg)](https://pkg.go.dev/github.com/MicahParks/jwkset)
# JWK Set
This is a minimal JWK Set (JWKS or jwks) server-side implementation. For a JWK Set client,
see [`github.com/MicahParks/keyfunc`](https://github.com/MicahParks/keyfunc). Cryptographic keys can be added, deleted,
and read from the JWK Set. A JSON representation of the JWK Set can be created for hosting via HTTPS. This project
includes an in-memory storage implementation, but an interface is provided for more advanced use cases.

Currently, only _public_ key material will be included in the JSON representation via the `.JSON` method. For example,
any HMAC keys stored within the JWK Set will not be included in the JSON representation. In the future, if there is a
feature to include private key material in the JSON representation, it will be added in another method, such as
`.JSONWithPrivateKeys`.

This project only depends on packages from the standard Go library. It has no external dependencies.

The following key types have a JSON representation:

| Key type | Go type                                                              | External link                                                                                                                  |
|----------|----------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| `EC`     | [`*ecdsa.PrivateKey`](https://pkg.go.dev/crypto/ecdsa#PrivateKey)    | [Elliptic Curve Digital Signature Algorithm (ECDSA)](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) |
| `OKP`    | [`ed25519.PrivateKey`](https://pkg.go.dev/crypto/ed25519#PrivateKey) | [Edwards-curve Digital Signature Algorithm (EdDSA)](https://en.wikipedia.org/wiki/EdDSA)                                       |
| `RSA`    | [`*rsa.PrivateKey`](https://pkg.go.dev/crypto/rsa#PrivateKey)        | [Rivest–Shamir–Adleman (RSA)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))                                                |

Other key types, such as HMAC (`OCT`, `[]byte`) can also be placed inside the JWK Set, but they will not be included in
the JSON representation.

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
		response, err := jwkSet.JSON(request.Context())
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

# Test coverage
Test coverage is currently greater than `95%`.

```
$ go test -cover -race
PASS
coverage: 98.5% of statements
ok      github.com/MicahParks/jwkset    0.021s
```

# References
This project was built and tested using various RFCs and services. The services are listed below:
* [mkjwk.org](https://github.com/mitreid-connect/mkjwk.org)

See also:
* [`github.com/MicahParks/keyfunc`](https://github.com/MicahParks/keyfunc)
* [`github.com/golang-jwt/jwt/v4`](https://github.com/golang-jwt/jwt)
