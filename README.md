[![Go Reference](https://pkg.go.dev/badge/github.com/MicahParks/jwkset.svg)](https://pkg.go.dev/github.com/MicahParks/jwkset)

# JWK Set (JSON Web Key Set)

This is a JWK Set (JSON Web Key Set) implementation written in Golang.

If you would like to run a JWK Set server without writing any Golang code, please visit the Docker server section below.
TODO

If you would like to have a JWK Set client without writing any Golang code, you can use the
[JWK Set Client Proxy (JCP) project](https://github.com/MicahParks/jcp) perform JWK Set client operations in the
language of your choice using an OpenAPI interface.

# Generate a JWK Set

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
    * Go Types: `ed25519.PrivateKey` and `ed25519.PublicKey`
* [Elliptic-curve Diffie–Hellman (ECDH)](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) (X25519
  only)
    * Go Types: `*ecdh.PrivateKey` and `*ecdh.PublicKey`
* [Elliptic Curve Digital Signature Algorithm (ECDSA)](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
    * Go Types: `*ecdsa.PrivateKey` and `*ecdsa.PublicKey`
* [Rivest–Shamir–Adleman (RSA)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
    * Go Types: `*rsa.PrivateKey` and `*rsa.PublicKey`
* [HMAC](https://en.wikipedia.org/wiki/HMAC), [AES Key Wrap](https://en.wikipedia.org/wiki/Key_Wrap), and other
  symmetric keys
    * Go Type: `[]byte`

Cryptographic keys can be added, deleted, and read from the JWK Set. A JSON representation of the JWK Set can be created
for hosting via HTTPS. This project includes an in-memory storage implementation, but an interface is provided for more
advanced use cases. For this implementation, a key ID (`kid`) is required.

# Notes

This project aims to implement the relevant RFCs to the fullest extent possible using the Go standard library, but does
not implement any cryptographic algorithms itself.

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

```
$ go test -cover -race
PASS
coverage: 86.5% of statements
ok      github.com/MicahParks/jwkset    1.064s
```

# References

This project was built and tested using various RFCs and services. The services are listed below:

* [mkjwk.org](https://github.com/mitreid-connect/mkjwk.org)

See also:

* [`github.com/MicahParks/jcp`](https://github.com/MicahParks/jcp)
* [`github.com/MicahParks/keyfunc`](https://github.com/MicahParks/keyfunc)