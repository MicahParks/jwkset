package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

const (
	logFmt   = "%s\nError: %s"
	privFile = "ec256SEC1Priv.pem"
)

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf(logFmt, "Failed to generate EC key.", err)
	}

	pemBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf(logFmt, "Failed to marshal EC private key.", err)
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: pemBytes,
	}
	out := pem.EncodeToMemory(block)

	err = os.WriteFile(privFile, out, 0644)
	if err != nil {
		log.Fatalf(logFmt, "Failed to write EC private key.", err)
	}
}
