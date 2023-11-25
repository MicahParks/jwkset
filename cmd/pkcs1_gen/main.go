package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

const (
	logFmt   = "%s\nError: %s"
	privFile = "rsa2048PKCS1Priv.pem"
	pubFile  = "rsa2048PKCS1Pub.pem"
)

func main() {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf(logFmt, "Failed to generate RSA key.", err)
	}

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	out := pem.EncodeToMemory(block)

	err = os.WriteFile(privFile, out, 0644)
	if err != nil {
		log.Fatalf(logFmt, "Failed to write RSA private key.", err)
	}

	pub := &priv.PublicKey
	block = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pub),
	}
	out = pem.EncodeToMemory(block)

	err = os.WriteFile(pubFile, out, 0644)
	if err != nil {
		log.Fatalf(logFmt, "Failed to write RSA public key.", err)
	}
}
