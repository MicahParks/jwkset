package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/MicahParks/jwkset"
)

const (
	logErr = "error"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	l := slog.Default()

	b, err := os.ReadFile("keys/chain.crt")
	if err != nil {
		l.Error("Failed to read file",
			logErr, err,
		)
		return
	}
	x5c, err := jwkset.LoadCertificates(b)
	if err != nil {
		l.Error("Failed to load certificates",
			logErr, err,
		)
		return
	}
	x509Options := jwkset.JWKX509Options{
		X5C: x5c,
		X5U: "",
	}
	options := jwkset.JWKOptions{
		Marshal:  jwkset.JWKMarshalOptions{},
		Metadata: jwkset.JWKMetadataOptions{},
		Validate: jwkset.JWKValidateOptions{},
		X509:     x509Options,
	}
	jwk, err := jwkset.NewJWKFromX5C(options)
	if err != nil {
		l.Error("Failed to create JWK",
			logErr, err,
		)
		return
	}

	j := jwkset.NewMemory()
	err = j.Store.WriteKey(ctx, jwk)
	if err != nil {
		l.Error("Failed to write key",
			logErr, err,
		)
		return
	}

	out, err := j.JSON(ctx)
	if err != nil {
		l.Error("Failed to create JSON",
			logErr, err,
		)
		return
	}

	err = os.WriteFile("keys/jwkset.json", out, 0600)
	if err != nil {
		l.Error("Failed to write file",
			logErr, err,
		)
		return
	}
}
