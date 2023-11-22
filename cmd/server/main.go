package main

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"os"

	"github.com/google/uuid"

	"github.com/MicahParks/jwkset"
)

func main() {
	l := slog.Default()
	b, err := os.ReadFile("keys/chain.crt")
	if err != nil {
		l.Error("Failed to read file",
			"error", err,
		)
		return
	}
	chainBlock := make([]byte, 0)
	x5c := make([]string, 0)
	block, rest := pem.Decode(b)
	for { // TODO Make a server configuration data structure with JSON struct tags.
		if block.Type == "CERTIFICATE" {
			pemCert := base64.StdEncoding.EncodeToString(block.Bytes)
			x5c = append(x5c, pemCert)
			chainBlock = append(chainBlock, block.Bytes...)
		}
		if len(rest) == 0 {
			break
		}
		block, rest = pem.Decode(rest)
		if block == nil {
			l.Error("Failed to decode PEM block")
			return
		}
	}
	pub, err := jwkset.LoadCertificates(chainBlock)
	if err != nil {
		l.Error("Failed to load public key",
			"error", err,
		)
		return
	}
	j := jwkset.NewMemory()
	meta := jwkset.KeyWithMeta{
		ALG:     "",
		Custom:  nil,
		Key:     pub[0].PublicKey,
		KeyID:   uuid.Must(uuid.NewRandom()).String(),
		X5U:     "https://thing.com", // TODO
		X5C:     x5c,
		X5T:     "",
		X5TS256: "",
	}
	ctx := context.Background()
	err = j.Store.WriteKey(ctx, meta)
	if err != nil {
		l.Error("Failed to write key",
			"error", err,
		)
		return
	}
	out, err := j.JSONPrivate(ctx)
	if err != nil {
		l.Error("Failed to create JSON",
			"error", err,
		)
		return
	}
	err = os.WriteFile("keys/jwkset.json", out, 0600)
	if err != nil {
		l.Error("Failed to write file",
			"error", err,
		)
		return
	}
}
