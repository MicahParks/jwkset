package main

import (
	"context"
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
	block, rest := pem.Decode(b)
	for len(rest) != 0 { // TODO Make a server configuration data structure with JSON struct tags.
		block, rest = pem.Decode(rest)
		if block == nil {
			l.Error("Failed to decode PEM block",
				"error", err,
			)
			return
		}
		if block.Type == "CERTIFICATE" {
			chainBlock = append(chainBlock, block.Bytes...)
		}
	}
	pub, err := jwkset.LoadCertificates(chainBlock)
	if err != nil {
		l.Error("Failed to load public key",
			"error", err,
		)
		return
	}
	j := jwkset.NewMemory[any]()
	meta := jwkset.KeyWithMeta[any]{
		ALG:    "",
		Custom: nil,
		Key:    pub[0].PublicKey,
		KeyID:  uuid.Must(uuid.NewRandom()).String(),
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
