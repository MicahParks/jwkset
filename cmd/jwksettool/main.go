package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/MicahParks/jwkset"
)

const (
	logErr = "error"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := slog.New(slog.NewTextHandler(os.Stderr, nil))

	allPEM := os.Getenv("PEM")
	if allPEM == "" {
		s := strings.Builder{}
		if len(os.Args) < 2 {
			l.Error("Please provide a list of PEM encoded files as CLI arguments or set the PEM environment variable.")
			os.Exit(1)
		}
		for _, fileName := range os.Args[1:] {
			b, err := os.ReadFile(fileName)
			if err != nil {
				l.Error("Failed to read file.",
					"fileName", fileName,
				)
				os.Exit(1)
			}
			s.Write(bytes.TrimSpace(b))
			s.WriteRune('\n')
		}
		allPEM = s.String()
	}

	jwks := jwkset.NewMemoryStorage()

	i := 0
	const kidPrefix = "UniqueKeyID"
	allPEMB := []byte(allPEM)
	for {
		metadata := jwkset.JWKMetadataOptions{}
		i++
		block, rest := pem.Decode(allPEMB)
		if block == nil {
			break
		}
		allPEMB = rest
		switch block.Type {
		case "CERTIFICATE":
			cert, err := jwkset.LoadCertificate(block.Bytes)
			if err != nil {
				l.Error("Failed to load certificates.",
					logErr, err,
				)
				os.Exit(1)
			}
			metadata.KID = kidPrefix + strconv.Itoa(i)
			x509Options := jwkset.JWKX509Options{
				X5C: []*x509.Certificate{cert},
			}
			options := jwkset.JWKOptions{
				Metadata: metadata,
				X509:     x509Options,
			}
			jwk, err := jwkset.NewJWKFromX5C(options)
			if err != nil {
				l.Error("Failed to create JWK from X5C.",
					logErr, err,
				)
				os.Exit(1)
			}
			err = jwks.KeyWrite(ctx, jwk)
			if err != nil {
				l.Error("Failed to write JWK.",
					logErr, err,
				)
				os.Exit(1)
			}
		default:
			key, err := jwkset.LoadX509KeyInfer(block)
			if err != nil {
				l.Error("Failed to load X509 key.",
					logErr, err,
				)
				os.Exit(1)
			}
			metadata.KID = kidPrefix + strconv.Itoa(i)
			marshalOptions := jwkset.JWKMarshalOptions{
				Private: true,
			}
			options := jwkset.JWKOptions{
				Marshal:  marshalOptions,
				Metadata: metadata,
			}
			jwk, err := jwkset.NewJWKFromKey(key, options)
			if err != nil {
				l.Error("Failed to create JWK from key.",
					logErr, err,
				)
				os.Exit(1)
			}
			err = jwks.KeyWrite(ctx, jwk)
			if err != nil {
				l.Error("Failed to write JWK.",
					logErr, err,
				)
				os.Exit(1)
			}
		}
	}

	marshal, err := jwks.Marshal(ctx)
	if err != nil {
		l.Error("Failed to marshal JWK set.",
			logErr, err,
		)
		os.Exit(1)
	}

	b, err := json.MarshalIndent(marshal, "", "  ")
	if err != nil {
		l.Error("Failed to marshal JSON.",
			logErr, err,
		)
		os.Exit(1)
	}

	_, _ = os.Stdout.Write(b)
}
