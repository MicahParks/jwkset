package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/golang-module/dongle"
	"github.com/lithammer/shortuuid/v3"

	"github.com/MicahParks/jwkset"
)

const (
	logErr = "error"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := slog.New(slog.NewTextHandler(os.Stderr, nil))

	flags := os.Args[1:]
	if len(flags) < 1 {
		printUsage()
		return
	}

	switch flags[0] {
	case "genkid":
		genkid()
		return
	case "genjwks":
		err := genjwks(ctx, flags)
		if err != nil {
			l.Error("Failed to generate JWKS.", err)
		}
		return
	default:
		printUsage()
		return
	}
}

func printUsage() {
	fmt.Println(`
	generate kid:
	  genkid
	  
	generate encoded jwk:
	  genjwks <kid> <file1 .pem or .crt> <file2 .pem or .crt> ... `)
}

func genkid() {
	fmt.Println("kid:")
	fmt.Println(shortuuid.New())
}

func genjwks(ctx context.Context, flags []string) error {
	kid := flags[1]
	allPEM := ""
	s := strings.Builder{}

	for _, fileName := range flags[2:] {
		b, err := os.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
		s.Write(bytes.TrimSpace(b))
		s.WriteRune('\n')
	}
	allPEM = s.String()

	jwks := jwkset.NewMemoryStorage()

	i := 0
	allPEMB := []byte(allPEM)
	for {
		metadata := jwkset.JWKMetadataOptions{}
		i++
		block, rest := pem.Decode(allPEMB)
		if block == nil {
			break
		}

		fmt.Printf("Processing PEM: %v \n", i)
		fmt.Printf("kid: %v \n\n", kid)
		fmt.Printf("ˇˇˇ Please copy the following jwk to env ˇˇˇ\n\n")
		use := "sig"
		alg := "RS256"
		if strings.Contains(block.Type, "PRIVATE") {
			use = "enc"
		}

		allPEMB = rest
		switch block.Type {
		case "CERTIFICATE":
			cert, err := jwkset.LoadCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to load certificates: %w", err)
			}
			metadata.KID = kid
			metadata.ALG = jwkset.ALG(alg)
			metadata.USE = jwkset.USE(use)
			x509Options := jwkset.JWKX509Options{
				X5C: []*x509.Certificate{cert},
			}
			options := jwkset.JWKOptions{
				Metadata: metadata,
				X509:     x509Options,
			}
			jwk, err := jwkset.NewJWKFromX5C(options)
			if err != nil {
				return fmt.Errorf("failed to create JWK from X5C: %w", err)
			}
			err = jwks.KeyWrite(ctx, jwk)
			if err != nil {
				return fmt.Errorf("failed to write JWK: %w", err)
			}
		default:
			key, err := jwkset.LoadX509KeyInfer(block)
			if err != nil {
				return fmt.Errorf("failed to load X509 key: %w", err)
			}
			metadata.KID = kid
			metadata.ALG = jwkset.ALG(alg)
			metadata.USE = jwkset.USE(use)
			marshalOptions := jwkset.JWKMarshalOptions{
				Private: true,
			}
			options := jwkset.JWKOptions{
				Marshal:  marshalOptions,
				Metadata: metadata,
			}
			jwk, err := jwkset.NewJWKFromKey(key, options)
			if err != nil {
				return fmt.Errorf("failed to create JWK from key: %w", err)
			}

			marshal := jwk.Marshal()
			b, err := json.Marshal(marshal)
			if err != nil {
				return fmt.Errorf("failed to marshal JSON: %w", err)
			}

			str := dongle.Encode.FromBytes(b).ByBase64URL().ToString()
			fmt.Println(str)
		}

		fmt.Printf("\n")
	}
	return nil
}
