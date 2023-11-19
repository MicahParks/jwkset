package jwkset

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// KeyWithMeta is holds a Key and its metadata.
type KeyWithMeta[CustomKeyMeta any] struct {
	ALG     ALG
	Custom  CustomKeyMeta
	Key     any
	KeyID   string
	X5C     []string
	X5T     string
	X5TS256 string
	X5U     string
}

// NewKey creates a new KeyWithMeta.
func NewKey[CustomKeyMeta any](key any, keyID string) KeyWithMeta[CustomKeyMeta] {
	return KeyWithMeta[CustomKeyMeta]{
		Key:   key,
		KeyID: keyID,
	}
}

// JWKSet is a set of JSON Web Keys.
type JWKSet[CustomKeyMeta any] struct {
	Store Storage[CustomKeyMeta]
}

// NewMemory creates a new in-memory JWKSet.
func NewMemory[CustomKeyMeta any]() JWKSet[CustomKeyMeta] {
	return JWKSet[CustomKeyMeta]{
		Store: NewMemoryStorage[CustomKeyMeta](),
	}
}

// JSONPublic creates the JSON representation of the public keys in JWKSet.
func (j JWKSet[CustomKeyMeta]) JSONPublic(ctx context.Context) (json.RawMessage, error) {
	return j.JSONWithOptions(ctx, JWKOptions{})
}

// JSONPrivate creates the JSON representation of the JWKSet public and private key material.
func (j JWKSet[CustomKeyMeta]) JSONPrivate(ctx context.Context) (json.RawMessage, error) {
	options := JWKOptions{
		AsymmetricPrivate: true,
		Symmetric:         true,
	}
	return j.JSONWithOptions(ctx, options)
}

// JSONWithOptions creates the JSON representation of the JWKSet with the given options.
func (j JWKSet[CustomKeyMeta]) JSONWithOptions(ctx context.Context, options JWKOptions) (json.RawMessage, error) {
	jwks := JWKSMarshal{}

	keys, err := j.Store.SnapshotKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot of all keys from storage: %w", err)
	}

	for _, meta := range keys {
		jwk, err := KeyMarshal(meta, options)
		if err != nil {
			if errors.Is(err, ErrUnsupportedKey) {
				// Ignore the key.
				continue
			}
			return nil, fmt.Errorf("failed to marshal key: %w", err)
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}

	return json.Marshal(jwks)
}

func DefaultGetX5U(u *url.URL) ([]*x509.Certificate, error) {
	timeout := time.Minute
	ctx, cancel := context.WithTimeoutCause(context.Background(), timeout, fmt.Errorf("%w: timeout of %s reached", ErrGetX5U, timeout.String()))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create X5U request: %w", errors.Join(ErrGetX5U, err))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do X5U request: %w", errors.Join(ErrGetX5U, err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: X5U request returned status code %d", ErrGetX5U, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read X5U response body: %w", errors.Join(ErrGetX5U, err))
	}
	certs, err := x509.ParseCertificates(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X5U response body: %w", errors.Join(ErrGetX5U, err))
	}
	return certs, nil
}
