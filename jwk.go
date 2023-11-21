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

// JWKSet is a set of JSON Web Keys.
type JWKSet struct {
	Store Storage
}

// NewMemory creates a new in-memory JWKSet.
func NewMemory() JWKSet {
	return JWKSet{
		Store: NewMemoryStorage(),
	}
}

// JSONPublic creates the JSON representation of the public keys in JWKSet.
func (j JWKSet) JSONPublic(ctx context.Context) (json.RawMessage, error) {
	return j.JSONWithOptions(ctx, JWKMarshalOptions{}, JWKValidateOptions{})
}

// JSONPrivate creates the JSON representation of the JWKSet public and private key material.
func (j JWKSet) JSONPrivate(ctx context.Context) (json.RawMessage, error) {
	marshalOptions := JWKMarshalOptions{
		MarshalAsymmetricPrivate: true,
		MarshalSymmetric:         true,
	}
	return j.JSONWithOptions(ctx, marshalOptions, JWKValidateOptions{})
}

// JSONWithOptions creates the JSON representation of the JWKSet with the given options.
func (j JWKSet) JSONWithOptions(ctx context.Context, marshalOptions JWKMarshalOptions, validationOptions JWKValidateOptions) (json.RawMessage, error) {
	jwks := JWKSMarshal{}

	keys, err := j.Store.SnapshotKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot of all keys from storage: %w", err)
	}

	for _, key := range keys {
		options := key.options
		options.Marshal = marshalOptions
		options.Validate = validationOptions
		marshal, err := keyMarshal(key.Key(), options)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal key: %w", err)
		}
		jwks.Keys = append(jwks.Keys, marshal)
	}

	return json.Marshal(jwks)
}

// DefaultGetX5U is the default implementation of the GetX5U field for JWKValidateOptions.
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
