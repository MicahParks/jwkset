package jwkset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
		AsymmetricPrivate: true,
		Symmetric:         true,
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
			if errors.Is(err, ErrOptions) {
				continue
			}
			return nil, fmt.Errorf("failed to marshal key: %w", err)
		}
		jwks.Keys = append(jwks.Keys, marshal)
	}

	return json.Marshal(jwks)
}
