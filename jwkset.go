package jwkset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// JWKSet is a set of JSON Web Keys.
type JWKSet struct { // TODO Turn into functions that accept a Client.
	Store Storage
}

// NewMemory creates a new in-memory JWKSet.
func NewMemory() JWKSet {
	return JWKSet{
		Store: NewMemoryStorage(),
	}
}

func (j JWKSet) JSON(ctx context.Context) (json.RawMessage, error) {
	jwks, err := j.Marshal(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK Set: %w", err)
	}
	return json.Marshal(jwks)
}

// JSONPublic creates the JSON representation of the public keys in JWKSet.
func (j JWKSet) JSONPublic(ctx context.Context) (json.RawMessage, error) {
	return j.JSONWithOptions(ctx, JWKMarshalOptions{}, JWKValidateOptions{})
}

// JSONPrivate creates the JSON representation of the JWKSet public and private key material.
func (j JWKSet) JSONPrivate(ctx context.Context) (json.RawMessage, error) {
	marshalOptions := JWKMarshalOptions{
		Private: true,
	}
	return j.JSONWithOptions(ctx, marshalOptions, JWKValidateOptions{})
}

// JSONWithOptions creates the JSON representation of the JWKSet with the given options. These options override whatever
// options are set on the individual JWKs.
func (j JWKSet) JSONWithOptions(ctx context.Context, marshalOptions JWKMarshalOptions, validationOptions JWKValidateOptions) (json.RawMessage, error) {
	jwks, err := j.MarshalWithOptions(ctx, marshalOptions, validationOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK Set with options: %w", err)
	}
	return json.Marshal(jwks)
}

// Marshal transforms the JWK Set's current state into a Go type that can be marshaled into JSON.
func (j JWKSet) Marshal(ctx context.Context) (JWKSMarshal, error) {
	keys, err := j.Store.SnapshotKeys(ctx)
	if err != nil {
		return JWKSMarshal{}, fmt.Errorf("failed to read snapshot of all keys from storage: %w", err)
	}
	jwks := JWKSMarshal{}
	for _, key := range keys {
		jwks.Keys = append(jwks.Keys, key.Marshal())
	}
	return jwks, nil
}

// MarshalWithOptions transforms the JWK Set's current state into a Go type that can be marshaled into JSON with the
// given options. These options override whatever options are set on the individual JWKs.
func (j JWKSet) MarshalWithOptions(ctx context.Context, marshalOptions JWKMarshalOptions, validationOptions JWKValidateOptions) (JWKSMarshal, error) {
	jwks := JWKSMarshal{}

	keys, err := j.Store.SnapshotKeys(ctx)
	if err != nil {
		return JWKSMarshal{}, fmt.Errorf("failed to read snapshot of all keys from storage: %w", err)
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
			return JWKSMarshal{}, fmt.Errorf("failed to marshal key: %w", err)
		}
		jwks.Keys = append(jwks.Keys, marshal)
	}

	return jwks, nil
}
