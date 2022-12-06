package jwkset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// KeyWithMeta is holds a Key and its metadata.
type KeyWithMeta[CustomKeyMeta any] struct {
	ALG    ALG
	Custom CustomKeyMeta
	Key    interface{}
	KeyID  string
}

// NewKey creates a new KeyWithMeta.
func NewKey[CustomKeyMeta any](key interface{}, keyID string) KeyWithMeta[CustomKeyMeta] {
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
	return j.JSONWithOptions(ctx, KeyMarshalOptions{})
}

// JSONPrivate creates the JSON representation of the JWKSet public and private key material.
func (j JWKSet[CustomKeyMeta]) JSONPrivate(ctx context.Context) (json.RawMessage, error) {
	options := KeyMarshalOptions{
		AsymmetricPrivate: true,
		Symmetric:         true,
	}
	return j.JSONWithOptions(ctx, options)
}

// JSONWithOptions creates the JSON representation of the JWKSet with the given options.
func (j JWKSet[CustomKeyMeta]) JSONWithOptions(ctx context.Context, options KeyMarshalOptions) (json.RawMessage, error) {
	jwks := JWKSMarshal{}

	keys, err := j.Store.SnapshotKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot of all keys from storage: %w", err)
	}

	for _, meta := range keys {
		jwk, err := KeyMarshal(meta, options)
		if err != nil {
			if errors.Is(err, ErrUnsupportedKeyType) {
				// Ignore the key.
				continue
			}
			return nil, fmt.Errorf("failed to marshal key: %w", err)
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}

	return json.Marshal(jwks)
}
