package jwkset

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
)

// ErrKeyNotFound is returned by a Storage implementation when a key is not found.
var ErrKeyNotFound = errors.New("key not found")

// Storage handles storage operations for a JWKSet.
type Storage interface {
	// DeleteKey deletes a key from the storage. It will return ok as true if the key was present for deletion.
	DeleteKey(ctx context.Context, keyID string) (ok bool, err error)

	// ReadKey reads a key from the storage. If the key is not present, it returns ErrKeyNotFound. Any pointers returned
	// should be considered read-only.
	ReadKey(ctx context.Context, keyID string) (JWK, error)

	// SnapshotKeys reads a snapshot of all keys from storage. As with ReadKey, any pointers returned should be
	// considered read-only.
	SnapshotKeys(ctx context.Context) ([]JWK, error)

	// WriteKey writes a key to the storage. If the key already exists, it will be overwritten. After writing a key,
	// any pointers written should be considered owned by the underlying storage.
	WriteKey(ctx context.Context, jwk JWK) error
}

var _ Storage = &memoryJWKSet{}

type memoryJWKSet struct {
	set []JWK
	mux sync.RWMutex
}

// NewMemoryStorage creates a new in-memory Storage implementation.
func NewMemoryStorage() Storage {
	return &memoryJWKSet{}
}

func (m *memoryJWKSet) SnapshotKeys(_ context.Context) ([]JWK, error) {
	m.mux.RLock()
	defer m.mux.RUnlock()
	return slices.Clone(m.set), nil
}
func (m *memoryJWKSet) DeleteKey(_ context.Context, keyID string) (ok bool, err error) {
	m.mux.Lock()
	defer m.mux.Unlock()
	for i, jwk := range m.set {
		if jwk.Marshal().KID == keyID {
			m.set = append(m.set[:i], m.set[i+1:]...)
			return true, nil
		}
	}
	return ok, nil
}
func (m *memoryJWKSet) ReadKey(_ context.Context, keyID string) (JWK, error) {
	m.mux.RLock()
	defer m.mux.RUnlock()
	for _, jwk := range m.set {
		if jwk.Marshal().KID == keyID {
			return jwk, nil
		}
	}
	return JWK{}, fmt.Errorf("%w: kid %q", ErrKeyNotFound, keyID)
}
func (m *memoryJWKSet) WriteKey(_ context.Context, jwk JWK) error {
	m.mux.Lock()
	defer m.mux.Unlock()
	for i, j := range m.set {
		if j.Marshal().KID == jwk.Marshal().KID {
			m.set[i] = jwk
			return nil
		}
	}
	m.set = append(m.set, jwk)
	return nil
}
