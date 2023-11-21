package jwkset

import (
	"context"
	"errors"
	"fmt"
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
	WriteKey(ctx context.Context, k JWK) error
}

var _ Storage = &memoryJWKSet{}

type memoryJWKSet struct {
	m   map[string]JWK
	mux sync.RWMutex
}

// NewMemoryStorage creates a new in-memory Storage implementation.
func NewMemoryStorage() Storage {
	return &memoryJWKSet{
		m: make(map[string]JWK),
	}
}

func (m *memoryJWKSet) SnapshotKeys(_ context.Context) ([]JWK, error) {
	m.mux.RLock()
	defer m.mux.RUnlock()
	cpy := make([]JWK, len(m.m))
	i := 0
	for _, k := range m.m {
		cpy[i] = k
		i++
	}
	return cpy, nil
}
func (m *memoryJWKSet) DeleteKey(_ context.Context, keyID string) (ok bool, err error) {
	m.mux.Lock()
	defer m.mux.Unlock()
	_, ok = m.m[keyID]
	delete(m.m, keyID)
	return ok, nil
}
func (m *memoryJWKSet) ReadKey(_ context.Context, keyID string) (JWK, error) {
	m.mux.RLock()
	defer m.mux.RUnlock()
	k, ok := m.m[keyID]
	if !ok {
		return k, fmt.Errorf("%s: %w", keyID, ErrKeyNotFound)
	}
	return k, nil
}
func (m *memoryJWKSet) WriteKey(_ context.Context, k JWK) error {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.m[k.Marshal().KID] = k
	return nil
}
