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
type Storage[CustomKeyMeta any] interface {
	// DeleteKey deletes a key from the storage. It will return ok as true if the key was present for deletion.
	DeleteKey(ctx context.Context, keyID string) (ok bool, err error)

	// ReadKey reads a key from the storage. If the key is not present, it returns ErrKeyNotFound. Any pointers returned
	// should be considered read-only.
	ReadKey(ctx context.Context, keyID string) (KeyWithMeta[CustomKeyMeta], error)

	// SnapshotKeys reads a snapshot of all keys from storage. As with ReadKey, any pointers returned should be
	// considered read-only.
	SnapshotKeys(ctx context.Context) ([]KeyWithMeta[CustomKeyMeta], error)

	// WriteKey writes a key to the storage. If the key already exists, it will be overwritten. After writing a key,
	// any pointers written should be considered owned by the underlying storage.
	WriteKey(ctx context.Context, meta KeyWithMeta[CustomKeyMeta]) error
}

var _ Storage[any] = &memoryJWKSet[any]{}

type memoryJWKSet[CustomKeyMeta any] struct {
	m   map[string]KeyWithMeta[CustomKeyMeta]
	mux sync.RWMutex
}

// NewMemoryStorage creates a new in-memory Storage implementation.
func NewMemoryStorage[CustomKeyMeta any]() Storage[CustomKeyMeta] {
	return &memoryJWKSet[CustomKeyMeta]{
		m: make(map[string]KeyWithMeta[CustomKeyMeta]),
	}
}

func (m *memoryJWKSet[CustomKeyMeta]) SnapshotKeys(ctx context.Context) ([]KeyWithMeta[CustomKeyMeta], error) {
	m.mux.RLock()
	defer m.mux.RUnlock()
	cpy := make([]KeyWithMeta[CustomKeyMeta], len(m.m))
	i := 0
	for _, meta := range m.m {
		cpy[i] = meta
		i++
	}
	return cpy, nil
}

func (m *memoryJWKSet[CustomKeyMeta]) DeleteKey(ctx context.Context, keyID string) (ok bool, err error) {
	m.mux.Lock()
	defer m.mux.Unlock()
	_, ok = m.m[keyID]
	delete(m.m, keyID)
	return ok, nil
}

func (m *memoryJWKSet[CustomKeyMeta]) ReadKey(ctx context.Context, keyID string) (KeyWithMeta[CustomKeyMeta], error) {
	m.mux.RLock()
	defer m.mux.RUnlock()
	meta, ok := m.m[keyID]
	if !ok {
		return meta, fmt.Errorf("%s: %w", keyID, ErrKeyNotFound)
	}
	return meta, nil
}

func (m *memoryJWKSet[CustomKeyMeta]) WriteKey(ctx context.Context, meta KeyWithMeta[CustomKeyMeta]) error {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.m[meta.KeyID] = meta
	return nil
}
