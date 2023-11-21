package jwkset_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
)

const (
	kidMissing  = "kid missing"
	kidWritten  = "kid written"
	kidWritten2 = "kid written 2"
)

var (
	hmacKey1 = []byte("hamc Key 1")
	hmacKey2 = []byte("hamc Key 2")
)

type storageTestParams[CustomKeyMeta any] struct {
	ctx    context.Context
	cancel context.CancelFunc
	jwks   jwkset.JWKSet[CustomKeyMeta]
}

func TestMemoryDeleteKey(t *testing.T) {
	params := setupMemory[any]()
	defer params.cancel()
	store := params.jwks.Store

	err := store.WriteKey(params.ctx, jwkset.NewKey[any](hmacKey1, kidWritten))
	if err != nil {
		t.Fatalf("Failed to write Key. %s", err)
	}

	ok, err := store.DeleteKey(params.ctx, kidMissing)
	if err != nil {
		t.Fatalf("Failed to delete missing Key. %s", err)
	}
	if ok {
		t.Fatalf("Deleted missing Key.")
	}

	ok, err = store.DeleteKey(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to delete written Key. %s", err)
	}
	if !ok {
		t.Fatalf("Failed to delete written Key.")
	}
}

func TestMemoryReadKey(t *testing.T) {
	params := setupMemory[any]()
	defer params.cancel()
	store := params.jwks.Store

	err := store.WriteKey(params.ctx, jwkset.NewKey[any](hmacKey1, kidWritten))
	if err != nil {
		t.Fatalf("Failed to write Key. %s", err)
	}

	_, err = store.ReadKey(params.ctx, kidMissing)
	if !errors.Is(err, jwkset.ErrKeyNotFound) {
		t.Fatalf("Should have specific error when reading missing Key.\n  Actual: %s\n  Expected: %s", err, jwkset.ErrKeyNotFound)
	}

	key, err := store.ReadKey(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to read written Key. %s", err)
	}

	if !bytes.Equal(key.key.([]byte), hmacKey1) {
		t.Fatalf("Read Key does not match written Key.")
	}

	err = store.WriteKey(params.ctx, jwkset.NewKey[any](hmacKey2, kidWritten))
	if err != nil {
		t.Fatalf("Failed to overwrite Key. %s", err)
	}

	key, err = store.ReadKey(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to read written Key. %s", err)
	}

	if !bytes.Equal(key.key.([]byte), hmacKey2) {
		t.Fatalf("Read Key does not match written Key.")
	}

	_, err = store.DeleteKey(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to delete written Key. %s", err)
	}

	_, err = store.ReadKey(params.ctx, kidWritten)
	if !errors.Is(err, jwkset.ErrKeyNotFound) {
		t.Fatalf("Should have specific error when reading missing Key.\n  Actual: %s\n  Expected: %s", err, jwkset.ErrKeyNotFound)
	}
}

func TestMemorySnapshotKeys(t *testing.T) {
	params := setupMemory[any]()
	defer params.cancel()
	store := params.jwks.Store

	err := store.WriteKey(params.ctx, jwkset.NewKey[any](hmacKey1, kidWritten))
	if err != nil {
		t.Fatalf("Failed to write Key 1. %s", err)
	}

	err = store.WriteKey(params.ctx, jwkset.NewKey[any](hmacKey2, kidWritten2))
	if err != nil {
		t.Fatalf("Failed to write Key 2. %s", err)
	}

	meta, err := store.SnapshotKeys(params.ctx)
	if err != nil {
		t.Fatalf("Failed to snapshot keys. %s", err)
	}
	if len(meta) != 2 {
		t.Fatalf("Snapshot should have 2 keys. %d", len(meta))
	}

	kid1Found := false
	kid2Found := false
	for _, m := range meta {
		if !kid1Found && m.KeyID == kidWritten {
			kid1Found = true
			if !bytes.Equal(m.key.([]byte), hmacKey1) {
				t.Fatalf("Snapshot Key does not match written Key.")
			}
		} else if !kid2Found && m.KeyID == kidWritten2 {
			kid2Found = true
			if !bytes.Equal(m.key.([]byte), hmacKey2) {
				t.Fatalf("Snapshot Key does not match written Key.")
			}
		} else {
			t.Fatalf("Snapshot Key has unexpected Key ID.")
		}
	}
}

func TestMemoryWriteKey(t *testing.T) {
	params := setupMemory[any]()
	defer params.cancel()
	store := params.jwks.Store

	err := store.WriteKey(params.ctx, jwkset.NewKey[any](hmacKey1, kidWritten))
	if err != nil {
		t.Fatalf("Failed to write Key. %s", err)
	}

	err = store.WriteKey(params.ctx, jwkset.NewKey[any](hmacKey2, kidWritten))
	if err != nil {
		t.Fatalf("Failed to overwrite Key. %s", err)
	}
}

func setupMemory[CustomKeyMeta any]() (params storageTestParams[CustomKeyMeta]) {
	jwkSet := jwkset.NewMemory[CustomKeyMeta]()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	params = storageTestParams[CustomKeyMeta]{
		ctx:    ctx,
		cancel: cancel,
		jwks:   jwkSet,
	}
	return params
}
