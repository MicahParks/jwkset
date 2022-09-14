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
	hmacKey1 = []byte("hamc key 1")
	hmacKey2 = []byte("hamc key 2")
)

type storageTestParams struct {
	ctx    context.Context
	cancel context.CancelFunc
	jwks   jwkset.JWKSet
}

func TestMemoryDeleteKey(t *testing.T) {
	params := setupMemory()
	defer params.cancel()
	store := params.jwks.Store

	err := store.WriteKey(params.ctx, jwkset.NewKey(hmacKey1, kidWritten))
	if err != nil {
		t.Fatalf("Failed to write key. %s", err)
	}

	ok, err := store.DeleteKey(params.ctx, kidMissing)
	if err != nil {
		t.Fatalf("Failed to delete missing key. %s", err)
	}
	if ok {
		t.Fatalf("Deleted missing key.")
	}

	ok, err = store.DeleteKey(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to delete written key. %s", err)
	}
	if !ok {
		t.Fatalf("Failed to delete written key.")
	}
}

func TestMemoryReadKey(t *testing.T) {
	params := setupMemory()
	defer params.cancel()
	store := params.jwks.Store

	err := store.WriteKey(params.ctx, jwkset.NewKey(hmacKey1, kidWritten))
	if err != nil {
		t.Fatalf("Failed to write key. %s", err)
	}

	_, err = store.ReadKey(params.ctx, kidMissing)
	if !errors.Is(err, jwkset.ErrKeyNotFound) {
		t.Fatalf("Should have specific error when reading missing key.\n  Actual: %s\n  Expected: %s", err, jwkset.ErrKeyNotFound)
	}

	key, err := store.ReadKey(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to read written key. %s", err)
	}

	if !bytes.Equal(key.Key.([]byte), hmacKey1) {
		t.Fatalf("Read key does not match written key.")
	}

	err = store.WriteKey(params.ctx, jwkset.NewKey(hmacKey2, kidWritten))
	if err != nil {
		t.Fatalf("Failed to overwrite key. %s", err)
	}

	key, err = store.ReadKey(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to read written key. %s", err)
	}

	if !bytes.Equal(key.Key.([]byte), hmacKey2) {
		t.Fatalf("Read key does not match written key.")
	}

	_, err = store.DeleteKey(params.ctx, kidWritten)
	if err != nil {
		t.Fatalf("Failed to delete written key. %s", err)
	}

	_, err = store.ReadKey(params.ctx, kidWritten)
	if !errors.Is(err, jwkset.ErrKeyNotFound) {
		t.Fatalf("Should have specific error when reading missing key.\n  Actual: %s\n  Expected: %s", err, jwkset.ErrKeyNotFound)
	}
}

func TestMemorySnapshotKeys(t *testing.T) {
	params := setupMemory()
	defer params.cancel()
	store := params.jwks.Store

	err := store.WriteKey(params.ctx, jwkset.NewKey(hmacKey1, kidWritten))
	if err != nil {
		t.Fatalf("Failed to write key 1. %s", err)
	}

	err = store.WriteKey(params.ctx, jwkset.NewKey(hmacKey2, kidWritten2))
	if err != nil {
		t.Fatalf("Failed to write key 2. %s", err)
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
			if !bytes.Equal(m.Key.([]byte), hmacKey1) {
				t.Fatalf("Snapshot key does not match written key.")
			}
		} else if !kid2Found && m.KeyID == kidWritten2 {
			kid2Found = true
			if !bytes.Equal(m.Key.([]byte), hmacKey2) {
				t.Fatalf("Snapshot key does not match written key.")
			}
		} else {
			t.Fatalf("Snapshot key has unexpected key ID.")
		}
	}
}

func TestMemoryWriteKey(t *testing.T) {
	params := setupMemory()
	defer params.cancel()
	store := params.jwks.Store

	err := store.WriteKey(params.ctx, jwkset.NewKey(hmacKey1, kidWritten))
	if err != nil {
		t.Fatalf("Failed to write key. %s", err)
	}

	err = store.WriteKey(params.ctx, jwkset.NewKey(hmacKey2, kidWritten))
	if err != nil {
		t.Fatalf("Failed to overwrite key. %s", err)
	}
}

func setupMemory() (params storageTestParams) {
	jwkSet := jwkset.NewMemory()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	params = storageTestParams{
		ctx:    ctx,
		cancel: cancel,
		jwks:   jwkSet,
	}
	return params
}
