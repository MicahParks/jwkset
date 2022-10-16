package jwkset_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
)

var (
	errStorage = errors.New("storage error")
)

type storageError struct{}

func (s storageError) DeleteKey(ctx context.Context, keyID string) (ok bool, err error) {
	return false, errStorage
}

func (s storageError) ReadKey(ctx context.Context, keyID string) (jwkset.KeyWithMeta, error) {
	return jwkset.KeyWithMeta{}, errStorage
}

func (s storageError) SnapshotKeys(ctx context.Context) ([]jwkset.KeyWithMeta, error) {
	return nil, errStorage
}

func (s storageError) WriteKey(ctx context.Context, meta jwkset.KeyWithMeta) error {
	return errStorage
}

func TestStorageError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	jwks := jwkset.NewMemory()
	jwks.Store = storageError{}

	_, err := jwks.JSONPublic(ctx)
	if err == nil {
		t.Fatalf("Expected error, but got none.")
	}
}
