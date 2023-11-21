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

type storageError[CustomKeyMeta any] struct{}

func (s storageError[CustomKeyMeta]) DeleteKey(ctx context.Context, keyID string) (ok bool, err error) {
	return false, errStorage
}

func (s storageError[CustomKeyMeta]) ReadKey(ctx context.Context, keyID string) (jwkset.KeyWithMeta[CustomKeyMeta], error) {
	return jwkset.KeyWithMeta[CustomKeyMeta]{}, errStorage
}

func (s storageError[CustomKeyMeta]) SnapshotKeys(ctx context.Context) ([]jwkset.KeyWithMeta[CustomKeyMeta], error) {
	return nil, errStorage
}

func (s storageError[CustomKeyMeta]) WriteKey(ctx context.Context, meta jwkset.KeyWithMeta[CustomKeyMeta]) error {
	return errStorage
}

func TestStorageError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	jwks := jwkset.NewMemory[any]()
	jwks.Store = storageError[any]{}

	_, err := jwks.JSONPublic(ctx)
	if err == nil {
		t.Fatalf("Expected error, but got none.")
	}
}
