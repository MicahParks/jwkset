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

func (s storageError) DeleteKey(_ context.Context, _ string) (ok bool, err error) {
	return false, errStorage
}
func (s storageError) ReadKey(_ context.Context, _ string) (jwkset.JWK, error) {
	return jwkset.JWK{}, errStorage
}
func (s storageError) SnapshotKeys(_ context.Context) ([]jwkset.JWK, error) {
	return nil, errStorage
}
func (s storageError) WriteKey(_ context.Context, _ jwkset.JWK) error {
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
