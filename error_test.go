package jwkset

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

var (
	errStorage = errors.New("storage error")
)

type storageError struct{}

func (s storageError) KeyDelete(_ context.Context, _ string) (ok bool, err error) {
	return false, errStorage
}
func (s storageError) KeyRead(_ context.Context, _ string) (JWK, error) {
	return JWK{}, errStorage
}
func (s storageError) KeyReadAll(_ context.Context) ([]JWK, error) {
	return nil, errStorage
}
func (s storageError) KeyWrite(_ context.Context, _ JWK) error {
	return errStorage
}

func (s storageError) JSON(_ context.Context) (json.RawMessage, error) {
	return nil, errStorage
}
func (s storageError) JSONPublic(_ context.Context) (json.RawMessage, error) {
	return nil, errStorage
}
func (s storageError) JSONPrivate(_ context.Context) (json.RawMessage, error) {
	return nil, errStorage
}
func (s storageError) JSONWithOptions(_ context.Context, _ JWKMarshalOptions, _ JWKValidateOptions) (json.RawMessage, error) {
	return nil, errStorage
}
func (s storageError) Marshal(_ context.Context) (JWKSMarshal, error) {
	return JWKSMarshal{}, errStorage
}
func (s storageError) MarshalWithOptions(_ context.Context, _ JWKMarshalOptions, _ JWKValidateOptions) (JWKSMarshal, error) {
	return JWKSMarshal{}, errStorage
}

func TestStorageError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	jwks := storageError{}

	_, err := jwks.JSONPublic(ctx)
	if err == nil {
		t.Fatalf("Expected error, but got none.")
	}
}
