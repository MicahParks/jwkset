package jwkset_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
)

var (
	errStorage = errors.New("storage error")
)

type storageError struct{}

func (s storageError) KeyDelete(_ context.Context, _ string) (ok bool, err error) {
	return false, errStorage
}
func (s storageError) KeyRead(_ context.Context, _ string) (jwkset.JWK, error) {
	return jwkset.JWK{}, errStorage
}
func (s storageError) KeyReadAll(_ context.Context) ([]jwkset.JWK, error) {
	return nil, errStorage
}
func (s storageError) KeyWrite(_ context.Context, _ jwkset.JWK) error {
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
func (s storageError) JSONWithOptions(_ context.Context, _ jwkset.JWKMarshalOptions, _ jwkset.JWKValidateOptions) (json.RawMessage, error) {
	return nil, errStorage
}
func (s storageError) Marshal(_ context.Context) (jwkset.JWKSMarshal, error) {
	return jwkset.JWKSMarshal{}, errStorage
}
func (s storageError) MarshalWithOptions(_ context.Context, _ jwkset.JWKMarshalOptions, _ jwkset.JWKValidateOptions) (jwkset.JWKSMarshal, error) {
	return jwkset.JWKSMarshal{}, errStorage
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
