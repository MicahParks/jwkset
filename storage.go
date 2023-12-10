package jwkset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"
)

var (
	// ErrKeyNotFound is returned by a Storage implementation when a key is not found.
	ErrKeyNotFound = errors.New("key not found")
	// ErrInvalidHTTPStatusCode is returned when the HTTP status code is invalid.
	ErrInvalidHTTPStatusCode = errors.New("invalid HTTP status code")
)

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

// HTTPClientStorageOptions are used to configure the behavior of NewMemoryStorageFromHTTP.
type HTTPClientStorageOptions struct {
	// Client is the HTTP client to use for requests.
	//
	// This defaults to http.DefaultClient.
	Client *http.Client

	// Ctx is used when performing HTTP requests. It is also used to end the refresh goroutine when it's no longer
	// needed.
	//
	// This defaults to context.Background().
	Ctx context.Context

	// HTTPExpectedStatus is the expected HTTP status code for the HTTP request.
	//
	// This defaults to http.StatusOK.
	HTTPExpectedStatus int

	// HTTPMethod is the HTTP method to use for the HTTP request.
	//
	// This defaults to http.MethodGet.
	HTTPMethod string

	// HTTPTimeout is the timeout for the HTTP request. When the Ctx option is also provided, this value is used for a
	// child context.
	//
	// This defaults to time.Minute.
	HTTPTimeout time.Duration

	// NoErrorReturnFirstHTTPReq will create the Storage without error if the first HTTP request fails.
	NoErrorReturnFirstHTTPReq bool

	// RefreshErrorHandler is a function that consumes errors that happen during an HTTP refresh. This is only effectual
	// if RefreshInterval is set.
	RefreshErrorHandler func(ctx context.Context, err error) // TODO Option to fail on HTTP creation?

	// RefreshInterval is the interval at which the HTTP URL is refreshed and the JWK Set is processed. This option will
	// launch a "refresh goroutine" to refresh the remote HTTP resource at the given interval.
	//
	// Provide the Ctx option to end the goroutine when it's no longer needed.
	RefreshInterval time.Duration
}

// NewMemoryStorageFromHTTP creates a new Storage implementation that processes a remote HTTP resource for a JWK Set. If
// the RefreshInterval option is not set, the remote HTTP resource will be requested and processed before returning. If
// the RefreshInterval option is set, a background goroutine will be launched to refresh the remote HTTP resource and
// not block the return of this function.
func NewMemoryStorageFromHTTP(u *url.URL, options HTTPClientStorageOptions) (Storage, error) {
	if options.Client == nil {
		options.Client = http.DefaultClient
	}
	if options.Ctx == nil {
		options.Ctx = context.Background()
	}
	if options.HTTPTimeout == 0 {
		options.HTTPTimeout = time.Minute
	}
	if options.HTTPMethod == "" {
		options.HTTPMethod = http.MethodGet
	}

	m := NewMemoryStorage()

	refresh := func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, options.HTTPMethod, u.String(), nil)
		if err != nil {
			return fmt.Errorf("failed to create HTTP request for JWK Set refresh: %w", err)
		}
		resp, err := options.Client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to perform HTTP request for JWK Set refresh: %w", err)
		}
		//goland:noinspection GoUnhandledErrorResult
		defer resp.Body.Close()
		if resp.StatusCode != options.HTTPExpectedStatus {
			return fmt.Errorf("%w: %d", ErrInvalidHTTPStatusCode, resp.StatusCode)
		}
		var jwks JWKSMarshal
		err = json.NewDecoder(resp.Body).Decode(&jwks)
		if err != nil {
			return fmt.Errorf("failed to decode JWK Set response: %w", err)
		}
		for _, marshal := range jwks.Keys {
			marshalOptions := JWKMarshalOptions{
				Private: true,
			}
			jwk, err := NewJWKFromMarshal(marshal, marshalOptions, JWKValidateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create JWK from JWK Marshal: %w", err)
			}
			err = m.WriteKey(options.Ctx, jwk)
			if err != nil {
				return fmt.Errorf("failed to write JWK to memory storage: %w", err)
			}
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(options.Ctx, options.HTTPTimeout)
	defer cancel()
	err := refresh(ctx)
	cancel()
	if err != nil && !options.NoErrorReturnFirstHTTPReq {
		return nil, fmt.Errorf("failed to perform first HTTP request for JWK Set: %w", err)
	}

	go func() { // Refresh goroutine.
		ticker := time.NewTicker(options.RefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-options.Ctx.Done():
				return
			case <-ticker.C:
				ctx, cancel = context.WithTimeout(options.Ctx, options.HTTPTimeout)
				err = refresh(ctx)
				cancel()
				if err != nil && options.RefreshErrorHandler != nil {
					options.RefreshErrorHandler(ctx, err)
				}
			}
		}
	}()

	return m, nil
}
