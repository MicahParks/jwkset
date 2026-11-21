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
	// KeyDelete deletes a key from the storage. It will return ok as true if the key was present for deletion.
	KeyDelete(ctx context.Context, keyID string) (ok bool, err error)
	// KeyRead reads a key from the storage. If the key is not present, it returns ErrKeyNotFound. Any pointers returned
	// should be considered read-only.
	KeyRead(ctx context.Context, keyID string) (JWK, error)
	// KeyReadAll reads a snapshot of all keys from storage. As with ReadKey, any pointers returned should be
	// considered read-only.
	KeyReadAll(ctx context.Context) ([]JWK, error)
	// KeyReplaceAll replaces all the keys in storage. All existing keys will be deleted and replaced with the given.
	KeyReplaceAll(ctx context.Context, given []JWK) error
	// KeyWrite writes a key to the storage. If the key already exists, it will be overwritten. After writing a key,
	// any pointers written should be considered owned by the underlying storage.
	KeyWrite(ctx context.Context, jwk JWK) error

	// JSON creates the JSON representation of the JWKSet.
	JSON(ctx context.Context) (json.RawMessage, error)
	// JSONPublic creates the JSON representation of the public keys in JWKSet.
	JSONPublic(ctx context.Context) (json.RawMessage, error)
	// JSONPrivate creates the JSON representation of the JWKSet public and private key material.
	JSONPrivate(ctx context.Context) (json.RawMessage, error)
	// JSONWithOptions creates the JSON representation of the JWKSet with the given options. These options override whatever
	// options are set on the individual JWKs.
	JSONWithOptions(ctx context.Context, marshalOptions JWKMarshalOptions, validationOptions JWKValidateOptions) (json.RawMessage, error)
	// Marshal transforms the JWK Set's current state into a Go type that can be marshaled into JSON.
	Marshal(ctx context.Context) (JWKSMarshal, error)
	// MarshalWithOptions transforms the JWK Set's current state into a Go type that can be marshaled into JSON with the
	// given options. These options override whatever options are set on the individual JWKs.
	MarshalWithOptions(ctx context.Context, marshalOptions JWKMarshalOptions, validationOptions JWKValidateOptions) (JWKSMarshal, error)
}

// RefreshableStorage is a Storage that can be refreshed.
type RefreshableStorage interface {
	Storage
	Refresh(ctx context.Context) error
}

var _ Storage = &MemoryJWKSet{}

type MemoryJWKSet struct {
	set []JWK
	mux sync.RWMutex
}

// NewMemoryStorage creates a new in-memory Storage implementation.
func NewMemoryStorage() *MemoryJWKSet {
	return &MemoryJWKSet{}
}

func (m *MemoryJWKSet) KeyDelete(_ context.Context, keyID string) (ok bool, err error) {
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
func (m *MemoryJWKSet) KeyRead(_ context.Context, keyID string) (JWK, error) {
	m.mux.RLock()
	defer m.mux.RUnlock()
	for _, jwk := range m.set {
		if jwk.Marshal().KID == keyID {
			return jwk, nil
		}
	}
	return JWK{}, fmt.Errorf("%w: kid %q", ErrKeyNotFound, keyID)
}
func (m *MemoryJWKSet) KeyReadAll(_ context.Context) ([]JWK, error) {
	m.mux.RLock()
	defer m.mux.RUnlock()
	return slices.Clone(m.set), nil
}
func (m *MemoryJWKSet) KeyReplaceAll(_ context.Context, given []JWK) error {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.set = given
	return nil
}
func (m *MemoryJWKSet) KeyWrite(_ context.Context, jwk JWK) error {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.set = append(m.set, jwk)
	return nil
}
func (m *MemoryJWKSet) JSON(ctx context.Context) (json.RawMessage, error) {
	jwks, err := m.Marshal(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK Set: %w", err)
	}
	return json.Marshal(jwks)
}
func (m *MemoryJWKSet) JSONPublic(ctx context.Context) (json.RawMessage, error) {
	return m.JSONWithOptions(ctx, JWKMarshalOptions{}, JWKValidateOptions{})
}
func (m *MemoryJWKSet) JSONPrivate(ctx context.Context) (json.RawMessage, error) {
	marshalOptions := JWKMarshalOptions{
		Private: true,
	}
	return m.JSONWithOptions(ctx, marshalOptions, JWKValidateOptions{})
}
func (m *MemoryJWKSet) JSONWithOptions(ctx context.Context, marshalOptions JWKMarshalOptions, validationOptions JWKValidateOptions) (json.RawMessage, error) {
	jwks, err := m.MarshalWithOptions(ctx, marshalOptions, validationOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK Set with options: %w", err)
	}
	return json.Marshal(jwks)
}
func (m *MemoryJWKSet) Marshal(ctx context.Context) (JWKSMarshal, error) {
	keys, err := m.KeyReadAll(ctx)
	if err != nil {
		return JWKSMarshal{}, fmt.Errorf("failed to read snapshot of all keys from storage: %w", err)
	}
	jwks := JWKSMarshal{}
	for _, key := range keys {
		jwks.Keys = append(jwks.Keys, key.Marshal())
	}
	return jwks, nil
}
func (m *MemoryJWKSet) MarshalWithOptions(ctx context.Context, marshalOptions JWKMarshalOptions, validationOptions JWKValidateOptions) (JWKSMarshal, error) {
	jwks := JWKSMarshal{}

	keys, err := m.KeyReadAll(ctx)
	if err != nil {
		return JWKSMarshal{}, fmt.Errorf("failed to read snapshot of all keys from storage: %w", err)
	}

	for _, key := range keys {
		options := key.options
		options.Marshal = marshalOptions
		options.Validate = validationOptions
		marshal, err := keyMarshal(key.Key(), options)
		if err != nil {
			if errors.Is(err, ErrOptions) {
				continue
			}
			return JWKSMarshal{}, fmt.Errorf("failed to marshal key: %w", err)
		}
		jwks.Keys = append(jwks.Keys, marshal)
	}

	return jwks, nil
}

// HTTPClientStorageOptions are used to configure the behavior of NewStorageFromHTTP.
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
	//
	// If NoErrorReturnFirstHTTPReq is set, this function will be called when if the first HTTP request fails.
	RefreshErrorHandler func(ctx context.Context, err error)

	// RefreshInterval is the interval at which the HTTP URL is refreshed and the JWK Set is processed. This option will
	// launch a "refresh goroutine" to refresh the remote HTTP resource at the given interval.
	//
	// Provide the Ctx option to end the goroutine when it's no longer needed.
	RefreshInterval time.Duration

	// RequireSupportedKeys will refuse to process a JWK Set if it contains an unsupported key. If false, unsupported
	// keys, like Ed448, will be ignored.
	RequireSupportedKeys bool

	// Storage is the underlying storage implementation to use.
	//
	// This defaults to NewMemoryStorage().
	Storage Storage

	// ValidateOptions are the options to use when validating the JWKs.
	ValidateOptions JWKValidateOptions

	// RemoteJWKSetURL is the URL of the remote JWK Set.
	RemoteJWKSetURL string
}

type httpStorage struct {
	options HTTPClientStorageOptions
	Storage
}

// NewStorageFromHTTP creates a new Storage implementation that processes a remote HTTP resource for a JWK Set. If
// the RefreshInterval option is not set, the remote HTTP resource will be requested and processed before returning. If
// the RefreshInterval option is set, a background goroutine will be launched to refresh the remote HTTP resource and
// not block the return of this function.
func NewStorageFromHTTP(remoteJWKSetURL string, options HTTPClientStorageOptions) (Storage, error) {
	if options.Client == nil {
		options.Client = http.DefaultClient
	}
	if options.Ctx == nil {
		options.Ctx = context.Background()
	}
	if options.HTTPExpectedStatus == 0 {
		options.HTTPExpectedStatus = http.StatusOK
	}
	if options.HTTPTimeout == 0 {
		options.HTTPTimeout = time.Minute
	}
	if options.HTTPMethod == "" {
		options.HTTPMethod = http.MethodGet
	}
	if options.RemoteJWKSetURL == "" {
		options.RemoteJWKSetURL = remoteJWKSetURL
	}
	store := options.Storage
	if store == nil {
		store = NewMemoryStorage()
	}
	_, err := url.ParseRequestURI(options.RemoteJWKSetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse given URL %q: %w", options.RemoteJWKSetURL, err)
	}
	s := httpStorage{
		options: options,
		Storage: store,
	}

	if options.RefreshInterval != 0 {
		go func() { // Refresh goroutine.
			ticker := time.NewTicker(options.RefreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-options.Ctx.Done():
					return
				case <-ticker.C:
					ctx, cancel := context.WithTimeout(options.Ctx, options.HTTPTimeout)
					err := s.Refresh(ctx)
					cancel()
					if err != nil && options.RefreshErrorHandler != nil {
						options.RefreshErrorHandler(ctx, err)
					}
				}
			}
		}()
	}

	ctx, cancel := context.WithTimeout(options.Ctx, options.HTTPTimeout)
	defer cancel()
	err = s.Refresh(ctx)
	cancel()
	if err != nil {
		if options.NoErrorReturnFirstHTTPReq {
			if options.RefreshErrorHandler != nil {
				options.RefreshErrorHandler(ctx, err)
			}
			return s, nil
		}
		return nil, fmt.Errorf("failed to perform first HTTP request for JWK Set: %w", err)
	}

	return s, nil
}

func (s *httpStorage) Refresh(ctx context.Context) error {
	err := s.refresh(ctx)
	if err != nil && s.options.RefreshErrorHandler != nil {
		s.options.RefreshErrorHandler(ctx, err)
		return nil
	}
	return err
}

func (s *httpStorage) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, s.options.HTTPMethod, s.options.RemoteJWKSetURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request for JWK Set refresh: %w", err)
	}
	resp, err := s.options.Client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform HTTP request for JWK Set refresh: %w", err)
	}
	//goland:noinspection GoUnhandledErrorResult
	defer resp.Body.Close()
	if resp.StatusCode != s.options.HTTPExpectedStatus {
		return fmt.Errorf("%w: %d", ErrInvalidHTTPStatusCode, resp.StatusCode)
	}
	var jwks JWKSMarshal
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return fmt.Errorf("failed to decode JWK Set response: %w", err)
	}
	newSet := make([]JWK, 0)
	for _, marshal := range jwks.Keys {
		marshalOptions := JWKMarshalOptions{
			Private: true,
		}
		jwk, err := NewJWKFromMarshal(marshal, marshalOptions, s.options.ValidateOptions)
		switch {
		case !s.options.RequireSupportedKeys && errors.Is(err, ErrUnsupportedKey):
			continue
		case err != nil:
			return fmt.Errorf("failed to create JWK from JWK Marshal: %w", err)
		}
		newSet = append(newSet, jwk)
	}
	err = s.Storage.KeyReplaceAll(ctx, newSet) // Clear local cache in case of key revocation.
	if err != nil {
		return fmt.Errorf("failed to delete all keys from storage: %w", err)
	}
	return nil
}

type CustomStorageOptions struct {
	// Ctx is used when performing requests. It is also used to end the refresh goroutine when it's no longer
	// needed.
	//
	// This defaults to context.Background().
	Ctx context.Context

	// NoErrorReturnFirstReq will create the Storage without error if the first request fails.
	NoErrorReturnFirstReq bool

	// RefreshErrorHandler is a function that consumes errors that happen during a refresh. This is only effectual
	// if RefreshInterval is set.
	//
	// If NoErrorReturnFirstReq is set, this function will be called when if the first request fails.
	RefreshErrorHandler func(ctx context.Context, err error)

	// RefreshInterval is the interval at which the request is refreshed and the JWK Set is processed. This option will
	// launch a "refresh goroutine" to refresh the request at the given interval.
	//
	// Provide the Ctx option to end the goroutine when it's no longer needed.
	RefreshInterval time.Duration

	// RequireSupportedKeys will refuse to process a JWK Set if it contains an unsupported key. If false, unsupported
	// keys, like Ed448, will be ignored.
	RequireSupportedKeys bool

	// Storage is the underlying storage implementation to use.
	//
	// This defaults to NewMemoryStorage().
	Storage Storage

	// ValidateOptions are the options to use when validating the JWKs.
	ValidateOptions JWKValidateOptions

	// RequestJWKSetFunc is a function that requests the JWK Set from the remote resource.
	RequestJWKSetFunc func(ctx context.Context) (JWKSMarshal, error)

	// RequestJWKSetTimeout is the timeout for the request to the JWK Set.
	RequestJWKSetTimeout time.Duration
}

type customStorage struct {
	options CustomStorageOptions
	Storage
}

func NewCustomStorage(options CustomStorageOptions) (Storage, error) {
	if options.Ctx == nil {
		options.Ctx = context.Background()
	}
	if options.RequestJWKSetTimeout == 0 {
		options.RequestJWKSetTimeout = time.Minute
	}
	store := options.Storage
	if store == nil {
		store = NewMemoryStorage()
	}
	if options.RequestJWKSetFunc == nil {
		return nil, fmt.Errorf("request JWK Set func is required")
	}
	s := customStorage{
		options: options,
		Storage: store,
	}

	if options.RefreshInterval != 0 {
		go func() { // Refresh goroutine.
			ticker := time.NewTicker(options.RefreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-options.Ctx.Done():
					return
				case <-ticker.C:
					ctx, cancel := context.WithTimeout(options.Ctx, options.RequestJWKSetTimeout)
					err := s.Refresh(ctx)
					cancel()
					if err != nil && options.RefreshErrorHandler != nil {
						options.RefreshErrorHandler(ctx, err)
					}
				}
			}
		}()
	}

	ctx, cancel := context.WithTimeout(options.Ctx, options.RequestJWKSetTimeout)
	defer cancel()
	err := s.Refresh(ctx)
	cancel()
	if err != nil {
		if options.NoErrorReturnFirstReq {
			if options.RefreshErrorHandler != nil {
				options.RefreshErrorHandler(ctx, err)
			}
			return s, nil
		}
		return nil, fmt.Errorf("failed to perform first request for JWK Set: %w", err)
	}

	return s, nil
}

func (s *customStorage) Refresh(ctx context.Context) error {
	err := s.refresh(ctx)
	if err != nil && s.options.RefreshErrorHandler != nil {
		s.options.RefreshErrorHandler(ctx, err)
		return nil
	}
	return err
}

func (s *customStorage) refresh(ctx context.Context) error {
	jwks, err := s.options.RequestJWKSetFunc(ctx)
	if err != nil {
		return fmt.Errorf("failed to get JWK Set: %w", err)
	}
	newSet := make([]JWK, 0)
	for _, marshal := range jwks.Keys {
		marshalOptions := JWKMarshalOptions{
			Private: true,
		}
		jwk, err := NewJWKFromMarshal(marshal, marshalOptions, s.options.ValidateOptions)
		switch {
		case !s.options.RequireSupportedKeys && errors.Is(err, ErrUnsupportedKey):
			continue
		case err != nil:
			return fmt.Errorf("failed to create JWK from JWK Marshal: %w", err)
		}
		newSet = append(newSet, jwk)
	}
	err = s.Storage.KeyReplaceAll(ctx, newSet) // Clear local cache in case of key revocation.
	if err != nil {
		return fmt.Errorf("failed to delete all keys from storage: %w", err)
	}
	return nil
}
