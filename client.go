package jwkset

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"
)

var (
	// ErrNewClient fails to create a new JWK Set client.
	ErrNewClient = errors.New("failed to create new JWK Set client")
)

type ClientOptions struct {
	// Given contains keys known from outside HTTP URLs.
	Given Storage
	// HTTPURLs are a mapping of HTTP URLs to JWK Set endpoints to storage implementations for the keys located at the
	// URL. If empty, HTTP will not be used.
	HTTPURLs map[string]Storage
	// PrioritizeHTTP is a flag that indicates whether keys from the HTTP URL should be prioritized over keys from the
	// given storage.
	PrioritizeHTTP bool
}

// Client is a JWK Set client.
type Client struct {
	given          Storage
	httpURLs       map[string]Storage
	prioritizeHTTP bool
}

// NewClient creates a new JWK Set client.
func NewClient(options ClientOptions) (Client, error) {
	if options.Given == nil && len(options.HTTPURLs) == 0 {
		return Client{}, fmt.Errorf("%w: no given keys or HTTP URLs", ErrNewClient)
	}
	for u, store := range options.HTTPURLs {
		if store == nil {
			options.HTTPURLs[u] = NewMemoryStorage()
		}
	}
	c := Client{
		given:          options.Given,
		httpURLs:       options.HTTPURLs,
		prioritizeHTTP: options.PrioritizeHTTP,
	}
	return c, nil
}

// NewDefaultClient creates a new JWK Set client with default options.
func NewDefaultClient(urls []string) (Client, error) {
	clientOptions := ClientOptions{
		HTTPURLs: make(map[string]Storage),
	}
	for _, u := range urls {
		parsed, err := url.ParseRequestURI(u)
		if err != nil {
			return Client{}, fmt.Errorf("failed to parse given URL %q: %w", u, errors.Join(err, ErrNewClient))
		}
		u = parsed.String()
		refreshErrorHandler := func(ctx context.Context, err error) {
			slog.Default().ErrorContext(ctx, "Failed to refresh HTTP JWK Set from remote HTTP resource.",
				"error", err,
				"url", u,
			)
		}
		options := HTTPClientStorageOptions{
			NoErrorReturnFirstHTTPReq: true,
			RefreshErrorHandler:       refreshErrorHandler,
			RefreshInterval:           time.Hour,
		}
		c, err := NewHTTPClientStorage(parsed, options)
		if err != nil {
			return Client{}, fmt.Errorf("failed to create HTTP client storage for %q: %w", u, errors.Join(err, ErrNewClient))
		}
		clientOptions.HTTPURLs[u] = c
	}
	return NewClient(clientOptions)
}

func (c Client) ReadKey(ctx context.Context, keyID string) (jwk JWK, err error) {
	if !c.prioritizeHTTP {
		jwk, err = c.given.ReadKey(ctx, keyID)
		switch {
		case errors.Is(err, ErrKeyNotFound):
			// Do nothing.
		case err != nil:
			return JWK{}, fmt.Errorf("failed to find JWT key with ID %q in given storage due to error: %w", keyID, err)
		default:
			return jwk, nil
		}
	}
	for _, store := range c.httpURLs {
		jwk, err = store.ReadKey(ctx, keyID)
		switch {
		case errors.Is(err, ErrKeyNotFound):
			continue
		case err != nil:
			return JWK{}, fmt.Errorf("failed to find JWT key with ID %q in HTTP storage due to error: %w", keyID, err)
		default:
			return jwk, nil
		}
	}
	if c.prioritizeHTTP {
		jwk, err = c.given.ReadKey(ctx, keyID)
		switch {
		case errors.Is(err, ErrKeyNotFound):
			// Do nothing.
		case err != nil:
			return JWK{}, fmt.Errorf("failed to find JWT key with ID %q in given storage due to error: %w", keyID, err)
		default:
			return jwk, nil
		}
	}
	return JWK{}, fmt.Errorf("%w %q", ErrKeyNotFound, keyID)
}

func (c Client) SnapshotKeys(ctx context.Context) ([]JWK, error) {
	jwks, err := c.given.SnapshotKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to snapshot given keys due to error: %w", err)
	}
	for u, store := range c.httpURLs {
		j, err := store.SnapshotKeys(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to snapshot HTTP keys from %q due to error: %w", u, err)
		}
		jwks = append(jwks, j...)
	}
	return jwks, nil
}
