package jwkset

import (
	"context"
	"golang.org/x/time/rate"
	"net/http"
	"time"
)

// HTTPClientOption wraps HTTPClientOptions to override defaults.
type HTTPClientOption func(*HTTPClientOptions)

// HTTPClientStorageOption wraps HTTPClientStorageOptions to override defaults.
type HTTPClientStorageOption func(*HTTPClientStorageOptions)

// WithGiven overrides default HTTPClientOptions.Given option.
func WithGiven(given Storage) HTTPClientOption {
	return func(options *HTTPClientOptions) {
		options.Given = given
	}
}

// WithPrioritizeHTTP overrides default HTTPClientOptions.PrioritizeHTTP option.
func WithPrioritizeHTTP(prioritize bool) HTTPClientOption {
	return func(o *HTTPClientOptions) {
		o.PrioritizeHTTP = prioritize
	}
}

// WithRateLimitWaitMax overrides default HTTPClientOptions.RateLimitWaitMax option.
func WithRateLimitWaitMax(waitMax time.Duration) HTTPClientOption {
	return func(o *HTTPClientOptions) {
		o.RateLimitWaitMax = waitMax
	}
}

// WithRefreshUnknownKID overrides default HTTPClientOptions.RefreshUnknownKID option.
func WithRefreshUnknownKID(limiter *rate.Limiter) HTTPClientOption {
	return func(o *HTTPClientOptions) {
		o.RefreshUnknownKID = limiter
	}
}

// WithStorageOptions sets HTTPClientStorageOption(s) to override default HTTPClientStorageOptions.
func WithStorageOptions(storageOptions ...HTTPClientStorageOption) HTTPClientOption {
	return func(o *HTTPClientOptions) {
		o.storageOptions = storageOptions
	}
}

// WithClient overrides default HTTPClientStorageOptions.Client option.
func WithClient(client *http.Client) HTTPClientStorageOption {
	return func(o *HTTPClientStorageOptions) {
		o.Client = client
	}
}

// WithHTTPExpectedStatus overrides default HTTPClientStorageOptions.HTTPExpectedStatus option.
func WithHTTPExpectedStatus(status int) HTTPClientStorageOption {
	return func(o *HTTPClientStorageOptions) {
		o.HTTPExpectedStatus = status
	}
}

// WithHTTPMethod overrides default HTTPClientStorageOptions.HTTPMethod option.
func WithHTTPMethod(method string) HTTPClientStorageOption {
	return func(o *HTTPClientStorageOptions) {
		o.HTTPMethod = method
	}
}

// WithHTTPTimeout overrides default HTTPClientStorageOptions.HTTPTimeout option.
func WithHTTPTimeout(timeout time.Duration) HTTPClientStorageOption {
	return func(o *HTTPClientStorageOptions) {
		o.HTTPTimeout = timeout
	}
}

// WithNoErrorReturnFirstHTTPReq overrides default HTTPClientStorageOptions.NoErrorReturnFirstHTTPReq option.
func WithNoErrorReturnFirstHTTPReq(noError bool) HTTPClientStorageOption {
	return func(o *HTTPClientStorageOptions) {
		o.NoErrorReturnFirstHTTPReq = noError
	}
}

// WithRefreshErrorHandler overrides default HTTPClientStorageOptions.RefreshErrorHandler option.
func WithRefreshErrorHandler(handler func(ctx context.Context, err error)) HTTPClientStorageOption {
	return func(o *HTTPClientStorageOptions) {
		o.RefreshErrorHandler = handler
	}
}

// WithRefreshInterval overrides default HTTPClientStorageOptions.RefreshInterval option.
func WithRefreshInterval(interval time.Duration) HTTPClientStorageOption {
	return func(o *HTTPClientStorageOptions) {
		o.RefreshInterval = interval
	}
}

// WithStorage overrides default HTTPClientStorageOptions.Storage option.
func WithStorage(storage Storage) HTTPClientStorageOption {
	return func(o *HTTPClientStorageOptions) {
		o.Storage = storage
	}
}
