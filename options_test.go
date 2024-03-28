package jwkset

import (
	"context"
	"golang.org/x/time/rate"
	"net/http"
	"reflect"
	"testing"
)

func TestWithClientOptions(t *testing.T) {
	tests := []struct {
		name string
		arg  HTTPClientOptions
		opt  HTTPClientOption
		want HTTPClientOptions
	}{
		{
			"WithGiven",
			HTTPClientOptions{},
			WithGiven(NewMemoryStorage()),
			HTTPClientOptions{Given: NewMemoryStorage()},
		},
		{
			"WithPrioritizeHTTP",
			HTTPClientOptions{},
			WithPrioritizeHTTP(true),
			HTTPClientOptions{PrioritizeHTTP: true},
		},
		{
			"WithRateLimitWaitMax",
			HTTPClientOptions{},
			WithRateLimitWaitMax(42),
			HTTPClientOptions{RateLimitWaitMax: 42},
		},
		{
			"WithRefreshUnknownKID",
			HTTPClientOptions{},
			WithRefreshUnknownKID(rate.NewLimiter(4, 2)),
			HTTPClientOptions{RefreshUnknownKID: rate.NewLimiter(4, 2)},
		},
		{
			"WithStorageOptions",
			HTTPClientOptions{},
			WithRefreshUnknownKID(rate.NewLimiter(4, 2)),
			HTTPClientOptions{RefreshUnknownKID: rate.NewLimiter(4, 2)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opt(&tt.arg)
			if !reflect.DeepEqual(tt.arg, tt.want) {
				t.Errorf("%s() = %v, want %v", tt.name, tt.arg, tt.want)
			}
		})
	}
}

func TestWithClientStorageOptions(t *testing.T) {
	tests := []struct {
		name string
		arg  HTTPClientStorageOptions
		opt  HTTPClientStorageOption
		want HTTPClientStorageOptions
	}{
		{
			"WithClient",
			HTTPClientStorageOptions{},
			WithClient(http.DefaultClient),
			HTTPClientStorageOptions{Client: http.DefaultClient},
		},
		{
			"WithHTTPExpectedStatus",
			HTTPClientStorageOptions{},
			WithHTTPExpectedStatus(http.StatusTeapot),
			HTTPClientStorageOptions{HTTPExpectedStatus: http.StatusTeapot},
		},
		{
			"WithHTTPMethod",
			HTTPClientStorageOptions{},
			WithHTTPMethod(http.MethodOptions),
			HTTPClientStorageOptions{HTTPMethod: http.MethodOptions},
		},
		{
			"WithHTTPTimeout",
			HTTPClientStorageOptions{},
			WithHTTPTimeout(42),
			HTTPClientStorageOptions{HTTPTimeout: 42},
		},
		{
			"WithNoErrorReturnFirstHTTPReq",
			HTTPClientStorageOptions{},
			WithNoErrorReturnFirstHTTPReq(true),
			HTTPClientStorageOptions{NoErrorReturnFirstHTTPReq: true},
		},
		{
			"WithRefreshErrorHandler",
			HTTPClientStorageOptions{RefreshErrorHandler: func(_ context.Context, _ error) {}},
			WithRefreshErrorHandler(nil),
			HTTPClientStorageOptions{RefreshErrorHandler: nil},
		},
		{
			"WithRefreshInterval",
			HTTPClientStorageOptions{},
			WithRefreshInterval(42),
			HTTPClientStorageOptions{RefreshInterval: 42},
		},
		{
			"WithStorage",
			HTTPClientStorageOptions{},
			WithStorage(NewMemoryStorage()),
			HTTPClientStorageOptions{Storage: NewMemoryStorage()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opt(&tt.arg)
			if !reflect.DeepEqual(tt.arg, tt.want) {
				t.Errorf("%s() = %v, want %v", tt.name, tt.arg, tt.want)
			}
		})
	}
}

func TestWithStorageOptions(t *testing.T) {
	name := "WithStorageOptions"
	arg1 := HTTPClientOptions{}
	arg2 := HTTPClientStorageOptions{}
	opt := WithStorageOptions(
		WithClient(http.DefaultClient),
		WithHTTPExpectedStatus(http.StatusTeapot),
		WithHTTPMethod(http.MethodOptions),
		WithHTTPTimeout(42),
		WithNoErrorReturnFirstHTTPReq(true),
		WithRefreshInterval(42),
		WithStorage(NewMemoryStorage()))
	want := HTTPClientStorageOptions{
		Client:                    http.DefaultClient,
		HTTPExpectedStatus:        http.StatusTeapot,
		HTTPMethod:                http.MethodOptions,
		HTTPTimeout:               42,
		NoErrorReturnFirstHTTPReq: true,
		RefreshInterval:           42,
		Storage:                   NewMemoryStorage(),
	}
	t.Run(name, func(t *testing.T) {
		opt(&arg1)
		for _, sopt := range arg1.storageOptions {
			sopt(&arg2)
		}
		if !reflect.DeepEqual(arg2, want) {
			t.Errorf("%s() = %v, want %v", name, arg2, want)
		}
	})
}
