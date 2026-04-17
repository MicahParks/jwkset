// Package ctxkey contains the context keys used by httphandle.
package ctxkey

const (
	// Logger is the context key a logger.
	Logger ContextKey = iota
	// ReqUUID is the context key a request UUID.
	ReqUUID
)

// ContextKey is the type of context keys.
type ContextKey int
