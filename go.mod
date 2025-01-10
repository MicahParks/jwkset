module github.com/MicahParks/jwkset

go 1.21

require golang.org/x/time v0.9.0

retract (
	v0.6.0 // Potential race condition in refresh goroutine: https://github.com/MicahParks/jwkset/pull/42
	[v0.5.0, v0.5.15] // HTTP client only overwrites and appends JWK to local cache during refresh: https://github.com/MicahParks/jwkset/issues/40
)
