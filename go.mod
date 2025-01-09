module github.com/MicahParks/jwkset

go 1.21

require golang.org/x/time v0.9.0

retract [v0.5.0, v0.5.15] // HTTP client failed to remove JWK from local cache if not in refresh: https://github.com/MicahParks/jwkset/issues/40
