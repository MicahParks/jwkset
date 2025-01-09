module readme

go 1.21

replace github.com/MicahParks/jwkset => ../..

require (
	github.com/MicahParks/jwkset v0.6.0
	github.com/google/uuid v1.6.0
)

require golang.org/x/time v0.9.0 // indirect
