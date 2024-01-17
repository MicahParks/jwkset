module readme

go 1.21

replace github.com/MicahParks/jwkset => ../..

require (
	github.com/MicahParks/jwkset v0.5.6
	github.com/google/uuid v1.5.0
)

require golang.org/x/time v0.5.0 // indirect
