package jwksetcom

import (
	"embed"
)

//go:embed static
var Static embed.FS

//go:embed templates
var Templates embed.FS
