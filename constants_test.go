package jwkset_test

import (
	"testing"

	"github.com/MicahParks/jwkset"
)

func TestALG_String(t *testing.T) {
	if jwkset.AlgEdDSA.String() != "EdDSA" {
		t.Errorf("Failed to get the string representation of the EdDSA algorithm.")
	}
}
