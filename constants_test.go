package jwkset

import (
	"testing"
)

func TestALG(t *testing.T) {
	a := AlgHS256
	if a.String() != string(a) {
		t.Errorf("Failed to get proper string from String method.")
	}
}

func TestCRV(t *testing.T) {
	c := CrvP256
	if c.String() != string(c) {
		t.Errorf("Failed to get proper string from String method.")
	}
}

func TestKEYOPS(t *testing.T) {
	k := KeyOpsSign
	if k.String() != string(k) {
		t.Errorf("Failed to get proper string from String method.")
	}
	if !k.valid() {
		t.Errorf("Failed to validate valid KEYOPS.")
	}
	k = "invalid"
	if k.valid() {
		t.Errorf("Do not validate invalid KEYOPS.")
	}
}

func TestKTY(t *testing.T) {
	k := KtyEC
	if k.String() != string(k) {
		t.Errorf("Failed to get proper string from String method.")
	}
	if !k.valid() {
		t.Errorf("Failed to validate valid KTY.")
	}
	k = "invalid"
	if k.valid() {
		t.Errorf("Do not validate invalid KTY.")
	}
}

func TestUSE(t *testing.T) {
	u := UseEnc
	if u.String() != string(u) {
		t.Errorf("Failed to get proper string from String method.")
	}
	if !u.valid() {
		t.Errorf("Failed to validate valid USE.")
	}
	u = "invalid"
	if u.valid() {
		t.Errorf("Do not validate invalid USE.")
	}
}
