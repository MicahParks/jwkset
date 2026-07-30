package jwkset

import (
	"testing"
)

const (
	invalid = "invalid"
)

func TestALG(t *testing.T) {
	a := AlgHS256
	if a.String() != string(a) {
		t.Errorf("Failed to get proper string from String method.")
	}
	if !a.IANARegistered() {
		t.Errorf("Failed to validate valid ALG.")
	}
	if a.Prohibited() {
		t.Errorf("Non-prohibited ALG reported as prohibited.")
	}
	a = invalid
	if a.IANARegistered() {
		t.Errorf("Do not validate invalid ALG.")
	}
	a = AlgHS1
	if !a.Prohibited() {
		t.Errorf("Prohibited ALG not reported as prohibited.")
	}
}

func TestCRV(t *testing.T) {
	c := CrvP256
	if c.String() != string(c) {
		t.Errorf("Failed to get proper string from String method.")
	}
	if !c.IANARegistered() {
		t.Errorf("Failed to validate valid CRV.")
	}
	c = invalid
	if c.IANARegistered() {
		t.Errorf("Do not validate invalid CRV.")
	}
}

func TestKEYOPS(t *testing.T) {
	k := KeyOpsSign
	if k.String() != string(k) {
		t.Errorf("Failed to get proper string from String method.")
	}
	if !k.IANARegistered() {
		t.Errorf("Failed to validate valid KEYOPS.")
	}
	k = invalid
	if k.IANARegistered() {
		t.Errorf("Do not validate invalid KEYOPS.")
	}
}

func TestKTY(t *testing.T) {
	k := KtyEC
	if k.String() != string(k) {
		t.Errorf("Failed to get proper string from String method.")
	}
	if !k.IANARegistered() {
		t.Errorf("Failed to validate valid KTY.")
	}
	k = invalid
	if k.IANARegistered() {
		t.Errorf("Do not validate invalid KTY.")
	}
}

func TestUSE(t *testing.T) {
	u := UseEnc
	if u.String() != string(u) {
		t.Errorf("Failed to get proper string from String method.")
	}
	if !u.IANARegistered() {
		t.Errorf("Failed to validate valid USE.")
	}
	u = invalid
	if u.IANARegistered() {
		t.Errorf("Do not validate invalid USE.")
	}
}
