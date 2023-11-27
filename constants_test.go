package jwkset

import (
	"crypto/x509"
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

func TestCertToAlg(t *testing.T) {
	m := map[x509.SignatureAlgorithm]ALG{
		x509.ECDSAWithSHA256:  AlgES256,
		x509.ECDSAWithSHA384:  AlgES384,
		x509.ECDSAWithSHA512:  AlgES512,
		x509.PureEd25519:      AlgEdDSA,
		x509.SHA256WithRSA:    AlgRS256,
		x509.SHA384WithRSA:    AlgRS384,
		x509.SHA512WithRSA:    AlgRS512,
		x509.SHA256WithRSAPSS: AlgPS256,
		x509.SHA384WithRSAPSS: AlgPS384,
		x509.SHA512WithRSAPSS: AlgPS512,
	}
	for cert, alg := range m {
		if certToAlg(cert) != alg {
			t.Errorf("Failed to convert certificate to algorithm.")
		}
	}
	if certToAlg(0) != "" {
		t.Errorf("Failed to convert unknown certificate signing algorithm to empty ALG.")
	}
}
