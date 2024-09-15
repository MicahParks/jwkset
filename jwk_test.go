package jwkset

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

const (
	anyStr     = "any"
	invalidStr = "invalid"
)

func TestNewJWKFromRawJSON(t *testing.T) {
	marshalOptions := JWKMarshalOptions{
		Private: true,
	}
	jwk, err := NewJWKFromRawJSON([]byte(edExpected), marshalOptions, JWKValidateOptions{})
	if err != nil {
		t.Fatalf("Failed to create JWK from raw JSON. %s", err)
	}
	if jwk.Marshal().KID != edID {
		t.Fatalf("Incorrect KID. %s", jwk.Marshal().KID)
	}

	_, err = NewJWKFromRawJSON([]byte("invalid"), JWKMarshalOptions{}, JWKValidateOptions{})
	if err == nil {
		t.Fatal("Expected an error.")
	}
}

func TestJSON(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	jwks := NewMemoryStorage()
	testJSON(ctx, t, jwks)
}

func TestThumbprint(t *testing.T) {
	type thumbprintScenario int
	const (
		thumbprintScenarioCorrect thumbprintScenario = iota
		thumbprintScenarioIncorrect
		thumbprintScenarioMissing
		thumbprintScenarioNoCert
	)
	testCases := []struct {
		name            string
		x5tScenario     thumbprintScenario
		x5tS256Scenario thumbprintScenario
	}{
		{
			name: "CorrectX5TAndX5T#S256",
		},
		{
			name:        "MissingX5T",
			x5tScenario: thumbprintScenarioMissing,
		},
		{
			name:            "MissingX5T#S256",
			x5tS256Scenario: thumbprintScenarioMissing,
		},
		{
			name:            "MissingX5TAndX5T#S256",
			x5tScenario:     thumbprintScenarioMissing,
			x5tS256Scenario: thumbprintScenarioMissing,
		},
		{
			name:        "IncorrectX5T",
			x5tScenario: thumbprintScenarioIncorrect,
		},
		{
			name:            "IncorrectX5T#S256",
			x5tS256Scenario: thumbprintScenarioIncorrect,
		},
		{
			name:            "IncorrectX5TAndX5T#S256",
			x5tScenario:     thumbprintScenarioIncorrect,
			x5tS256Scenario: thumbprintScenarioIncorrect,
		},
		{
			name:            "NoCertX5T",
			x5tScenario:     thumbprintScenarioNoCert,
			x5tS256Scenario: thumbprintScenarioMissing,
		},
		{
			name:            "NoCertX5T#S256",
			x5tScenario:     thumbprintScenarioMissing,
			x5tS256Scenario: thumbprintScenarioNoCert,
		},
		{
			name:            "NoCertX5TAndX5T#S256",
			x5tScenario:     thumbprintScenarioNoCert,
			x5tS256Scenario: thumbprintScenarioNoCert,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			block, _ := pem.Decode([]byte(ed25519Cert))
			cert, err := LoadCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("Failed to load certificate. %s", err)
			}
			metadata := JWKMetadataOptions{
				KID: myKeyID,
			}
			x509Options := JWKX509Options{
				X5C: []*x509.Certificate{cert},
			}
			options := JWKOptions{
				Metadata: metadata,
				X509:     x509Options,
			}
			jwk, err := NewJWKFromKey(cert.PublicKey, options)
			if err != nil {
				t.Fatalf("Failed to create JWK from key. %s", err)
			}
			marshal := jwk.Marshal()
			switch tc.x5tScenario {
			case thumbprintScenarioCorrect:
				// Do nothing.
			case thumbprintScenarioIncorrect:
				marshal.X5T = invalidStr
			case thumbprintScenarioMissing:
				marshal.X5T = ""
			case thumbprintScenarioNoCert:
				marshal.X5C = nil
			}
			switch tc.x5tS256Scenario {
			case thumbprintScenarioCorrect:
				// Do nothing.
			case thumbprintScenarioIncorrect:
				marshal.X5TS256 = invalidStr
			case thumbprintScenarioMissing:
				marshal.X5TS256 = ""
			case thumbprintScenarioNoCert:
				marshal.X5C = nil
			}
			jwk, err = NewJWKFromMarshal(marshal, JWKMarshalOptions{}, JWKValidateOptions{})
			if err != nil {
				if tc.x5tScenario == thumbprintScenarioIncorrect || tc.x5tS256Scenario == thumbprintScenarioIncorrect {
					return
				}
				t.Fatalf("Failed to create JWK from marshal. %s", err)
			}
			if jwk.Marshal().KID != myKeyID {
				t.Fatalf("Incorrect KID. %s", jwk.Marshal().KID)
			}
		})
	}
}

func TestJWK_Validate(t *testing.T) {
	jwk := JWK{}
	err := jwk.Validate()
	if err == nil {
		t.Fatalf("Expected to fail validation for empty JWK.")
	}

	jwk.options.Validate.SkipAll = true
	err = jwk.Validate()
	if err != nil {
		t.Fatalf("Failed to skip validation. %s", err)
	}
	jwk.options.Validate.SkipAll = false

	jwk.marshal.KTY = KtyOKP
	jwk.marshal.USE = invalidStr
	err = jwk.Validate()
	if err == nil {
		t.Fatalf("Expected to fail validation for invalid use.")
	}
	jwk.marshal.USE = ""

	jwk.marshal.KEYOPS = []KEYOPS{invalidStr}
	err = jwk.Validate()
	if err == nil {
		t.Fatalf("Expected to fail validation for invalid key operations.")
	}
	jwk.marshal.KEYOPS = nil

	jwk.options.Metadata.ALG = AlgEdDSA
	err = jwk.Validate()
	if err == nil {
		t.Fatalf("Expected to fail validation for options not matching algorithm.")
	}
	jwk.options.Metadata.ALG = ""

	jwk.options.Metadata.KID = anyStr
	err = jwk.Validate()
	if err == nil {
		t.Fatalf("Expected to fail validation for options not matching key ID.")
	}
	jwk.options.Metadata.KID = ""

	jwk.options.Metadata.KEYOPS = []KEYOPS{KeyOpsSign}
	err = jwk.Validate()
	if err == nil {
		t.Fatalf("Expected to fail validation for options not matching key operations.")
	}
	jwk.options.Metadata.KEYOPS = nil

	jwk.options.Metadata.USE = UseSig
	err = jwk.Validate()
	if err == nil {
		t.Fatalf("Expected to fail validation for options not matching use.")
	}
	jwk.options.Metadata.USE = ""
}

func TestJWK_Validate_Padding(t *testing.T) {
	const invalidRSAModulusPadding = `
{
  "kty": "RSA",
  "n": "AOpF5dwoCpmW2Th5kBaKDZmygOlyQSJm3JqwGvPTTViHCs4ZitlLF9za9-DPxP3zoNaryEYlFfLhYOFVS7mUjMGtLNTkLafBSIIoF28sy_z1GruxJ2aFchazBimxI1B0MXTKdIw4V268klrOECO5FIcHar7EV9W0XqToFon3oVvHWw3qkPV4o-A7Gdrh3Yh7vRUE_T5XCLYD9jO41nAqYhWYRGN-Kxu51x6VMa595TXTrpzgYGDba1MLQzB9qcHRIvRskt7Gh8M0zgcyo6c6jvktaEzh0j2kdL2JCAFHhMXUZedRUOpeqkEehpxDDR0Deiz7UPlMe6l8Ots97Wm357bgajDcxnqaGGEF5GIkr7xHw15DrTfOWPY35f0sHjNTOn9AU2bPWTy6oHZPhoFjHdSNp3UOIunnf1eXRlTa7YZ5PLmbFFyjNNSnQdcOHgKx1lJExJqXCAJ2pBkp0dX65uiqCLz4WZBcmCHGToi4mvQ5wpFqgUJ_6N8HXpP5ZLZ-hQ",
  "e": "AQAB"
}`
	jwk, err := NewJWKFromRawJSON([]byte(invalidRSAModulusPadding), JWKMarshalOptions{}, JWKValidateOptions{})
	if err != nil {
		t.Fatalf("Failed to create JWK from raw JSON. %s", err)
	}
	err = jwk.Validate()
	if err != nil {
		t.Fatalf("Failed to validate RSA JWK with acceptably invalid padding. %s", err)
	}
	jwk.options.Validate.StrictPadding = true
	err = jwk.Validate()
	if !errors.Is(err, ErrPadding) {
		t.Fatalf("Expected to fail validation for invalid RSA modulus padding.")
	}

	const invalidECDSAPadding = `
{
  "kty": "EC",
  "crv": "P-521",
  "x": "aQnZOuwyXH1APmjESTgHLVUH49Ry19Ay7hgHiOB4Nsv5m_JN18wW-ByFtGtHatVJ_OHL5TuLOTSsp8ctniKTn3E",
  "y": "TZAwFszO_oiyvncIviOJdi8MU8VDfZo8Y3q0Z-AxaPDUFQS8aRDCHUzukj6RCNZsRCWd0HGOayIhV_uQZrB_Xbc",
  "d": "AZHsd9nLaXHFWH4wjiW5XcCrIO9AWl4Y0aV64kagRFPnWjljC6VxCsFF5IM0vTzCWKdlwFLEIgJO0pfwWlQMXKef"
}
`
	jwk, err = NewJWKFromRawJSON([]byte(invalidECDSAPadding), JWKMarshalOptions{}, JWKValidateOptions{})
	if err != nil {
		t.Fatalf("Failed to create JWK from raw JSON. %s", err)
	}
	err = jwk.Validate()
	if err != nil {
		t.Fatalf("Failed to validate ECDSA JWK with acceptably invalid padding. %s", err)
	}
	jwk.options.Validate.StrictPadding = true
	err = jwk.Validate()
	if !errors.Is(err, ErrPadding) {
		t.Fatalf("Expected to fail validation for invalid ECDSA padding.")
	}
}

func testJSON(ctx context.Context, t *testing.T, jwks Storage) {
	b, err := base64.RawURLEncoding.DecodeString(x25519PrivateKey)
	if err != nil {
		t.Fatalf("Failed to decode ECDH X25519 private key. %s", err)
	}
	x25519Priv, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		t.Fatalf("Failed to generate ECDH X25519 key. %s", err)
	}
	writeKey(ctx, t, jwks, x25519Priv, x25519ID, true)

	block, _ := pem.Decode([]byte(ecPrivateKey))
	eKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse EC private key. %s", err)
	}
	writeKey(ctx, t, jwks, eKey, eID, true)

	edPriv, err := base64.RawURLEncoding.DecodeString(edPrivateKey)
	if err != nil {
		t.Fatalf("Failed to decode EdDSA private key. %s", err)
	}
	edPub, err := base64.RawURLEncoding.DecodeString(edPublicKey)
	if err != nil {
		t.Fatalf("Failed to decode EdDSA public key. %s", err)
	}
	ed := ed25519.PrivateKey(append(edPriv, edPub...))
	writeKey(ctx, t, jwks, ed, edID, true)

	block, _ = pem.Decode([]byte(rsaPrivateKey))
	rKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse RSA private key. %s", err)
	}
	writeKey(ctx, t, jwks, rKey, rID, true)

	hKey := []byte(hmacSecret)
	writeKey(ctx, t, jwks, hKey, hID, true)

	jsonRepresentation, err := jwks.JSONPublic(ctx)
	if err != nil {
		t.Fatalf("Failed to get JSON. %s", err)
	}
	compareJSON(t, jsonRepresentation, false)

	jsonRepresentation, err = jwks.JSONPrivate(ctx)
	if err != nil {
		t.Fatalf("Failed to get JSON. %s", err)
	}
	compareJSON(t, jsonRepresentation, true)
}

func compareJSON(t *testing.T, actual json.RawMessage, private bool) {
	type jwksUnmarshal struct {
		Keys []map[string]any `json:"keys"`
	}

	var keys jwksUnmarshal
	err := json.Unmarshal(actual, &keys)
	if err != nil {
		t.Fatalf("Failed to unmarshal actual JSON. %s", err)
	}

	wrongLength := false
	var expectedKeys int
	if private && len(keys.Keys) != 5 {
		expectedKeys = 5
		wrongLength = true
	} else if !private && len(keys.Keys) != 4 {
		expectedKeys = 4
		wrongLength = true
	}
	if wrongLength {
		t.Fatalf("Expected %d keys. Got %d. HMAC keys should not have a JSON representation.", expectedKeys, len(keys.Keys))
	}

	for _, key := range keys.Keys {
		kty, ok := key["kty"].(string)
		if !ok {
			t.Fatal("Failed to get key type.")
		}

		var expectedJSON json.RawMessage
		var matchingAttributes []string
		switch KTY(kty) {
		case KtyEC:
			expectedJSON = json.RawMessage(ecExpected)
			matchingAttributes = []string{"kty", "kid", "crv", "x", "y"}
			if private {
				matchingAttributes = append(matchingAttributes, "d")
			}
		case KtyOKP:
			matchingAttributes = []string{"crv", "kty", "kid", "x"}
			if private {
				matchingAttributes = append(matchingAttributes, "d")
			}
			switch CRV(key["crv"].(string)) {
			case CrvEd25519:
				matchingAttributes = append(matchingAttributes, "alg")
				expectedJSON = json.RawMessage(edExpected)
			case CrvX25519:
				expectedJSON = json.RawMessage(x25519Expected)
			default:
				t.Fatalf("Unknown OKP curve %q.", key["crv"].(string))
			}
		case KtyRSA:
			expectedJSON = json.RawMessage(rsaExpected)
			matchingAttributes = []string{"kty", "kid", "n", "e"}
			if private {
				matchingAttributes = append(matchingAttributes, "d", "p", "q", "dp", "dq", "qi")
			}
		case KtyOct:
			if private {
				expectedJSON = json.RawMessage(hmacExpected)
				matchingAttributes = []string{"kty", "kid", "k"}
			} else {
				t.Fatal("HMAC keys should not have a JSON representation.")
			}
		}
		var expectedMap map[string]any
		err = json.Unmarshal(expectedJSON, &expectedMap)
		if err != nil {
			t.Fatalf("Failed to unmarshal expected JSON. %s", err)
		}

		for _, attribute := range matchingAttributes {
			actualAttr, ok := key[attribute].(string)
			if !ok {
				t.Fatalf("Failed to get actual attribute %s.", attribute)
			}
			expectedAttr, ok := expectedMap[attribute].(string)
			if !ok {
				t.Fatalf("Failed to get expected attribute %s.", attribute)
			}
			if actualAttr != expectedAttr {
				t.Fatalf("Attribute %s does not match.\n  Actual: %q\n  Expected: %q", attribute, actualAttr, expectedAttr)
			}
		}
	}
}

func writeKey(ctx context.Context, t *testing.T, jwks Storage, key any, keyID string, private bool) {
	marshal := JWKMarshalOptions{
		Private: private,
	}
	metadata := JWKMetadataOptions{
		KID: keyID,
	}
	options := JWKOptions{
		Marshal:  marshal,
		Metadata: metadata,
	}
	jwk, err := NewJWKFromKey(key, options)
	if err != nil {
		t.Fatalf("Failed to create JWK from key ID %q. %s", keyID, err)
	}
	err = jwks.KeyWrite(ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to write key ID %q. %s", keyID, err)
	}
}

const (
	x25519ID = "myX25519Key"
	eID      = "myECKey"
	edID     = "myEdDSAKey"
	hID      = "myHMACKey"
	rID      = "myRSAKey"
)

/*
These assets were generated using this tool:
https://mkjwk.org/
*/
const (
	x25519Expected = `{
    "kty": "OKP",
    "d": "GIu7AbclXA1FtVswPBUileBckbJu2B9UUhZPTebrox4",
    "crv": "X25519",
    "kid": "myX25519Key",
    "x": "fGMcCrO_gWS7rva_PpXiS7D5-2OppjZQLlZmdRUSN0g"
}`
	x25519PrivateKey = `GIu7AbclXA1FtVswPBUileBckbJu2B9UUhZPTebrox4`
	ecExpected       = `{
    "kty": "EC",
    "d": "Vp3epfDd9viOo1w6Co7DpIP2lPnqwIB8HcOrI7Jt0II",
    "crv": "P-256",
    "kid": "myECKey",
    "x": "24yKWYrRffYdpQzbnkzbhABivplltO-eimNwqK3xeAM",
    "y": "qGxS4s4TH35_VK4Bk119s16tFGKegwHJc3pL2p2Zy30"
}`
	ecPrivateKey = `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBWnd6l8N32+I6jXDoK
jsOkg/aU+erAgHwdw6sjsm3Qgg==
-----END PRIVATE KEY-----`
	edExpected = `{
    "alg": "EdDSA",
    "kty": "OKP",
    "d": "tKqo1bnSif18g2hE0D7zPDNgSTKQKwBMEl2UvhJZ-bs",
    "crv": "Ed25519",
    "kid": "myEdDSAKey",
    "x": "eX81_IFCbcbhBDD-wgUYbYk8E6DLnPnl39YXx_ru7ao"
}`
	edPrivateKey = "tKqo1bnSif18g2hE0D7zPDNgSTKQKwBMEl2UvhJZ-bs"
	edPublicKey  = "eX81_IFCbcbhBDD-wgUYbYk8E6DLnPnl39YXx_ru7ao"
	hmacExpected = `{
    "kty": "oct",
    "kid": "myHMACKey",
    "k": "bXlITUFDU2VjcmV0"
}`
	rsaExpected = `{
    "p": "5x2fw5e3bz20IxlbU3Jxn9OOAeMuVGqC-BP2XYk6-2T9T_TeKRgEEIoHtt0lre3QZrefB-6UjNfXU6pfuMr4BsSpT-tAjiUI1c8EmHC5hhpCDJ8LWekWrTJDPApfQjpZK-HO0UdIZCIILyVr82KuZax5RKBMTMfDPjF2NQxwqFc",
    "kty": "RSA",
    "q": "wbu1LZuDBRq8PZ-G2SJNU_t-b1Zev3Hn6iLFNYF5Y3CYRVtAg_TWpErfrM-4YUXucLQGsLOaCnRNQ81GXFb9e6W7sY8UeyAlqFxxtm0FZ2CnpxxS9EYq57AP5EfpyOi7DNUe0fe0wTwC5o_sq-pMOeCsuWgiXjgTpDoydwtjIFM",
    "d": "c0w8JqtmAAX5TC5Ba0KaGft-uAi-Q0rngcob_l8dVcF6pRqN0QKhwZAKKlb57hwHLdzl6Rc9YmVjWBemVo-Pi-ZKpeXSnkxFEc_50NMMGOp4TIjBaoJcrQ3KP5T7djwPc0aZ51z7XtUZ8Q_G0gEGAywnG6zUTJlqS8ctybBcol0LDl--Ps52I2pupZ1RiIRsgPF0zrGTsGrnxdtFVxOVRqNTZ26fEOSqRRTXxC4PNN4PDR2OSTDc-G1F_OPGJutgPnt7dpgw0vAkGD0b4FxtMXTXoS3cgB5zug4ySi9-1jBvAvNkWt0i3OoYPPLarDjlesRTHs5P_iOWjt6nFBeLpQ",
    "e": "AQAB",
    "kid": "myRSAKey",
    "qi": "eJxCTg3NoEUcK8eCMBp0ukJ1SZD11UbWrL-Js6YaAr-Mx5nrWozMfcyaerSrwGYcCmD3Ga3bhv28TyGCujCsT35aWqOyi9S51M8AJ6VoiLgYSufuI7DnlUHjKpoPezhSM-RWW1QFdLR9InCBsfQctiy0Hf8IjaKqtPotx6zTR2E",
    "dp": "xHCRkxYpfAveSNcMoOjtWwPd-Ay5HFdL6sBM70PtNjCofoWLLzKSgdxQokVl-Wfhcu0v5vYKnYv4Icz2f4NFPbt6jctPm4Iu-Ex1g3yMtEctTL0CUPGlrKDENQw723bsxDeyKn-EMFgczLXqA30k7painIoDUF-avAoehwiD2RE",
    "dq": "BK60wlVv5T-wLQ0eBUF-_PinJanAwH_QSyhr-88VUAH4rDR4argQOAhXP6YFntRB3xd60eqFXptRAsKDYNf5aHOpBbGfnRo5zsftN6uK5eTAKJnWp3DKuK7Ys3vJesGlQ7oi9JA4HjOFHm18GuuezAdSJWkO65gPYXjGn3n2-2E",
    "n": "rubLp0fQtgIIy1xq-fM-mDxlobK7qUf1UIH4DQHUSWXzauvRNaV2cj4iIhooJVej24v0EOH3ZNzdt8MTj7X9r5P1GSIFfNydcP_00T8zeYec0x7XjdNsZ2EY5rYV3Eo-rRivz08y5622Bt82o0td4QvMovmYKGwTKIiIe0mCByOOVbIACPEvZsCiI-Fbd_ovFv1zAl_-G8DAXCQHz-MwpW_ouZmdlnFz0kMCPf58cEUvLCczt4C8xCRYYqQyz84Nal0BiZ4x8ZiZ6k_z8SRN_QB5bk9aetwKgjBPWsBpwnuccXjGyGqSIWa91tTxeGMC4nsHWT89LDH_0dn-9DZ0NQ"
}`
	rsaPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu5sunR9C2AgjL
XGr58z6YPGWhsrupR/VQgfgNAdRJZfNq69E1pXZyPiIiGiglV6Pbi/QQ4fdk3N23
wxOPtf2vk/UZIgV83J1w//TRPzN5h5zTHteN02xnYRjmthXcSj6tGK/PTzLnrbYG
3zajS13hC8yi+ZgobBMoiIh7SYIHI45VsgAI8S9mwKIj4Vt3+i8W/XMCX/4bwMBc
JAfP4zClb+i5mZ2WcXPSQwI9/nxwRS8sJzO3gLzEJFhipDLPzg1qXQGJnjHxmJnq
T/PxJE39AHluT1p63AqCME9awGnCe5xxeMbIapIhZr3W1PF4YwLiewdZPz0sMf/R
2f70NnQ1AgMBAAECggEAc0w8JqtmAAX5TC5Ba0KaGft+uAi+Q0rngcob/l8dVcF6
pRqN0QKhwZAKKlb57hwHLdzl6Rc9YmVjWBemVo+Pi+ZKpeXSnkxFEc/50NMMGOp4
TIjBaoJcrQ3KP5T7djwPc0aZ51z7XtUZ8Q/G0gEGAywnG6zUTJlqS8ctybBcol0L
Dl++Ps52I2pupZ1RiIRsgPF0zrGTsGrnxdtFVxOVRqNTZ26fEOSqRRTXxC4PNN4P
DR2OSTDc+G1F/OPGJutgPnt7dpgw0vAkGD0b4FxtMXTXoS3cgB5zug4ySi9+1jBv
AvNkWt0i3OoYPPLarDjlesRTHs5P/iOWjt6nFBeLpQKBgQDnHZ/Dl7dvPbQjGVtT
cnGf044B4y5UaoL4E/ZdiTr7ZP1P9N4pGAQQige23SWt7dBmt58H7pSM19dTql+4
yvgGxKlP60COJQjVzwSYcLmGGkIMnwtZ6RatMkM8Cl9COlkr4c7RR0hkIggvJWvz
Yq5lrHlEoExMx8M+MXY1DHCoVwKBgQDBu7Utm4MFGrw9n4bZIk1T+35vVl6/cefq
IsU1gXljcJhFW0CD9NakSt+sz7hhRe5wtAaws5oKdE1DzUZcVv17pbuxjxR7ICWo
XHG2bQVnYKenHFL0RirnsA/kR+nI6LsM1R7R97TBPALmj+yr6kw54Ky5aCJeOBOk
OjJ3C2MgUwKBgQDEcJGTFil8C95I1wyg6O1bA934DLkcV0vqwEzvQ+02MKh+hYsv
MpKB3FCiRWX5Z+Fy7S/m9gqdi/ghzPZ/g0U9u3qNy0+bgi74THWDfIy0Ry1MvQJQ
8aWsoMQ1DDvbduzEN7Iqf4QwWBzMteoDfSTulqKcigNQX5q8Ch6HCIPZEQKBgASu
tMJVb+U/sC0NHgVBfvz4pyWpwMB/0Esoa/vPFVAB+Kw0eGq4EDgIVz+mBZ7UQd8X
etHqhV6bUQLCg2DX+WhzqQWxn50aOc7H7TeriuXkwCiZ1qdwyriu2LN7yXrBpUO6
IvSQOB4zhR5tfBrrnswHUiVpDuuYD2F4xp959vthAoGAeJxCTg3NoEUcK8eCMBp0
ukJ1SZD11UbWrL+Js6YaAr+Mx5nrWozMfcyaerSrwGYcCmD3Ga3bhv28TyGCujCs
T35aWqOyi9S51M8AJ6VoiLgYSufuI7DnlUHjKpoPezhSM+RWW1QFdLR9InCBsfQc
tiy0Hf8IjaKqtPotx6zTR2E=
-----END PRIVATE KEY-----`
)
