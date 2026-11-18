package jwkset

import (
	"encoding/json"
	"errors"
	"hash"
	"testing"
)

func TestThumbprint(t *testing.T) {
	t.Parallel()

	deriveKey := func(t *testing.T, raw string, private bool) any {
		t.Helper()
		jwk, err := NewJWKFromRawJSON(json.RawMessage(raw), JWKMarshalOptions{Private: private}, JWKValidateOptions{})
		if err != nil {
			t.Fatalf("failed to create JWK: %v", err)
		}
		return jwk.key
	}

	tests := []struct {
		name           string
		key            func(t *testing.T) any
		hash           hash.Hash
		wantThumbprint string
		wantErr        error
	}{
		// https://www.rfc-editor.org/info/rfc7638/#section-3.1
		{
			name: "rfc RSA example",
			key: func(t *testing.T) any {
				return deriveKey(
					t,
					`{
      			"kty": "RSA",
      			"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      			"e": "AQAB",
      			"alg": "RS256",
      			"kid": "2011-04-29"
     			}`,
					false,
				)
			},
			wantThumbprint: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
		},
		// compare with https://kjur.github.io/jsrsasign/sample/tool_jwktp.html
		{
			name: "EC256 key",
			key: func(t *testing.T) any {
				return deriveKey(
					t,
					`{
						"kty":"EC",
  					"crv":"P-256",
  					"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
  					"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
  					"use":"enc",
  					"kid":"1"
					}`,
					false,
				)
			},
			wantThumbprint: "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s",
		},
		{
			name: "symmetric key",
			key: func(t *testing.T) any {
				return deriveKey(
					t,
					`{ 
					"kty":"oct",
  				"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
  				"kid":"HMAC key used in JWS spec Appendix A.1 example"
					}`,
					true,
				)
			},
			wantThumbprint: "y_x3gCJnL6oKGBBIXScabduwxTVy2Wd2bzRVEUbdUzc",
		},
		// compare with https://encrypt-online.com/tools/jwk-thumbprint-calculator
		{
			name: "Ed25519",
			key: func(t *testing.T) any {
				return deriveKey(
					t,
					`{
  			"crv": "Ed25519",
  			"x": "kkuykt3sLHDHlwJLpA48RyupsMmYk3JJVO_Owtq1tyk",
  			"kty": "OKP"
				}`,
					false,
				)
			},
			wantThumbprint: "W8SIurfuxo6rbncofGtIXvLhE0Ip9_CAqjGUsT71Qv8",
		},
		{
			name: "unsupported key type",
			key: func(t *testing.T) any {
				return 67
			},
			wantErr: ErrThumbprintNotSupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := thumbprint(tt.key(t), tt.hash)
			if tt.wantThumbprint != got {
				t.Fatalf("thumbprint() got = %v, want %v", got, tt.wantThumbprint)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("thumbprint() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
