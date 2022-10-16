package jwkset_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
)

func TestJSON(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	jwkSet := jwkset.NewMemory()

	block, _ := pem.Decode([]byte(ecPrivateKey))
	eKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse EC private key. %s", err)
	}
	const eID = "myECKey"
	err = jwkSet.Store.WriteKey(ctx, jwkset.NewKey(eKey.(*ecdsa.PrivateKey), eID))
	if err != nil {
		t.Fatalf("Failed to write EC key. %s", err)
	}

	edPriv, err := base64.RawURLEncoding.DecodeString(edPrivateKey)
	if err != nil {
		t.Fatalf("Failed to decode EdDSA private key. %s", err)
	}
	edPub, err := base64.RawURLEncoding.DecodeString(edPublicKey)
	if err != nil {
		t.Fatalf("Failed to decode EdDSA public key. %s", err)
	}
	ed := ed25519.PrivateKey(append(edPriv, edPub...))
	const edID = "myEdDSAKey"
	err = jwkSet.Store.WriteKey(ctx, jwkset.NewKey(ed, edID))
	if err != nil {
		t.Fatalf("Failed to write EdDSA key. %s", err)
	}

	block, _ = pem.Decode([]byte(rsaPrivateKey))
	rKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse RSA private key. %s", err)
	}
	const rID = "myRSAKey"
	err = jwkSet.Store.WriteKey(ctx, jwkset.NewKey(rKey.(*rsa.PrivateKey), rID))
	if err != nil {
		t.Fatalf("Failed to write RSA key. %s", err)
	}

	hKey := []byte(hmacSecret)
	const hID = "myHMACKey"
	err = jwkSet.Store.WriteKey(ctx, jwkset.KeyWithMeta{
		Key:   hKey,
		KeyID: hID,
	})
	if err != nil {
		t.Fatalf("Failed to write HMAC key. %s", err)
	}

	jsonRepresentation, err := jwkSet.JSON(ctx)
	if err != nil {
		t.Fatalf("Failed to get JSON. %s", err)
	}

	compareJSON(t, jsonRepresentation)
}

func TestJSONPublic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	jwkSet := jwkset.NewMemory()

	block, _ := pem.Decode([]byte(ecPrivateKey))
	eKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse EC private key. %s", err)
	}
	const eID = "myECKey"
	err = jwkSet.Store.WriteKey(ctx, jwkset.NewKey(&eKey.(*ecdsa.PrivateKey).PublicKey, eID))
	if err != nil {
		t.Fatalf("Failed to write EC key. %s", err)
	}

	edPriv, err := base64.RawURLEncoding.DecodeString(edPrivateKey)
	if err != nil {
		t.Fatalf("Failed to decode EdDSA private key. %s", err)
	}
	edPub, err := base64.RawURLEncoding.DecodeString(edPublicKey)
	if err != nil {
		t.Fatalf("Failed to decode EdDSA public key. %s", err)
	}
	ed := ed25519.PrivateKey(append(edPriv, edPub...))
	const edID = "myEdDSAKey"
	err = jwkSet.Store.WriteKey(ctx, jwkset.NewKey(ed.Public(), edID))
	if err != nil {
		t.Fatalf("Failed to write EdDSA key. %s", err)
	}

	block, _ = pem.Decode([]byte(rsaPrivateKey))
	rKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse RSA private key. %s", err)
	}
	const rID = "myRSAKey"
	err = jwkSet.Store.WriteKey(ctx, jwkset.NewKey(rKey.(*rsa.PrivateKey).PublicKey, rID))
	if err != nil {
		t.Fatalf("Failed to write RSA key. %s", err)
	}

	hKey := []byte(hmacSecret)
	const hID = "myHMACKey"
	err = jwkSet.Store.WriteKey(ctx, jwkset.KeyWithMeta{
		Key:   hKey,
		KeyID: hID,
	})
	if err != nil {
		t.Fatalf("Failed to write HMAC key. %s", err)
	}

	jsonRepresentation, err := jwkSet.JSON(ctx)
	if err != nil {
		t.Fatalf("Failed to get JSON. %s", err)
	}

	compareJSON(t, jsonRepresentation)
}

func compareJSON(t *testing.T, actual json.RawMessage) {
	type jwksUnmarshal struct {
		Keys []map[string]interface{} `json:"keys"`
	}

	var keys jwksUnmarshal
	err := json.Unmarshal(actual, &keys)
	if err != nil {
		t.Fatalf("Failed to unmarshal actual JSON. %s", err)
	}

	if len(keys.Keys) != 3 {
		t.Fatalf("Expected 3 keys. Got %d. HMAC keys should not have a JSON representation.", len(keys.Keys))
	}

	for _, key := range keys.Keys {
		kty, ok := key["kty"].(string)
		if !ok {
			t.Fatal("Failed to get key type.")
		}

		var expectedJSON json.RawMessage
		var matchingAttributes []string
		switch jwkset.KTY(kty) {
		case jwkset.KeyTypeEC:
			expectedJSON = json.RawMessage(ecExpected)
			matchingAttributes = []string{"kty", "kid", "crv", "x", "y"}
		case jwkset.KeyTypeOKP:
			expectedJSON = json.RawMessage(edExpected)
			matchingAttributes = []string{"kty", "kid", "x"}
		case jwkset.KeyTypeRSA:
			expectedJSON = json.RawMessage(rsaExpected)
			matchingAttributes = []string{"kty", "kid", "n", "e"}
		}
		var expectedMap map[string]interface{}
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

/*
These assets were generated using this tool:
https://mkjwk.org/
*/
const (
	ecExpected = `{
    "kid": "myECKey",
    "kty": "EC",
    "use": "enc",
    "crv": "P-256",
    "x": "ySFyLLthCEMqO1TVh2B5SM85DBhg-wuVlcVsSdswEl8",
    "y": "-MbIwk9t-vt3GpGpp_0yoiCpp8yRB3igUQkBStwJjyI",
    "alg": "ECDH-ES"
}`
	ecPrivateKey = `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBa80vb9tIT7/EQ8rjE
O9NiIPiTn67K5a9I9ai++4ZpeA==
-----END PRIVATE KEY-----`
	edExpected = `{
    "kid": "myEdDSAKey",
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "LYqimvjlMIx_qs9UKpigrlJDyP2RKfEljOLWhUgzQyE"
}`
	edPrivateKey = "tsXK0Kzrt5tkQitfrNezrJ8ky4whAEnoBE4fZg0jbQw"
	edPublicKey  = "LYqimvjlMIx_qs9UKpigrlJDyP2RKfEljOLWhUgzQyE"
	rsaExpected  = `{
    "kid": "myRSAKey",
    "kty": "RSA",
    "e": "AQAB",
    "use": "enc",
    "alg": "RSA1_5",
    "n": "neGKcVtE7bSvOZpqku2AtubWmjYIU3BH3EIUmTgKCswL2jYEcYMnLUQdOTBobBrhzgP2V1xN79s_LuqSHcFzvqE1wg64RvCWE4tF0aHCBQieH1PnRKsZlw5ZAPNKQC7e7QRgqmdcp9ljJQLCLFNfftQHYR1WzCwD2IslJkX5endXW4M7jyoCwbp1_KNnibgU29glQEk2FsII6Q1UG1Qi-LMPn2Tj2dIST9x_toYiuI2WZ5P4YfPI8xGNx5_uCgi7m9JZouwhcNGdAwa_ro6D7xzlwz4Me6_rpdR2lCNgeA2aRs6e9qbvx5-WmtXHzdZ7k6DU-FTjMGFhrLG23NSqaw"
}`
	rsaPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCd4YpxW0TttK85
mmqS7YC25taaNghTcEfcQhSZOAoKzAvaNgRxgyctRB05MGhsGuHOA/ZXXE3v2z8u
6pIdwXO+oTXCDrhG8JYTi0XRocIFCJ4fU+dEqxmXDlkA80pALt7tBGCqZ1yn2WMl
AsIsU19+1AdhHVbMLAPYiyUmRfl6d1dbgzuPKgLBunX8o2eJuBTb2CVASTYWwgjp
DVQbVCL4sw+fZOPZ0hJP3H+2hiK4jZZnk/hh88jzEY3Hn+4KCLub0lmi7CFw0Z0D
Br+ujoPvHOXDPgx7r+ul1HaUI2B4DZpGzp72pu/Hn5aa1cfN1nuToNT4VOMwYWGs
sbbc1KprAgMBAAECggEBAII4cD8VP6IsgMarRbIQcTTq6yDg5jckCjFy05iY7zd+
m1wNZ9bUjXC5mLz933MjLRIGlJ3zxVjL5q5kzcX7NOOMBlIcYAQrFi3iluDUYbpT
JFDEnKE32vCL5f9xq9GKl1a5YJ3MiVDsbekuAEgdMEvkyH1ifKAEwdtO0YJi/uXx
0y1wOlDsnzFHqERG6b8Jxm0AhXbTIAueKtoNgbSV5k0vNQFC4WUbLqVuEAQdrGO5
0tcCrDC+8mxMDoMwBs/Es+q6Hm/KD0QEUj3GwwEZALwMrnvrMl9+qNOGjMn1xFkv
jxhn3ZBUxVQ91zASG1L3oiz/8lRPqTFUc+MjuMIHJDkCgYEA02JFMhaMQzu8ufGf
ht6J3JMRcEKMRik0WvkPKUS7SlffRYj6AGyrFmlb97uRv7fobdHtXdKLS9cj7YgD
Xjty3ylrLL9GBTNXAg791TI8HNbapf2YicvnfMqP07epLMeDlp2ORzyj+wJiOAEH
Bdx0duAepdYN/9DaBVacXKBJjI0CgYEAvzRYO4Y7dVcoi23cw3jTaA1Cmxkn/Q6f
kwIMmBYCFC1goA3Yl8GGT0hlFZyd2+/fz2h1T7Y2r1xadoYeCq5qpvA+4tkuHboU
ABt04u2CoR0+ZXK7SiLzaPMv/HBOblz0kjPzy9OhmzH9YqBzY/Guc137Zfq1V3If
pw1RYXb2INcCgYEAnmPtO3nfweU6Jg5iHboUjR36HCcRWuU3IM+sx5yDxlIPr9fS
lIzYqeNqkTeQH5sbY2bAuOOxkrNzbWHUPEDJc2RitVXhjrYIhTdcheqtVmK71VMv
gFk0bLKPkPH2puIcvLf0S3ap3MTNee9zJrYo4oZPEK5TMRN6ujNK2LEWS2UCgYEA
lK3OYlLpzz+8DleakAFXWpTdEx/HoZaKbVTtmCGc8jWq6ip6Ht9kYigoOlrzwX9Q
aMaQWjCVa10EFyAJIkMoObGdJOa+Xm1AeijfhkosBr5ns5k4m9h7sENSMBjgVB9C
KqHtVLS2+KgxoUylDbVz8s/E2jLOajYa+Np5SrGniDcCgYBE3c8d0qiu8ugKDdHd
zmKk8gnHYzeELNR8f526vMNuhFSDRSWIqh/U3vTHSW85de9AjAdoqnNEeLWQrqXE
yZWXNOy1L7SFlQuOazzfqMSdQjVc69u1ynpDqDpcvYTqxCjyN3vg0lUivwIEnlZb
B+NVKlk8klnh9O7UBmbF17ExCA==
-----END PRIVATE KEY-----`
)
