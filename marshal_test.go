package jwkset_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/MicahParks/jwkset"
)

const (
	ecdsaP256D    = "GpanYiHB-TeCKFmfAwqzIJVhziUH6QX77obHwDPERGo"
	ecdsaP256X    = "IZrURsAt0DcSytZRCBQ4SjCcbIhLLQvg53uSkRdETZ4"
	ecdsaP256Y    = "Uy2iBhx7jMXB4n8fPASCOaNjnUPd8C1toVwytGeAEdU"
	ecdsaP384D    = "P0mnrdElxUwAOcYeRlEz6uUNM6v_Bj4iBB4qxfEQ0xpKiAI5wM1lhzyoXibfWRHo"
	ecdsaP384X    = "qL8wKJLZT5qowOGc8FMYqMWurcdVL15VxHqYV5JmJYj0EjBiPv14iwUrnhEEHVS9"
	ecdsaP384Y    = "5qSWUmTjYNREUNCjDyAxu-ymHUGOtnEzO2z_pxtl5vd4W5Eb_9QcK9E9z3G3Xxjp"
	ecdsaP521D    = "AE4nfzwC69AYJhoJav6VH_rCFodPqcy5Li-6ISmJsLBZwvHX-2S0EYxsPuuk5shfxSFHJbXaD_t85doozgcsV_8t"
	ecdsaP521X    = "ARxti_MdbyBVgT4N-08XzYBx5c8ZUPtZXshNHu_AoMwQqXq0WjZznL5b2175hv8nsUvRshjHpHaj_7SWQl5vH9f0"
	ecdsaP521Y    = "AYx5MdFtiuPA1_IVS0A0z8MhLmQNJOxKd1hnhSRlod1sd7sz17WSXz-DggJwK5gj0qFp9_8dsVvI1Yn688myoImU"
	eddsaPrivate  = "5hT6NTzNJyUCaG7mqtq2ru0EsA2z5SwnnkP0pBycP64"
	eddsaPublic   = "VYk14QSFla7FKnL_okf6TqLIyV2X6DPaDi26UpAMVnM"
	hmacSecret    = "myHMACSecret"
	invalidB64URL = "&"
	myKeyID       = "myKeyID"
	rsa2048D      = "cNNmGwtIladiUlF9v4774vjflIMQvrr-AV-_tHjXK59PY2k4b2HvpKXAoOTn4FAR8fuEeYuMRA-cky5KpBvyXdTxCpPFjI-ZS7QFiTyKk5TmJh73g--ZvyAjjUmsJhL_A02zUD8N2cEP4dKmffSdhe4JO-HVuIHKQCF6TJ_IrrP7IkA5Kji2DZR9_xPiBEele_RkB74TykrClkbXZ-fASt-gdO3e058__j0Ou5LYnzxcnA0vkxarIdqszZ3rHxI2MtqaNobKGJ6R3i9CmjxRKlBw-cDOnFz_L1v7P2QL9szxuGSYCCbKE7d04zc-7GqissY_SRdKM4cJ66SJxin6AQ"
	rsa2048DP     = "AV-vUYbJgrfbtLEc8i4N8k__BsFyiN3OjkqqqjgxJIYViOZPa7QMPwSbqhGTKJE8EzjkJw"
	rsa2048DQ     = "s-ehKBdb1qBJ8b06TOt1u6VK2AqWR_nhXPLhdnqXbHcvWGNv54wI_C0VU8Wt3SA3Jm1h"
	rsa2048E      = "AQAB"
	rsa2048N      = "mE4elfuO41dIwsjUJllqwIsNcr_pvHjnXHColxtL6wwrkcwJ8AOfaW5QJ0KuctXq2EvtkUESZLNKyA4xijsF7XtuEedLgHQheubXOp2YddCTuSiGEqRpWnYaJWDe05PzcWCNAGkXvsWL2Cz-jnjU1VCCnZDwBF5N5sNSXovfm5KVeEGZ1PwkDIc2XHGpjora37CQGh3KboqLDwwF5iRi5M1gTbW_VaGi05jv1fchRhs_6WlcUMJAUJsHLGiMgyj-XirjN3u3zGLFzuM1NkRp9eNijghq3fjkBPFCsGfPnryLwxjs6ZPg98ipFcJUwoqUk1hzOa_iJvAx-nDwnZSEFw"
	rsa2048P      = "AaGvyuF5RegGs6CbARhJhmUdWM_Ye-0M7hyqeEEKKwClJ1ExiJxAKolv6DvtNipXTdZwPw"
	rsa2048Q      = "AcQEclDgR23sTFZHzYka_wKAwC4QPHttlOSt0WAGau3PW5WPaVugh8FndYHGxzi1abU4GQ"
	rsa2048QI     = "DOMVnjENDseMasjhWwfbVSasID0254_t4REMTnoqcfV7m9iBpCT2OjO1AHOSgZc0zkm8"
	rsa2048OthD1  = "ATNJ2PNpn3NXTTtb7TYBcgQZN8jYCwKdKFhzTsLduqaHqjH5-p5okeISJ8osVaRJtJhqIQ"
	rsa2048OthR1  = "A8mD0s9gHYp108OTdGoSJECefSQ7ND0IK6XUzlXVFLU-qmQf5w94JAT6v4X9uuShzdd2SQ"
	rsa2048OthT1  = "AWj6bdr0udGInXeU0mDScIxa84-f2QFBSnbWZjwo6qDqPmk11GNbtOId3WiUAlmloZwWxg"
	rsa2048OthD2  = "AZmpHHucdyCmzCFUO82u9cre3D7lC2dCO0mBi3n1oTilPY7zngl-ZW7DshPtu5DAjiOy5w"
	rsa2048OthR2  = "A5RHuzHITMonYBSxMb0MCyoOcXAUXA3-StaIfxmij3Zc5H06QfA5lZPCdvDf8Jwcrquejw"
	rsa2048OthT2  = "t48pBgBi-seV7vh9tgFw64oiIyw7auLuHRYnUEIN7wHGmSsPl5rUrip3Pe9UKqfNdfJ8"
	rsa2048OthD3  = "AUyP-XN0Gg0GuxL8rDQxthUpUBYM9izNyJ8uX5Bgm1mPGRtkN3qwxYUUTbAeX8lPoEZC_w"
	rsa2048OthR3  = "A-Zy7gnYivX7bW0ZH2GbbZSXoMPcoehJVlBqYJi9v4Am33A8dC71varbLEC8k89Y7Mb75w"
	rsa2048OthT3  = "AssFXSpsj1ZFVjZ_tsJ2yePXdjdgQ-Wj59BcfKpzgJ6YuSEhf6kW4kbMZQULiSeNlckiYw"
)

func TestMarshalECDSA(t *testing.T) {
	checkMarshal := func(marshal jwkset.JWKMarshal, options jwkset.KeyMarshalOptions) {
		// TODO Check ALG.
		if marshal.CRV != jwkset.CrvP256 {
			t.Fatal(`Marshaled parameter "crv" does not match original key.`)
		}
		if options.AsymmetricPrivate {
			if marshal.D != ecdsaP256D {
				t.Fatal(`Marshaled parameter "d" does not match original key.`)
			}
		} else {
			if marshal.D != "" {
				t.Fatal("Asymmetric private key should be unsupported for given options.")
			}
		}
		if marshal.KTY != jwkset.KtyEC {
			t.Fatal(`Marshaled parameter "kty" does not match original key.`)
		}
		if marshal.X != ecdsaP256X {
			t.Fatal(`Marshaled parameter "x" does not match original key.`)
		}
		if marshal.Y != ecdsaP256Y {
			t.Fatal(`Marshaled parameter "y" does not match original key.`)
		}
	}
	private := makeECDSAP256(t)

	meta := jwkset.KeyWithMeta[any]{
		Key: private,
	}

	options := jwkset.KeyMarshalOptions{}
	marshal, err := jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
	checkMarshal(marshal, options)

	options.AsymmetricPrivate = true
	marshal, err = jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
	checkMarshal(marshal, options)

	publicMeta := jwkset.KeyWithMeta[any]{
		Key: private.Public(),
	}
	options.AsymmetricPrivate = false
	marshal, err = jwkset.KeyMarshal(publicMeta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}

	checkMarshal(marshal, options)
}

func TestUnmarshalECDSA(t *testing.T) {
	checkUnmarshal := func(meta jwkset.KeyWithMeta[any], options jwkset.KeyUnmarshalOptions, original *ecdsa.PrivateKey) {
		var public *ecdsa.PublicKey
		var ok bool
		if options.AsymmetricPrivate {
			private, ok := meta.Key.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatal("Unmarshaled key should be a private key.")
			}
			if private.D.Cmp(original.D) != 0 {
				t.Fatal(`Unmarshaled key parameter "d" does not match original key.`)
			}
			public = private.Public().(*ecdsa.PublicKey)
		} else {
			public, ok = meta.Key.(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Unmarshaled key should be a public key.")
			}
		}
		if public.Curve != original.PublicKey.Curve {
			t.Fatal(`Unmarshaled key parameter "crv" does not match original key.`)
		}
		if public.X.Cmp(original.PublicKey.X) != 0 {
			t.Fatal(`Unmarshaled key parameter "x" does not match original key.`)
		}
		if public.Y.Cmp(original.PublicKey.Y) != 0 {
			t.Fatal(`Unmarshaled key parameter "y" does not match original key.`)
		}
	}

	jwk := jwkset.JWKMarshal{
		CRV: jwkset.CrvP256,
		D:   ecdsaP256D,
		KTY: jwkset.KtyEC,
		X:   ecdsaP256X,
		Y:   ecdsaP256Y,
	}

	key := makeECDSAP256(t)
	options := jwkset.KeyUnmarshalOptions{}
	meta, err := jwkset.KeyUnmarshal[any](jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, key)

	options.AsymmetricPrivate = true
	meta, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, key)

	key = makeECDSAP384(t)
	jwk.CRV = jwkset.CrvP384
	jwk.D = ecdsaP384D
	jwk.X = ecdsaP384X
	jwk.Y = ecdsaP384Y
	meta, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, key)

	key = makeECDSAP521(t)
	jwk.CRV = jwkset.CrvP521
	jwk.D = ecdsaP521D
	jwk.X = ecdsaP521X
	jwk.Y = ecdsaP521Y
	meta, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, key)

	jwk.CRV = ""
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "crv" is empty. %s`, err)
	}

	jwk.CRV = "invalid"
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "crv" is invalid. %s`, err)
	}
	jwk.CRV = jwkset.CrvP521

	jwk.D = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "d" is invalid raw Base64 URL. %s`, err)
	}
	jwk.D = ecdsaP521D

	jwk.X = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "x" is invalid raw Base64 URL. %s`, err)
	}
	jwk.X = ecdsaP521X

	jwk.Y = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "y" is invalid raw Base64 URL. %s`, err)
	}
	jwk.Y = ecdsaP521Y
}

func TestMarshalEdDSA(t *testing.T) {
	checkMarshal := func(marshal jwkset.JWKMarshal, options jwkset.KeyMarshalOptions) {
		if marshal.ALG != jwkset.AlgEdDSA {
			t.Fatal(`Marshaled key parameter "alg" does not match original key.`)
		}
		if marshal.CRV != jwkset.CrvEd25519 {
			t.Fatal(`Marshaled key parameter "crv" does not match original key.`)
		}
		if options.AsymmetricPrivate {
			if marshal.D != eddsaPrivate {
				t.Fatal(`Marshaled key parameter "d" does not match original key.`)
			}
		} else {
			if marshal.D != "" {
				t.Fatalf("Asymmetric private key should be unsupported for given options.")
			}
		}
		if marshal.KTY != jwkset.KtyOKP {
			t.Fatal(`Marshaled key parameter "kty" does not match original key.`)
		}
		if marshal.X != eddsaPublic {
			t.Fatal(`Marshaled key parameter "x" does not match original key.`)
		}
	}
	private := makeEdDSA(t)

	meta := jwkset.KeyWithMeta[any]{
		Key: private,
	}

	options := jwkset.KeyMarshalOptions{}
	marshal, err := jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
	checkMarshal(marshal, options)

	options.AsymmetricPrivate = true
	marshal, err = jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
	checkMarshal(marshal, options)

	publicMeta := jwkset.KeyWithMeta[any]{
		Key: private.Public(),
	}
	options.AsymmetricPrivate = false
	marshal, err = jwkset.KeyMarshal(publicMeta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
	checkMarshal(marshal, options)
}

func TestUnmarshalEdDSA(t *testing.T) {
	private := makeEdDSA(t)

	jwk := jwkset.JWKMarshal{
		ALG: jwkset.AlgEdDSA,
		CRV: jwkset.CrvEd25519,
		D:   eddsaPrivate,
		KID: myKeyID,
		KTY: jwkset.KtyOKP,
		X:   eddsaPublic,
	}

	options := jwkset.KeyUnmarshalOptions{}
	meta, err := jwkset.KeyUnmarshal[any](jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	switch meta.Key.(type) {
	case ed25519.PublicKey:
		// Do nothing.
	default:
		t.Fatal("Key type should be public key.")
	}

	options.AsymmetricPrivate = true
	meta, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	if !bytes.Equal(private, meta.Key.(ed25519.PrivateKey)) {
		t.Fatalf("Unmarshaled key does not match original key.")
	}
	if meta.KeyID != myKeyID {
		t.Fatalf("Unmarshaled key ID does not match original key ID.")
	}

	jwk.D = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "d" is invalid raw Base64URL. %s`, err)
	}

	jwk.X = ""
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "x" is empty. %s`, err)
	}

	jwk.X = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "x" is invalid raw Base64URL. %s`, err)
	}

	jwk.CRV = ""
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "crv" is empty. %s`, err)
	}
	jwk.CRV = jwkset.CrvEd25519

	invalidSize := base64.RawURLEncoding.EncodeToString([]byte("invalidSize"))
	jwk.X = invalidSize
	jwk.D = eddsaPrivate
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "x" is invalid size. %s`, err)
	}
	jwk.X = eddsaPublic

	jwk.D = invalidSize
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "d" is invalid size. %s`, err)
	}
}

func TestMarshalOct(t *testing.T) {
	meta := jwkset.KeyWithMeta[any]{
		Key: []byte(hmacSecret),
	}

	options := jwkset.KeyMarshalOptions{}
	_, err := jwkset.KeyMarshal(meta, options)
	if !errors.Is(err, jwkset.ErrUnsupportedKeyType) {
		t.Fatalf("Symmetric key should be unsupported for given options. %s", err)
	}

	options.Symmetric = true
	marshal, err := jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}

	if marshal.K != base64.RawURLEncoding.EncodeToString(meta.Key.([]byte)) {
		t.Fatalf("Unmarshaled key does not match original key.")
	}
	if marshal.KTY != jwkset.KtyOct {
		t.Fatalf("Key type does not match original key.")
	}
}

func TestUnmarshalOct(t *testing.T) {
	jwk := jwkset.JWKMarshal{
		K:   base64.RawURLEncoding.EncodeToString([]byte(hmacSecret)),
		KID: myKeyID,
		KTY: jwkset.KtyOct,
	}

	options := jwkset.KeyUnmarshalOptions{}
	meta, err := jwkset.KeyUnmarshal[any](jwk, options)
	if !errors.Is(err, jwkset.ErrUnsupportedKeyType) {
		t.Fatalf("Symmetric key should be unsupported for given options. %s", err)
	}

	options.Symmetric = true
	meta, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	if !bytes.Equal([]byte(hmacSecret), meta.Key.([]byte)) {
		t.Fatalf("Unmarshaled key does not match original key.")
	}
	if meta.KeyID != myKeyID {
		t.Fatalf("Unmarshaled key ID does not match original key ID.")
	}

	jwk.K = ""
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "k" is empty. %s`, err)
	}

	jwk.K = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "k" is invalid raw Base64URL. %s`, err)
	}
}

func TestMarshalRSA(t *testing.T) {
	private := makeRSA(t)
	checkMarshal := func(marshal jwkset.JWKMarshal, options jwkset.KeyMarshalOptions) {
		// TODO Check ALG.
		if marshal.E != rsa2048E {
			t.Fatal(`Marshal parameter "e" does not match original key.`)
		}
		if marshal.KTY != jwkset.KtyRSA {
			t.Fatal(`Marshal parameter "kty" does not match original key.`)
		}
		if marshal.N != rsa2048N {
			t.Fatal(`Marshal parameter "n" does not match original key.`)
		}
		if options.AsymmetricPrivate {
			if marshal.D != rsa2048D {
				t.Fatal(`Marshal parameter "d" does not match original key.`)
			}
			if marshal.DP != rsa2048DP {
				t.Fatal(`Marshal parameter "dp" does not match original key.`)
			}
			if marshal.DQ != rsa2048DQ {
				t.Fatal(`Marshal parameter "dq" does not match original key.`)
			}
			if marshal.P != rsa2048P {
				t.Fatal(`Marshal parameter "p" does not match original key.`)
			}
			if marshal.Q != rsa2048Q {
				t.Fatal(`Marshal parameter "q" does not match original key.`)
			}
			if marshal.QI != rsa2048QI {
				t.Fatal(`Marshal parameter "qi" does not match original key.`)
			}
			if len(marshal.OTH) != 3 {
				t.Fatal(`Marshal parameter "oth" does not match original key.`)
			}
			if marshal.OTH[0].D != rsa2048OthD1 {
				t.Fatal(`Marshal parameter "d" does not match original key's first multi-prime.`)
			}
			if marshal.OTH[0].R != rsa2048OthR1 {
				t.Fatal(`Marshal parameter "r" does not match original key's first multi-prime.`)
			}
			if marshal.OTH[0].T != rsa2048OthT1 {
				t.Fatal(`Marshal parameter "t" does not match original key's first multi-prime.`)
			}
			if marshal.OTH[1].D != rsa2048OthD2 {
				t.Fatal(`Marshal parameter "d" does not match original key's second multi-prime.`)
			}
			if marshal.OTH[1].R != rsa2048OthR2 {
				t.Fatal(`Marshal parameter "r" does not match original key's second multi-prime.`)
			}
			if marshal.OTH[1].T != rsa2048OthT2 {
				t.Fatal(`Marshal parameter "t" does not match original key's second multi-prime.`)
			}
			if marshal.OTH[2].D != rsa2048OthD3 {
				t.Fatal(`Marshal parameter "d" does not match original key's third multi-prime.`)
			}
			if marshal.OTH[2].R != rsa2048OthR3 {
				t.Fatal(`Marshal parameter "r" does not match original key's third multi-prime.`)
			}
			if marshal.OTH[2].T != rsa2048OthT3 {
				t.Fatal(`Marshal parameter "t" does not match original key's third multi-prime.`)
			}
		} else {
			if marshal.D != "" {
				t.Fatal(`Marshal parameter "d" should be empty.`)
			}
			if marshal.DP != "" {
				t.Fatal(`Marshal parameter "dp" should be empty.`)
			}
			if marshal.DQ != "" {
				t.Fatal(`Marshal parameter "dq" should be empty.`)
			}
			if marshal.P != "" {
				t.Fatal(`Marshal parameter "p" should be empty.`)
			}
			if marshal.Q != "" {
				t.Fatal(`Marshal parameter "q" should be empty.`)
			}
			if marshal.QI != "" {
				t.Fatal(`Marshal parameter "qi" should be empty.`)
			}
			if len(marshal.OTH) != 0 {
				t.Fatal(`Marshal parameter "oth" should be empty.`)
			}
		}
	}

	meta := jwkset.KeyWithMeta[any]{
		Key: private,
	}

	options := jwkset.KeyMarshalOptions{}
	marshal, err := jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
	checkMarshal(marshal, options)

	options.AsymmetricPrivate = true
	marshal, err = jwkset.KeyMarshal(meta, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
	checkMarshal(marshal, options)

	metaPublic := jwkset.KeyWithMeta[any]{
		Key: private.Public(),
	}
	options.AsymmetricPrivate = false
	marshal, err = jwkset.KeyMarshal(metaPublic, options)
	if err != nil {
		t.Fatalf("Failed to marshal key with correct options. %s", err)
	}
	checkMarshal(marshal, options)
}

func TestUnmarshalRSA(t *testing.T) {
	checkUnmarshal := func(meta jwkset.KeyWithMeta[any], options jwkset.KeyUnmarshalOptions, original *rsa.PrivateKey) {
		var public *rsa.PublicKey
		var ok bool
		if options.AsymmetricPrivate {
			private, ok := meta.Key.(*rsa.PrivateKey)
			if !ok {
				t.Fatal("Unmarshaled key should be a private key.")
			}
			if private.D.Cmp(original.D) != 0 {
				t.Fatal(`Unmarshaled key parameter "d" does not match original key.`)
			}
			if private.Primes[0].Cmp(original.Primes[0]) != 0 {
				t.Fatal(`Unmarshaled key parameter "p" does not match original key.`)
			}
			if private.Primes[1].Cmp(original.Primes[1]) != 0 {
				t.Fatal(`Unmarshaled key parameter "q" does not match original key.`)
			}
			if private.Precomputed.Dp.Cmp(original.Precomputed.Dp) != 0 {
				t.Fatal(`Unmarshaled key parameter "dp" does not match original key.`)
			}
			if private.Precomputed.Dq.Cmp(original.Precomputed.Dq) != 0 {
				t.Fatal(`Unmarshaled key parameter "dq" does not match original key.`)
			}
			if private.Precomputed.Qinv.Cmp(original.Precomputed.Qinv) != 0 {
				t.Fatal(`Unmarshaled key parameter "qi" does not match original key.`)
			}
			if len(private.Precomputed.CRTValues) != len(original.Precomputed.CRTValues) {
				t.Fatal(`Unmarshaled key parameter "oth" does not match original key.`)
			}
			for i, crt := range private.Precomputed.CRTValues {
				if crt.Coeff.Cmp(original.Precomputed.CRTValues[i].Coeff) != 0 {
					t.Fatal(`Unmarshaled key parameter "oth" coeff does not match original key.`)
				}
				if crt.Exp.Cmp(original.Precomputed.CRTValues[i].Exp) != 0 {
					t.Fatal(`Unmarshaled key parameter "oth" exp does not match original key.`)
				}
			}
			public = private.Public().(*rsa.PublicKey)
		} else {
			public, ok = meta.Key.(*rsa.PublicKey)
			if !ok {
				t.Fatal("Unmarshaled key should be a public key.")
			}
		}
		if public.N.Cmp(original.N) != 0 {
			t.Fatal(`Unmarshaled key parameter "n" does not match original key.`)
		}
		if public.E != original.E {
			t.Fatal(`Unmarshaled key parameter "e" does not match original key.`)
		}
	}
	private := makeRSA(t)

	jwk := jwkset.JWKMarshal{
		E:   rsa2048E,
		D:   rsa2048D,
		DP:  rsa2048DP,
		DQ:  rsa2048DQ,
		KTY: jwkset.KtyRSA,
		N:   rsa2048N,
		P:   rsa2048P,
		Q:   rsa2048Q,
		QI:  rsa2048QI,
		OTH: []jwkset.OtherPrimes{
			{
				D: rsa2048OthD1,
				R: rsa2048OthR1,
				T: rsa2048OthT1,
			},
			{
				D: rsa2048OthD2,
				R: rsa2048OthR2,
				T: rsa2048OthT2,
			},
			{
				D: rsa2048OthD3,
				R: rsa2048OthR3,
				T: rsa2048OthT3,
			},
		},
	}

	options := jwkset.KeyUnmarshalOptions{}
	meta, err := jwkset.KeyUnmarshal[any](jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, private)

	options.AsymmetricPrivate = true
	meta, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, private)

	jwk.N = ""
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatal(`Should get error when parameter "n" is empty.`)
	}

	jwk.N = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "n" is invalid raw Base64 URL. %s`, err)
	}
	jwk.N = rsa2048N

	jwk.E = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "e" is invalid raw Base64 URL. %s`, err)
	}
	jwk.E = rsa2048E

	jwk.D = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "d" is invalid raw Base64 URL. %s`, err)
	}
	jwk.D = rsa2048D

	jwk.DP = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "dp" is invalid raw Base64 URL. %s`, err)
	}
	jwk.DP = rsa2048DP

	jwk.DQ = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "dq" is invalid raw Base64 URL. %s`, err)
	}
	jwk.DQ = rsa2048DQ

	jwk.P = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "p" is invalid raw Base64 URL. %s`, err)
	}
	jwk.P = rsa2048P

	jwk.Q = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "q" is invalid raw Base64 URL. %s`, err)
	}
	jwk.Q = rsa2048Q

	jwk.QI = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "qi" is invalid raw Base64 URL. %s`, err)
	}
	jwk.QI = rsa2048QI

	jwk.OTH[0].D = ""
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get error when parameter "oth" "d" is empty. %s`, err)
	}

	jwk.OTH[0].D = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "oth" "d"" is invalid raw Base64 URL. %s`, err)
	}
	jwk.OTH[0].D = rsa2048OthD1

	jwk.OTH[0].R = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "oth" "r"" is invalid raw Base64 URL. %s`, err)
	}
	jwk.OTH[0].R = rsa2048OthR1

	jwk.OTH[0].T = invalidB64URL
	_, err = jwkset.KeyUnmarshal[any](jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "oth" "t"" is invalid raw Base64 URL. %s`, err)
	}
	jwk.OTH[0].T = rsa2048OthT1
}

func TestMarshalUnsupported(t *testing.T) {
	meta := jwkset.KeyWithMeta[any]{
		Key: "unsupported",
	}

	options := jwkset.KeyMarshalOptions{}
	_, err := jwkset.KeyMarshal(meta, options)
	if !errors.Is(err, jwkset.ErrUnsupportedKeyType) {
		t.Fatalf("Unsupported key type should be unsupported for given options. %s", err)
	}
}

func TestUnmarshalUnsupported(t *testing.T) {
	jwk := jwkset.JWKMarshal{
		KTY: "unsupported",
	}

	options := jwkset.KeyUnmarshalOptions{}
	_, err := jwkset.KeyUnmarshal[any](jwk, options)
	if !errors.Is(err, jwkset.ErrUnsupportedKeyType) {
		t.Fatalf("Unsupported key type should return ErrUnsupportedKeyType. %s", err)
	}
}

func makeECDSAP256(t *testing.T) *ecdsa.PrivateKey {
	d, err := base64.RawURLEncoding.DecodeString(ecdsaP256D)
	if err != nil {
		t.Fatalf("Failed to decode private key. %s", err)
	}
	x, err := base64.RawURLEncoding.DecodeString(ecdsaP256X)
	if err != nil {
		t.Fatalf("Failed to decode x coordinate. %s", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(ecdsaP256Y)
	if err != nil {
		t.Fatalf("Failed to decode y coordinate. %s", err)
	}
	privateP256 := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		D: new(big.Int).SetBytes(d),
	}
	return privateP256
}

func makeECDSAP384(t *testing.T) *ecdsa.PrivateKey {
	d, err := base64.RawURLEncoding.DecodeString(ecdsaP384D)
	if err != nil {
		t.Fatalf("Failed to decode private key. %s", err)
	}
	x, err := base64.RawURLEncoding.DecodeString(ecdsaP384X)
	if err != nil {
		t.Fatalf("Failed to decode x coordinate. %s", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(ecdsaP384Y)
	if err != nil {
		t.Fatalf("Failed to decode y coordinate. %s", err)
	}
	privateP256 := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		D: new(big.Int).SetBytes(d),
	}
	return privateP256
}

func makeECDSAP521(t *testing.T) *ecdsa.PrivateKey {
	d, err := base64.RawURLEncoding.DecodeString(ecdsaP521D)
	if err != nil {
		t.Fatalf("Failed to decode private key. %s", err)
	}
	x, err := base64.RawURLEncoding.DecodeString(ecdsaP521X)
	if err != nil {
		t.Fatalf("Failed to decode x coordinate. %s", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(ecdsaP521Y)
	if err != nil {
		t.Fatalf("Failed to decode y coordinate. %s", err)
	}
	privateP256 := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		D: new(big.Int).SetBytes(d),
	}
	return privateP256
}

func makeEdDSA(t *testing.T) ed25519.PrivateKey {
	privateBytes, err := base64.RawURLEncoding.DecodeString(eddsaPrivate)
	if err != nil {
		t.Fatalf("Failed to decode private key. %s", err)
	}
	publicBytes, err := base64.RawURLEncoding.DecodeString(eddsaPublic)
	if err != nil {
		t.Fatalf("Failed to decode public key. %s", err)
	}
	private := ed25519.PrivateKey(append(privateBytes, publicBytes...))
	return private
}

func makeRSA(t *testing.T) *rsa.PrivateKey {
	d, err := base64.RawURLEncoding.DecodeString(rsa2048D)
	if err != nil {
		t.Fatalf(`Failed to decode "d" parameter. %s`, err)
	}
	dp, err := base64.RawURLEncoding.DecodeString(rsa2048DP)
	if err != nil {
		t.Fatalf(`Failed to decode "dp" parameter. %s`, err)
	}
	dq, err := base64.RawURLEncoding.DecodeString(rsa2048DQ)
	if err != nil {
		t.Fatalf(`Failed to decode "dq" parameter. %s`, err)
	}
	e, err := base64.RawURLEncoding.DecodeString(rsa2048E)
	if err != nil {
		t.Fatalf(`Failed to decode "e" parameter. %s`, err)
	}
	n, err := base64.RawURLEncoding.DecodeString(rsa2048N)
	if err != nil {
		t.Fatalf(`Failed to decode "n" parameter. %s`, err)
	}
	p, err := base64.RawURLEncoding.DecodeString(rsa2048P)
	if err != nil {
		t.Fatalf(`Failed to decode "p" parameter. %s`, err)
	}
	q, err := base64.RawURLEncoding.DecodeString(rsa2048Q)
	if err != nil {
		t.Fatalf(`Failed to decode "q" parameter. %s`, err)
	}
	qi, err := base64.RawURLEncoding.DecodeString(rsa2048QI)
	if err != nil {
		t.Fatalf(`Failed to decode "qi" parameter. %s`, err)
	}
	othD1, err := base64.RawURLEncoding.DecodeString(rsa2048OthD1)
	if err != nil {
		t.Fatalf(`Failed to decode "othD1" parameter. %s`, err)
	}
	othR1, err := base64.RawURLEncoding.DecodeString(rsa2048OthR1)
	if err != nil {
		t.Fatalf(`Failed to decode "othR1" parameter. %s`, err)
	}
	othT1, err := base64.RawURLEncoding.DecodeString(rsa2048OthT1)
	if err != nil {
		t.Fatalf(`Failed to decode "othT1" parameter. %s`, err)
	}
	othD2, err := base64.RawURLEncoding.DecodeString(rsa2048OthD2)
	if err != nil {
		t.Fatalf(`Failed to decode "othD2" parameter. %s`, err)
	}
	othR2, err := base64.RawURLEncoding.DecodeString(rsa2048OthR2)
	if err != nil {
		t.Fatalf(`Failed to decode "othR2" parameter. %s`, err)
	}
	othT2, err := base64.RawURLEncoding.DecodeString(rsa2048OthT2)
	if err != nil {
		t.Fatalf(`Failed to decode "othT2" parameter. %s`, err)
	}
	othD3, err := base64.RawURLEncoding.DecodeString(rsa2048OthD3)
	if err != nil {
		t.Fatalf(`Failed to decode "othD3" parameter. %s`, err)
	}
	othR3, err := base64.RawURLEncoding.DecodeString(rsa2048OthR3)
	if err != nil {
		t.Fatalf(`Failed to decode "othR3" parameter. %s`, err)
	}
	othT3, err := base64.RawURLEncoding.DecodeString(rsa2048OthT3)
	if err != nil {
		t.Fatalf(`Failed to decode "othT3" parameter. %s`, err)
	}
	private := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		},
		D:      new(big.Int).SetBytes(d),
		Primes: []*big.Int{new(big.Int).SetBytes(p), new(big.Int).SetBytes(q), new(big.Int).SetBytes(othR1), new(big.Int).SetBytes(othR2), new(big.Int).SetBytes(othR3)},
		Precomputed: rsa.PrecomputedValues{
			Dp:   new(big.Int).SetBytes(dp),
			Dq:   new(big.Int).SetBytes(dq),
			Qinv: new(big.Int).SetBytes(qi),
			CRTValues: []rsa.CRTValue{
				{
					Exp:   new(big.Int).SetBytes(othD1),
					Coeff: new(big.Int).SetBytes(othT1),
				},
				{
					Exp:   new(big.Int).SetBytes(othD2),
					Coeff: new(big.Int).SetBytes(othT2),
				},
				{
					Exp:   new(big.Int).SetBytes(othD3),
					Coeff: new(big.Int).SetBytes(othT3),
				},
			},
		},
	}
	return private
}
