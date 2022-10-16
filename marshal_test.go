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
	ecdsaP256D     = "GpanYiHB-TeCKFmfAwqzIJVhziUH6QX77obHwDPERGo"
	ecdsaP256X     = "IZrURsAt0DcSytZRCBQ4SjCcbIhLLQvg53uSkRdETZ4"
	ecdsaP256Y     = "Uy2iBhx7jMXB4n8fPASCOaNjnUPd8C1toVwytGeAEdU"
	ecdsaP384D     = "P0mnrdElxUwAOcYeRlEz6uUNM6v_Bj4iBB4qxfEQ0xpKiAI5wM1lhzyoXibfWRHo"
	ecdsaP384X     = "qL8wKJLZT5qowOGc8FMYqMWurcdVL15VxHqYV5JmJYj0EjBiPv14iwUrnhEEHVS9"
	ecdsaP384Y     = "5qSWUmTjYNREUNCjDyAxu-ymHUGOtnEzO2z_pxtl5vd4W5Eb_9QcK9E9z3G3Xxjp"
	ecdsaP521D     = "AE4nfzwC69AYJhoJav6VH_rCFodPqcy5Li-6ISmJsLBZwvHX-2S0EYxsPuuk5shfxSFHJbXaD_t85doozgcsV_8t"
	ecdsaP521X     = "ARxti_MdbyBVgT4N-08XzYBx5c8ZUPtZXshNHu_AoMwQqXq0WjZznL5b2175hv8nsUvRshjHpHaj_7SWQl5vH9f0"
	ecdsaP521Y     = "AYx5MdFtiuPA1_IVS0A0z8MhLmQNJOxKd1hnhSRlod1sd7sz17WSXz-DggJwK5gj0qFp9_8dsVvI1Yn688myoImU"
	eddsaPrivate   = "5hT6NTzNJyUCaG7mqtq2ru0EsA2z5SwnnkP0pBycP64"
	eddsaPublic    = "VYk14QSFla7FKnL_okf6TqLIyV2X6DPaDi26UpAMVnM"
	hmacSecret     = "myHMACSecret"
	invalidB64URL  = "&"
	myKeyID        = "myKeyID"
	rsa2048RS256D  = "d_cI2SZFrrjn5mJ4dz-SMKw73EhWk-F0q69mhQZOQTC3JdSuBffqAZow6uyJ2kxyhJyu6bSxHM6Crmpf8DiQ1xnST25N9AxLRvHnG4uCm1c8D_Pxi7S19c7H9UqUZp_mHznQ8g8zfBgBl936Hi8EtvzlqmrTXfeccU-5Iieqqq1eMCwSDeBxyNzWhqwytreoSSO8KkIQmtrVPKc2w5qoUhEAv_f2eTGEcCX9J4GuXeFAWqXb3_sWzAaVzMShXDrLmAORebl1105lI3yQoJigst7xGqunsjQ6VcKQ6EZpIypwqUaQTqyup14roNlNbgSIaW-GJJWzy8-GzaamnWBvkQ"
	rsa2048RS256DP = "SoKY6vHD0-KI5tYD9HG0vYHi7lieP3Wqu7Hk_v5lvx31REIBGhHtE25Pae_qjLx35IMbmbzH_MpWe50TfrN8mhnDxO2D2TttbWwKw_B_mQ3mayCPAZb-MwQmnBrrjGJVfaJ1Le9Zfo-3XGrcKDzQ1mNI6MCv3qcdoqawfS0RdpE"
	rsa2048RS256DQ = "C_2JqWBA6z0c9oVEiAJ3D3O92SisHj2c7fjUrC1ZnRaj-A3Y-Fh772oKGp09CwU1n31kqtKIHhGMOodpvb4aNyy15rwNjp4TAkxvTfUyO0z3Xox95rghB8fuGjSDZgFlSUXFSYw3mBKj4IGwbDrevE4W1VaYzxZ81qkO2upTxik"
	rsa2048RS256E  = "AQAB"
	rsa2048RS256N  = "ndE98WGJceW0C9oMxfv1RYoEoKMONvv7_2d-nA5yQvudACH58y8KIYvmFgrQ2f7k7KoBqBsGBR3AHtEtjXNZTHei5KJpJmXN9zVm1TqFNbq_bECCO8j2dxky8gvJXxkxmsRm9V0XJsDlJPx26ROyNddjFLtoTzvLy6XRaXCnqDzBZV4XBF6xQDipPA3U0jAamybsZN6ydKLqhGUlEOH4ZUkSHzSCazfqN6o4iUceFMQoqzpmkGDYRp96o9xx3NFo5ND-RSTEBEDYdOAvtZInHKqltQuT_Mj98GqczxvV5Jaw4mJMC8mWUE2UHFdFAkdL80Tt74HCk-mKMaBW1CkwMw"
	rsa2048RS256P  = "70b-D_1gG8b1lJviBn5b6c4HoTYMJMc6UnKcj79uqHA_2ihouBXEDmSW1Vd2rOVDjLt13_4Du5arrY3877rl-nXJl6YxqK8ZTLAfG_Bjq3i3wkUres6F_wakyFLJZjuiEcMFUtkOUwHHwQGc4-nV5Fq1yiFs39_XLbb7iFlMAz8"
	rsa2048RS256Q  = "qNjQ9vlqWsMsiPqOpZ_MLetjnHeLU5hSfKGk9vrtir2AF9zaKouDBQ8nwCgGnXE9GHqQIPW14mNbpRwRchMj0w5AN43Smf9t7GMZi2nz7QieK_9dW4hKzcblmrZFAbGhwXX28QLQKQw1a1lFhhEa6GSBH6cB9oANC2-Gw6r_eg0"
	rsa2048RS256QI = "xcDoI05jRx-eRfQ6XoKTA360XdK3yc6hVm3ysgyGiEAhBS7xuGy0KSXeX6M-W7ir37CYGxcm4UkfoT4JFGISttu89C1LaQUTmDzJzgOTvFmlHuhvn0mZkTAhzsnQtnKihFdNtekU6DAb4JSMgwJU-rd4xajPfdxgp2okYYl2QOE"
)

func TestMarshalECDSA(t *testing.T) {
	checkMarshal := func(marshal jwkset.JWKMarshal, options jwkset.KeyMarshalOptions) {
		// TODO Check ALG.
		if marshal.CRV != jwkset.CurveP256 {
			t.Fatal(`Marshalled parameter "crv" does not match original key.`)
		}
		if options.AsymmetricPrivate {
			if marshal.D != ecdsaP256D {
				t.Fatal(`Marshalled parameter "d" does not match original key.`)
			}
		} else {
			if marshal.D != "" {
				t.Fatal("Asymmetric private key should be unsupported for given options.")
			}
		}
		if marshal.KTY != jwkset.KeyTypeEC {
			t.Fatal(`Marshalled parameter "kty" does not match original key.`)
		}
		if marshal.X != ecdsaP256X {
			t.Fatal(`Marshalled parameter "x" does not match original key.`)
		}
		if marshal.Y != ecdsaP256Y {
			t.Fatal(`Marshalled parameter "y" does not match original key.`)
		}
	}
	private := makeECDSAP256(t)

	meta := jwkset.KeyWithMeta{
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

	publicMeta := jwkset.KeyWithMeta{
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
	checkUnmarshal := func(meta jwkset.KeyWithMeta, options jwkset.KeyUnmarshalOptions, original *ecdsa.PrivateKey) {
		var public *ecdsa.PublicKey
		var ok bool
		if options.AsymmetricPrivate {
			private, ok := meta.Key.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatal("Unmarshalled key should be a private key.")
			}
			if private.D.Cmp(original.D) != 0 {
				t.Fatal(`Unmarshalled key parameter "d" does not match original key.`)
			}
			public = private.Public().(*ecdsa.PublicKey)
		} else {
			public, ok = meta.Key.(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("Unmarshalled key should be a public key.")
			}
		}
		if public.Curve != original.PublicKey.Curve {
			t.Fatal(`Unmarshalled key parameter "crv" does not match original key.`)
		}
		if public.X.Cmp(original.PublicKey.X) != 0 {
			t.Fatal(`Unmarshalled key parameter "x" does not match original key.`)
		}
		if public.Y.Cmp(original.PublicKey.Y) != 0 {
			t.Fatal(`Unmarshalled key parameter "y" does not match original key.`)
		}
	}

	jwk := jwkset.JWKMarshal{
		CRV: jwkset.CurveP256,
		D:   ecdsaP256D,
		KTY: jwkset.KeyTypeEC,
		X:   ecdsaP256X,
		Y:   ecdsaP256Y,
	}

	key := makeECDSAP256(t)
	options := jwkset.KeyUnmarshalOptions{}
	meta, err := jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, key)

	options.AsymmetricPrivate = true
	meta, err = jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, key)

	key = makeECDSAP384(t)
	jwk.CRV = jwkset.CurveP384
	jwk.D = ecdsaP384D
	jwk.X = ecdsaP384X
	jwk.Y = ecdsaP384Y
	meta, err = jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, key)

	key = makeECDSAP521(t)
	jwk.CRV = jwkset.CurveP521
	jwk.D = ecdsaP521D
	jwk.X = ecdsaP521X
	jwk.Y = ecdsaP521Y
	meta, err = jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, key)

	jwk.CRV = ""
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "crv" is empty. %s`, err)
	}

	jwk.CRV = "invalid"
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "crv" is invalid. %s`, err)
	}
	jwk.CRV = jwkset.CurveP521

	jwk.D = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "d" is invalid raw Base64 URL. %s`, err)
	}
	jwk.D = ecdsaP521D

	jwk.X = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "x" is invalid raw Base64 URL. %s`, err)
	}
	jwk.X = ecdsaP521X

	jwk.Y = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "y" is invalid raw Base64 URL. %s`, err)
	}
	jwk.Y = ecdsaP521Y
}

func TestMarshalEdDSA(t *testing.T) {
	checkMarshal := func(marshal jwkset.JWKMarshal, options jwkset.KeyMarshalOptions) {
		// TODO Check ALG.
		if marshal.CRV != jwkset.CurveEd25519 {
			t.Fatal(`Marshalled key parameter "crv" does not match original key.`)
		}
		if options.AsymmetricPrivate {
			if marshal.D != eddsaPrivate {
				t.Fatal(`Marshalled key parameter "d" does not match original key.`)
			}
		} else {
			if marshal.D != "" {
				t.Fatalf("Asymmetric private key should be unsupported for given options.")
			}
		}
		if marshal.KTY != jwkset.KeyTypeOKP {
			t.Fatal(`Marshalled key parameter "kty" does not match original key.`)
		}
		if marshal.X != eddsaPublic {
			t.Fatal(`Marshalled key parameter "x" does not match original key.`)
		}
	}
	private := makeEdDSA(t)

	meta := jwkset.KeyWithMeta{
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

	publicMeta := jwkset.KeyWithMeta{
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
		CRV: jwkset.CurveEd25519,
		D:   eddsaPrivate,
		KID: myKeyID,
		KTY: jwkset.KeyTypeOKP,
		X:   eddsaPublic,
	}

	options := jwkset.KeyUnmarshalOptions{}
	meta, err := jwkset.KeyUnmarshal(jwk, options)
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
	meta, err = jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	if !bytes.Equal(private, meta.Key.(ed25519.PrivateKey)) {
		t.Fatalf("Unmarshalled key does not match original key.")
	}
	if meta.KeyID != myKeyID {
		t.Fatalf("Unmarshalled key ID does not match original key ID.")
	}

	jwk.D = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "d" is invalid raw Base64URL. %s`, err)
	}

	jwk.X = ""
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "x" is empty. %s`, err)
	}

	jwk.X = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "x" is invalid raw Base64URL. %s`, err)
	}

	jwk.CRV = ""
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "crv" is empty. %s`, err)
	}
	jwk.CRV = jwkset.CurveEd25519

	invalidSize := base64.RawURLEncoding.EncodeToString([]byte("invalidSize"))
	jwk.X = invalidSize
	jwk.D = eddsaPrivate
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "x" is invalid size. %s`, err)
	}
	jwk.X = eddsaPublic

	jwk.D = invalidSize
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "d" is invalid size. %s`, err)
	}
}

func TestMarshalOct(t *testing.T) {
	meta := jwkset.KeyWithMeta{
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
		t.Fatalf("Unmarshalled key does not match original key.")
	}
	if marshal.KTY != jwkset.KeyTypeOct {
		t.Fatalf("Key type does not match original key.")
	}
}

func TestUnmarshalOct(t *testing.T) {
	jwk := jwkset.JWKMarshal{
		K:   base64.RawURLEncoding.EncodeToString([]byte(hmacSecret)),
		KID: myKeyID,
		KTY: jwkset.KeyTypeOct,
	}

	options := jwkset.KeyUnmarshalOptions{}
	meta, err := jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrUnsupportedKeyType) {
		t.Fatalf("Symmetric key should be unsupported for given options. %s", err)
	}

	options.Symmetric = true
	meta, err = jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	if !bytes.Equal([]byte(hmacSecret), meta.Key.([]byte)) {
		t.Fatalf("Unmarshalled key does not match original key.")
	}
	if meta.KeyID != myKeyID {
		t.Fatalf("Unmarshalled key ID does not match original key ID.")
	}

	jwk.K = ""
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if !errors.Is(err, jwkset.ErrKeyUnmarshalParameter) {
		t.Fatalf(`Should get ErrKeyUnmarshalParameter when parameter "k" is empty. %s`, err)
	}

	jwk.K = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "k" is invalid raw Base64URL. %s`, err)
	}
}

func TestMarshalRSA(t *testing.T) {
	private := makeRSA(t)
	checkMarshal := func(marshal jwkset.JWKMarshal, options jwkset.KeyMarshalOptions) {
		// TODO Check ALG.
		if marshal.E != rsa2048RS256E {
			t.Fatal(`Marshall parameter "e" does not match original key.`)
		}
		if marshal.KTY != jwkset.KeyTypeRSA {
			t.Fatal(`Marshall parameter "kty" does not match original key.`)
		}
		if marshal.N != rsa2048RS256N {
			t.Fatal(`Marshall parameter "n" does not match original key.`)
		}
		if options.AsymmetricPrivate {
			if marshal.D != rsa2048RS256D {
				t.Fatal(`Marshall parameter "d" does not match original key.`)
			}
			if marshal.DP != rsa2048RS256DP {
				t.Fatal(`Marshall parameter "dp" does not match original key.`)
			}
			if marshal.DQ != rsa2048RS256DQ {
				t.Fatal(`Marshall parameter "dq" does not match original key.`)
			}
			if marshal.P != rsa2048RS256P {
				t.Fatal(`Marshall parameter "p" does not match original key.`)
			}
			if marshal.Q != rsa2048RS256Q {
				t.Fatal(`Marshall parameter "q" does not match original key.`)
			}
			if marshal.QI != rsa2048RS256QI {
				t.Fatal(`Marshall parameter "qi" does not match original key.`)
			}
		} else {
			if marshal.D != "" {
				t.Fatal(`Marshall parameter "d" should be empty.`)
			}
			if marshal.DP != "" {
				t.Fatal(`Marshall parameter "dp" should be empty.`)
			}
			if marshal.DQ != "" {
				t.Fatal(`Marshall parameter "dq" should be empty.`)
			}
			if marshal.P != "" {
				t.Fatal(`Marshall parameter "p" should be empty.`)
			}
			if marshal.Q != "" {
				t.Fatal(`Marshall parameter "q" should be empty.`)
			}
			if marshal.QI != "" {
				t.Fatal(`Marshall parameter "qi" should be empty.`)
			}
		}
	}

	meta := jwkset.KeyWithMeta{
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

	// TODO Tests for multi-prime keys.
}

func TestUnmarshalRSA(t *testing.T) {
	checkUnmarshal := func(meta jwkset.KeyWithMeta, options jwkset.KeyUnmarshalOptions, original *rsa.PrivateKey) {
		var public *rsa.PublicKey
		var ok bool
		if options.AsymmetricPrivate {
			private, ok := meta.Key.(*rsa.PrivateKey)
			if !ok {
				t.Fatal("Unmarshalled key should be a private key.")
			}
			if private.D.Cmp(original.D) != 0 {
				t.Fatal(`Unmarshalled key parameter "d" does not match original key.`)
			}
			if private.Primes[0].Cmp(original.Primes[0]) != 0 {
				t.Fatal(`Unmarshalled key parameter "p" does not match original key.`)
			}
			if private.Primes[1].Cmp(original.Primes[1]) != 0 {
				t.Fatal(`Unmarshalled key parameter "q" does not match original key.`)
			}
			if private.Precomputed.Dp.Cmp(original.Precomputed.Dp) != 0 {
				t.Fatal(`Unmarshalled key parameter "dp" does not match original key.`)
			}
			if private.Precomputed.Dq.Cmp(original.Precomputed.Dq) != 0 {
				t.Fatal(`Unmarshalled key parameter "dq" does not match original key.`)
			}
			if private.Precomputed.Qinv.Cmp(original.Precomputed.Qinv) != 0 {
				t.Fatal(`Unmarshalled key parameter "qi" does not match original key.`)
			}
			public = private.Public().(*rsa.PublicKey)
		} else {
			public, ok = meta.Key.(*rsa.PublicKey)
			if !ok {
				t.Fatal("Unmarshalled key should be a public key.")
			}
		}
		if public.N.Cmp(original.N) != 0 {
			t.Fatal(`Unmarshalled key parameter "n" does not match original key.`)
		}
		if public.E != original.E {
			t.Fatal(`Unmarshalled key parameter "e" does not match original key.`)
		}
	}
	private := makeRSA(t)

	jwk := jwkset.JWKMarshal{
		E:   rsa2048RS256E,
		D:   rsa2048RS256D,
		DP:  rsa2048RS256DP,
		DQ:  rsa2048RS256DQ,
		KTY: jwkset.KeyTypeRSA,
		N:   rsa2048RS256N,
		P:   rsa2048RS256P,
		Q:   rsa2048RS256Q,
		QI:  rsa2048RS256QI,
	}

	options := jwkset.KeyUnmarshalOptions{}
	meta, err := jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, private)

	options.AsymmetricPrivate = true
	meta, err = jwkset.KeyUnmarshal(jwk, options)
	if err != nil {
		t.Fatalf("Failed to unmarshal key with correct options. %s", err)
	}
	checkUnmarshal(meta, options, private)

	jwk.N = ""
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatal(`Should get error when parameter "n" is empty.`)
	}

	jwk.N = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "n" is invalid raw Base64 URL. %s`, err)
	}
	jwk.N = rsa2048RS256N

	jwk.E = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "e" is invalid raw Base64 URL. %s`, err)
	}
	jwk.E = rsa2048RS256E

	jwk.D = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "d" is invalid raw Base64 URL. %s`, err)
	}
	jwk.D = rsa2048RS256D

	jwk.DP = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "dp" is invalid raw Base64 URL. %s`, err)
	}
	jwk.DP = rsa2048RS256DP

	jwk.DQ = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "dq" is invalid raw Base64 URL. %s`, err)
	}
	jwk.DQ = rsa2048RS256DQ

	jwk.P = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "p" is invalid raw Base64 URL. %s`, err)
	}
	jwk.P = rsa2048RS256P

	jwk.Q = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "q" is invalid raw Base64 URL. %s`, err)
	}
	jwk.Q = rsa2048RS256Q

	jwk.QI = invalidB64URL
	_, err = jwkset.KeyUnmarshal(jwk, options)
	if err == nil {
		t.Fatalf(`Should get error when parameter "qi" is invalid raw Base64 URL. %s`, err)
	}
	jwk.QI = rsa2048RS256QI

	// TODO Tests for multi-prime keys.
}

func TestMarshalUnsupported(t *testing.T) {
	meta := jwkset.KeyWithMeta{
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
	_, err := jwkset.KeyUnmarshal(jwk, options)
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
	d, err := base64.RawURLEncoding.DecodeString(rsa2048RS256D)
	if err != nil {
		t.Fatalf(`Failed to decode "d" parameter. %s`, err)
	}
	dp, err := base64.RawURLEncoding.DecodeString(rsa2048RS256DP)
	if err != nil {
		t.Fatalf(`Failed to decode "dp" parameter. %s`, err)
	}
	dq, err := base64.RawURLEncoding.DecodeString(rsa2048RS256DQ)
	if err != nil {
		t.Fatalf(`Failed to decode "dq" parameter. %s`, err)
	}
	e, err := base64.RawURLEncoding.DecodeString(rsa2048RS256E)
	if err != nil {
		t.Fatalf(`Failed to decode "e" parameter. %s`, err)
	}
	n, err := base64.RawURLEncoding.DecodeString(rsa2048RS256N)
	if err != nil {
		t.Fatalf(`Failed to decode "n" parameter. %s`, err)
	}
	p, err := base64.RawURLEncoding.DecodeString(rsa2048RS256P)
	if err != nil {
		t.Fatalf(`Failed to decode "p" parameter. %s`, err)
	}
	q, err := base64.RawURLEncoding.DecodeString(rsa2048RS256Q)
	if err != nil {
		t.Fatalf(`Failed to decode "q" parameter. %s`, err)
	}
	qi, err := base64.RawURLEncoding.DecodeString(rsa2048RS256QI)
	if err != nil {
		t.Fatalf(`Failed to decode "qi" parameter. %s`, err)
	}
	private := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		},
		D:      new(big.Int).SetBytes(d),
		Primes: []*big.Int{new(big.Int).SetBytes(p), new(big.Int).SetBytes(q)},
		Precomputed: rsa.PrecomputedValues{
			Dp:        new(big.Int).SetBytes(dp),
			Dq:        new(big.Int).SetBytes(dq),
			Qinv:      new(big.Int).SetBytes(qi),
			CRTValues: []rsa.CRTValue{},
		},
	}
	return private
}
