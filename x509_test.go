package jwkset_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"testing"

	"github.com/MicahParks/jwkset"
)

func TestLoadCertificates(t *testing.T) {
	b := append(append([]byte(ec521Cert), []byte(ed25519Cert)...), []byte(rsa4096Cert)...)
	certs, err := jwkset.LoadCertificates(b)
	if err != nil {
		t.Fatal("Failed to load certificates:", err)
	}
	if len(certs) != 3 {
		t.Fatal("Wrong number of certificates loaded:", len(certs))
	}
	_ = certs[0].PublicKey.(*ecdsa.PublicKey)
	_ = certs[1].PublicKey.(ed25519.PublicKey)
	_ = certs[2].PublicKey.(*rsa.PublicKey)
}

func TestLoadX509KeyInfer(t *testing.T) {
	b := loadPEM(t, ec521Pub)
	key, err := jwkset.LoadX509KeyInfer(b)
	if err != nil {
		t.Fatal("Failed to load public EC 521 X509 key:", err)
	}
	_ = key.(*ecdsa.PublicKey)

	b = loadPEM(t, ed25519Pub)
	key, err = jwkset.LoadX509KeyInfer(b)
	if err != nil {
		t.Fatal("Failed to load public EdDSA X509 key:", err)
	}
	_ = key.(ed25519.PublicKey)

	b = loadPEM(t, rsa4096Pub)
	key, err = jwkset.LoadX509KeyInfer(b)
	if err != nil {
		t.Fatal("Failed to load public RSA 4096 X509 key:", err)
	}
	_ = key.(*rsa.PublicKey)

	b = loadPEM(t, ec521Priv)
	key, err = jwkset.LoadX509KeyInfer(b)
	if err != nil {
		t.Fatal("Failed to load private EC 521 X509 key:", err)
	}
	_ = key.(*ecdsa.PrivateKey)

	b = loadPEM(t, ed25519Priv)
	key, err = jwkset.LoadX509KeyInfer(b)
	if err != nil {
		t.Fatal("Failed to load private EdDSA X509 key:", err)
	}
	_ = key.(ed25519.PrivateKey)

	b = loadPEM(t, rsa4096Priv)
	key, err = jwkset.LoadX509KeyInfer(b)
	if err != nil {
		t.Fatal("Failed to load private RSA 4096 X509 key:", err)
	}
	_ = key.(*rsa.PrivateKey)
}

func loadPEM(t *testing.T, rawPem string) *pem.Block {
	b, _ := pem.Decode([]byte(rawPem))
	if b == nil {
		t.Fatal("Failed to decode PEM.")
	}
	return b
}

const (
	ec521Cert = `
-----BEGIN CERTIFICATE-----
MIICuTCCAhqgAwIBAgIURHp0UtKTyrMNVuzjFxOPj09/fO8wCgYIKoZIzj0EAwIw
bjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCFZpcmdpbmlhMREwDwYDVQQHDAhSaWNo
bW9uZDEUMBIGA1UECgwLTWljYWggUGFya3MxDTALBgNVBAsMBFNlbGYxFDASBgNV
BAMMC2V4YW1wbGUuY29tMB4XDTIzMTExMjE3NTgxM1oXDTIzMTIxMjE3NTgxM1ow
bjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCFZpcmdpbmlhMREwDwYDVQQHDAhSaWNo
bW9uZDEUMBIGA1UECgwLTWljYWggUGFya3MxDTALBgNVBAsMBFNlbGYxFDASBgNV
BAMMC2V4YW1wbGUuY29tMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBtW2F+MPt
PcN+t5YtYcq8dluVBimcJ3cwTT/Hqrls0iHzpPVANAFRGqhvZnOb4rz7bh3bRqSm
zRNXT9lRJhg07gIA8n2j87Vg5r2FNwlRfD5eMNN3g+o62HUsB9sBfpMiGvLphgvy
g7Mtub7of4eBNphHTBvh3GU+S9TEHvTNP3Ja0aWjUzBRMB0GA1UdDgQWBBSRmKro
6jYkFz0suXUdjCeONWSZSDAfBgNVHSMEGDAWgBSRmKro6jYkFz0suXUdjCeONWSZ
SDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA4GMADCBiAJCARNYjIrrRbub
jF2D/I0Auw7sFQMvV3ImKp+L42kYpoFMXvnmKcuDt6n/OZCDAWpky/Uj/gLbvR2M
fsCNJ+9mbi+4AkIBB0L6Ue7Mxl5cNGprGKSy5c0mlXWezB3GhUKxNrOMUo3+Lt3G
slfqg3TSRlKC1YH863YkRGsE0XWwt9Myj2N6cVI=
-----END CERTIFICATE-----`
	ec521Priv = `
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBK1phZlyXggGSevAh
qqdocYbUK0AQBeD52ZB14sXshymnv/VkMop9UkZRIv11GrIDInxdfRBTXHS4lS18
DvW6mOehgYkDgYYABAG1bYX4w+09w363li1hyrx2W5UGKZwndzBNP8equWzSIfOk
9UA0AVEaqG9mc5vivPtuHdtGpKbNE1dP2VEmGDTuAgDyfaPztWDmvYU3CVF8Pl4w
03eD6jrYdSwH2wF+kyIa8umGC/KDsy25vuh/h4E2mEdMG+HcZT5L1MQe9M0/clrR
pQ==
-----END PRIVATE KEY-----`
	ec521Pub = `
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBtW2F+MPtPcN+t5YtYcq8dluVBimc
J3cwTT/Hqrls0iHzpPVANAFRGqhvZnOb4rz7bh3bRqSmzRNXT9lRJhg07gIA8n2j
87Vg5r2FNwlRfD5eMNN3g+o62HUsB9sBfpMiGvLphgvyg7Mtub7of4eBNphHTBvh
3GU+S9TEHvTNP3Ja0aU=
-----END PUBLIC KEY-----`
	ed25519Cert = `
-----BEGIN CERTIFICATE-----
MIIB8TCCAaOgAwIBAgIUV1qgafWZ5a/PVYZiwTZIyCfiF6gwBQYDK2VwMG4xCzAJ
BgNVBAYTAlVTMREwDwYDVQQIDAhWaXJnaW5pYTERMA8GA1UEBwwIUmljaG1vbmQx
FDASBgNVBAoMC01pY2FoIFBhcmtzMQ0wCwYDVQQLDARTZWxmMRQwEgYDVQQDDAtl
eGFtcGxlLmNvbTAeFw0yMzExMTIxNzU4MTNaFw0yMzEyMTIxNzU4MTNaMG4xCzAJ
BgNVBAYTAlVTMREwDwYDVQQIDAhWaXJnaW5pYTERMA8GA1UEBwwIUmljaG1vbmQx
FDASBgNVBAoMC01pY2FoIFBhcmtzMQ0wCwYDVQQLDARTZWxmMRQwEgYDVQQDDAtl
eGFtcGxlLmNvbTAqMAUGAytlcAMhAFddnU/P7hWUHzdljcXTsfKN5QffdYSikqUo
dt4PAu7oo1MwUTAdBgNVHQ4EFgQUoblrsByGUQ2+Ttthwnm/Vwe+yB8wHwYDVR0j
BBgwFoAUoblrsByGUQ2+Ttthwnm/Vwe+yB8wDwYDVR0TAQH/BAUwAwEB/zAFBgMr
ZXADQQB89PtKOOmgALNTe14oSxMEeFXxGgns7ZiTsuQ+nRtlvkkCJVJKDEJxBXnZ
RqPHwMhPvj2Jw4lYx85CSr47R7cM
-----END CERTIFICATE-----`
	ed25519Priv = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOC6YxHKyd+kPJo6N0lpdiGQLrre5P5W1GKDPwMN0Hxj
-----END PRIVATE KEY-----`
	ed25519Pub = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAV12dT8/uFZQfN2WNxdOx8o3lB991hKKSpSh23g8C7ug=
-----END PUBLIC KEY-----`
	rsa4096Cert = `
-----BEGIN CERTIFICATE-----
MIIFvTCCA6WgAwIBAgIUZNBtI415mo2zhbfEo3i9YeSocy8wDQYJKoZIhvcNAQEL
BQAwbjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCFZpcmdpbmlhMREwDwYDVQQHDAhS
aWNobW9uZDEUMBIGA1UECgwLTWljYWggUGFya3MxDTALBgNVBAsMBFNlbGYxFDAS
BgNVBAMMC2V4YW1wbGUuY29tMB4XDTIzMTExMjE3NTgxNFoXDTIzMTIxMjE3NTgx
NFowbjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCFZpcmdpbmlhMREwDwYDVQQHDAhS
aWNobW9uZDEUMBIGA1UECgwLTWljYWggUGFya3MxDTALBgNVBAsMBFNlbGYxFDAS
BgNVBAMMC2V4YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEA29D7ytMzYhjhw8eweNA73Xid4qpb2uspSmleN5BjWvFeM+tk9RCdc7UQDhrQ
Sv1nrH5sc7NcK2gznmETm+cgaXQeAxacXiC7pXCcSLGhp3BJtBFmOpINyUxPjQrt
WzTUP2AC85DoxQVdM9/cRY7AMLF20YhsgG3B+VxvihbiMSVYwonqB31n2aZgKina
R65JSJQf4SjTgYCtXe128Ch5tsRMMSUTqKzl63w+85VHLoQ+vZBnx6Ht7pBm3tGs
ZFeeaTmZAF+0A9PMkDaFBw6mRyPqus87jjcWv6/VkcVDiZnNw6gEQfltDXFsk03B
Fvs9KU4rfjHA3GuDfpu4OZRkziO9aRvdk1xofTqQSrd6rTTFydzOhmvp5A0mt1Ap
KQQn1f+zTh9ybTxDtJroRCKP+gJYq+kGbMDlpCZXyHv6D68pL04LVctga+5CkZ09
TzVijb85+LCUk5LNvFoh6NcFpz7z5Ru0EyMLDTazOvzQ/aNGl0IYMxs5Ske+cpiJ
XG0+dVe441TlRgwOeUKBg09vrWZoIaD8s7KiziRlrxfHSxJCgPMKCm0lMYQpaXAI
bDMVWr4a1O+WZy0z7R7e9QiFvSoy1ocL9m+5UwiOmS2Z/Oj9HZP+ZT+A/H0Z/hQw
nN7zpbsNms4LGgrneCOc7VaKYq+jeWIsoQ8Bq9aZwsTnH58CAwEAAaNTMFEwHQYD
VR0OBBYEFCXfwSpbQUoatjcGGpxcA0y63ZysMB8GA1UdIwQYMBaAFCXfwSpbQUoa
tjcGGpxcA0y63ZysMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIB
AGGGHDzxe+vSop9RUm5J1I8zmeVjxIC6FxEUSzXst+9DggjXRqaof4EhWKtW+Sdf
DgPGTvDZagDX1VKxuzolmMUgBRT9MrXrnNj3IOUkxptU1t1itIWNSOv0EuNfdMFo
kyDByLNXt8n3zewKZ0KEQkOHnl7sQSfnKxA4AuIaYUFOXAzn8LuL5ZCO3kl60Hla
M0DcRUaKJeJHFjxTXgBQr9M3dr55eQGw/jSWBk5jsfEQgKndQY27I43kMhFOmL5r
ldBB0LrTzuBToFG79oQpzvUkNQkbFevDE15RgtBV5xQTTYjxi3MBcFlL98Vtfj85
SjICsN0KNjolABtryrlQ32PwPp5dIelaILzuvvLsQNFt62RtcntfniScdZ5PZIae
bx0IJyhvy2ylhmYVwfJwUKqIMqnbhYJinvZ/NYjD7tQmnUq2AzopB6YHXDs/CrfU
YckvHj/LGWRyTzb00CWQMvmRZmUsVEThSThY+aTlcRiXu6OATMYii/w/hv+7sVwr
NcMXVckh2/bpHjlZM03LJoabhDp+6c16U+NvOxoVsaPT7y4avoGZZ/IU30i3QpDf
qx5NKPcC4HDK28Daw6zBdO+fkodKFcgsL4jUqP+Q6QCWBH88PlmlXx80XoPQu++W
VhA/xoU82uODjoUbY6FzMW49ESHddZfuFg9fXHm1z31q
-----END CERTIFICATE-----`
	rsa4096Priv = `
-----BEGIN PRIVATE KEY-----
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
NlwPSUy/6PKkQnZiQ0mW4LZqG/maLg==
-----END PRIVATE KEY-----`
	rsa4096Pub = `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA29D7ytMzYhjhw8eweNA7
3Xid4qpb2uspSmleN5BjWvFeM+tk9RCdc7UQDhrQSv1nrH5sc7NcK2gznmETm+cg
aXQeAxacXiC7pXCcSLGhp3BJtBFmOpINyUxPjQrtWzTUP2AC85DoxQVdM9/cRY7A
MLF20YhsgG3B+VxvihbiMSVYwonqB31n2aZgKinaR65JSJQf4SjTgYCtXe128Ch5
tsRMMSUTqKzl63w+85VHLoQ+vZBnx6Ht7pBm3tGsZFeeaTmZAF+0A9PMkDaFBw6m
RyPqus87jjcWv6/VkcVDiZnNw6gEQfltDXFsk03BFvs9KU4rfjHA3GuDfpu4OZRk
ziO9aRvdk1xofTqQSrd6rTTFydzOhmvp5A0mt1ApKQQn1f+zTh9ybTxDtJroRCKP
+gJYq+kGbMDlpCZXyHv6D68pL04LVctga+5CkZ09TzVijb85+LCUk5LNvFoh6NcF
pz7z5Ru0EyMLDTazOvzQ/aNGl0IYMxs5Ske+cpiJXG0+dVe441TlRgwOeUKBg09v
rWZoIaD8s7KiziRlrxfHSxJCgPMKCm0lMYQpaXAIbDMVWr4a1O+WZy0z7R7e9QiF
vSoy1ocL9m+5UwiOmS2Z/Oj9HZP+ZT+A/H0Z/hQwnN7zpbsNms4LGgrneCOc7VaK
Yq+jeWIsoQ8Bq9aZwsTnH58CAwEAAQ==
-----END PUBLIC KEY-----`
)
