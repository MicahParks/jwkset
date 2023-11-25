package jwkset

const (
	// HeaderKID is a JWT header for the key ID.
	HeaderKID = "kid"
)

const (
	AlgHS256            ALG = "HS256"
	AlgHS384            ALG = "HS384"
	AlgHS512            ALG = "HS512"
	AlgRS256            ALG = "RS256"
	AlgRS384            ALG = "RS384"
	AlgRS512            ALG = "RS512"
	AlgES256            ALG = "ES256"
	AlgES384            ALG = "ES384"
	AlgES512            ALG = "ES512"
	AlgPS256            ALG = "PS256"
	AlgPS384            ALG = "PS384"
	AlgPS512            ALG = "PS512"
	AlgNone             ALG = "none"
	AlgRSA1_5           ALG = "RSA1_5"
	AlgRSAOAEP          ALG = "RSA-OAEP"
	AlgRSAOAEP256       ALG = "RSA-OAEP-256"
	AlgA128KW           ALG = "A128KW"
	AlgA192KW           ALG = "A192KW"
	AlgA256KW           ALG = "A256KW"
	Algdir              ALG = "dir"
	AlgECDHES           ALG = "ECDH-ES"
	AlgECDHESA128KW     ALG = "ECDH-ES+A128KW"
	AlgECDHESA192KW     ALG = "ECDH-ES+A192KW"
	AlgECDHESA256KW     ALG = "ECDH-ES+A256KW"
	AlgA128GCMKW        ALG = "A128GCMKW"
	AlgA192GCMKW        ALG = "A192GCMKW"
	AlgA256GCMKW        ALG = "A256GCMKW"
	AlgPBES2HS256A128KW ALG = "PBES2-HS256+A128KW"
	AlgPBES2HS384A192KW ALG = "PBES2-HS384+A192KW"
	AlgPBES2HS512A256KW ALG = "PBES2-HS512+A256KW"
	AlgA128CBCHS256     ALG = "A128CBC-HS256"
	AlgA192CBCHS384     ALG = "A192CBC-HS384"
	AlgA256CBCHS512     ALG = "A256CBC-HS512"
	AlgA128GCM          ALG = "A128GCM"
	AlgA192GCM          ALG = "A192GCM"
	AlgA256GCM          ALG = "A256GCM"
	AlgEdDSA            ALG = "EdDSA"
	AlgRS1              ALG = "RS1" // Prohibited.
	AlgRSAOAEP384       ALG = "RSA-OAEP-384"
	AlgRSAOAEP512       ALG = "RSA-OAEP-512"
	AlgA128CBC          ALG = "A128CBC" // Prohibited.
	AlgA192CBC          ALG = "A192CBC" // Prohibited.
	AlgA256CBC          ALG = "A256CBC" // Prohibited.
	AlgA128CTR          ALG = "A128CTR" // Prohibited.
	AlgA192CTR          ALG = "A192CTR" // Prohibited.
	AlgA256CTR          ALG = "A256CTR" // Prohibited.
	AlgHS1              ALG = "HS1"     // Prohibited.
	AlgES256K           ALG = "ES256K"

	CrvP256    CRV = "P-256"
	CrvP384    CRV = "P-384"
	CrvP521    CRV = "P-521"
	CrvEd25519 CRV = "Ed25519"
	CrvEd448   CRV = "Ed448"
	X25519     CRV = "X25519"
	X448       CRV = "X448"
	SECP256K1  CRV = "secp256k1"

	KeyOpsSign       KEYOPS = "sign"
	KeyOpsVerify     KEYOPS = "verify"
	KeyOpsEncrypt    KEYOPS = "encrypt"
	KeyOpsDecrypt    KEYOPS = "decrypt"
	KeyOpsWrapKey    KEYOPS = "wrapKey"
	KeyOpsUnwrapKey  KEYOPS = "unwrapKey"
	KeyOpsDeriveKey  KEYOPS = "deriveKey"
	KeyOpsDeriveBits KEYOPS = "deriveBits"

	KtyEC  KTY = "EC"
	KtyOKP KTY = "OKP"
	KtyRSA KTY = "RSA"
	KtyOct KTY = "oct"

	UseEnc USE = "enc"
	UseSig USE = "sig"
)

// ALG is a set of "JSON Web Signature and Encryption Algorithms" types from
// https://www.iana.org/assignments/jose/jose.xhtml as defined in
// https://www.rfc-editor.org/rfc/rfc7518#section-7.1
type ALG string

func (alg ALG) String() string {
	return string(alg)
}

// CRV is a set of "JSON Web Key Elliptic Curve" types from https://www.iana.org/assignments/jose/jose.xhtml as
// mentioned in https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1
type CRV string

func (crv CRV) String() string {
	return string(crv)
}

// KEYOPS is a set of "JSON Web Key Operations" from https://www.iana.org/assignments/jose/jose.xhtml as mentioned in
// https://www.rfc-editor.org/rfc/rfc7517#section-4.3
type KEYOPS string

func (keyopts KEYOPS) String() string {
	return string(keyopts)
}
func (keyopts KEYOPS) valid() bool {
	switch keyopts {
	case KeyOpsSign, KeyOpsVerify, KeyOpsEncrypt, KeyOpsDecrypt, KeyOpsWrapKey, KeyOpsUnwrapKey, KeyOpsDeriveKey, KeyOpsDeriveBits:
		return true
	}
	return false
}

// KTY is a set of "JSON Web Key Types" from https://www.iana.org/assignments/jose/jose.xhtml as mentioned in
// https://www.rfc-editor.org/rfc/rfc7517#section-4.1
type KTY string

func (kty KTY) String() string {
	return string(kty)
}
func (kty KTY) valid() bool {
	switch kty {
	case KtyEC, KtyOKP, KtyRSA, KtyOct:
		return true
	}
	return false
}

// USE is a set of "JSON Web Key Use" types from https://www.iana.org/assignments/jose/jose.xhtml as mentioned in
// https://www.rfc-editor.org/rfc/rfc7517#section-4.2
type USE string

func (use USE) String() string {
	return string(use)
}
func (use USE) valid() bool {
	switch use {
	case UseEnc, UseSig, "":
		return true
	}
	return false
}
