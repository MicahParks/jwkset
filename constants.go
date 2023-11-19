package jwkset

const (
	// AlgHS256 is the HMAC using SHA-256 algorithm.
	AlgHS256 ALG = "HS256"
	// AlgHS384 is the HMAC using SHA-384 algorithm.
	AlgHS384 ALG = "HS384"
	// AlgHS512 is the HMAC using SHA-512 algorithm.
	AlgHS512 ALG = "HS512"
	// AlgRS256 is the RSASSA-PKCS1-v1_5 using SHA-256 algorithm.
	AlgRS256 ALG = "RS256"
	// AlgRS384 is the RSASSA-PKCS1-v1_5 using SHA-384 algorithm.
	AlgRS384 ALG = "RS384"
	// AlgRS512 is the RSASSA-PKCS1-v1_5 using SHA-512 algorithm.
	AlgRS512 ALG = "RS512"
	// AlgES256 is the ECDSA using P-256 and SHA-256 algorithm.
	AlgES256 ALG = "ES256"
	// AlgES384 is the ECDSA using P-384 and SHA-384 algorithm.
	AlgES384 ALG = "ES384"
	// AlgES512 is the ECDSA using P-521 and SHA-512 algorithm.
	AlgES512 ALG = "ES512"
	// AlgPS256 is the RSASSA-PSS using SHA-256 and MGF1 with SHA-256 algorithm.
	AlgPS256 ALG = "PS256"
	// AlgPS384 is the RSASSA-PSS using SHA-384 and MGF1 with SHA-384 algorithm.
	AlgPS384 ALG = "PS384"
	// AlgPS512 is the RSASSA-PSS using SHA-512 and MGF1 with SHA-512 algorithm.
	AlgPS512 ALG = "PS512"
	// AlgNone is the No digital signature or MAC performed algorithm.
	AlgNone ALG = "none"
	// AlgEdDSA is the EdDSA algorithm.
	AlgEdDSA ALG = "EdDSA"

	// KeyOpsSign is a key operation for signing.
	KeyOpsSign = "sign"
	// KeyOpsVerify is a key operation for verifying.
	KeyOpsVerify = "verify"
	// KeyOpsEncrypt is a key operation for encryption.
	KeyOpsEncrypt = "encrypt"
	// KeyOpsDecrypt is a key operation for decryption.
	KeyOpsDecrypt = "decrypt"
	// KeyOpsWrapKey is a key operation for wrapping a key.
	KeyOpsWrapKey = "wrapKey"
	// KeyOpsUnwrapKey is a key operation for unwrapping a key.
	KeyOpsUnwrapKey = "unwrapKey"
	// KeyOpsDeriveKey is a key operation for deriving a key.
	KeyOpsDeriveKey = "deriveKey"
	// KeyOpsDeriveBits is a key operation for deriving bits.
	KeyOpsDeriveBits = "deriveBits"

	// KtyEC is the key type for ECDSA.
	KtyEC KTY = "EC"
	// KtyOKP is the key type for EdDSA.
	KtyOKP KTY = "OKP"
	// KtyRSA is the key type for RSA.
	KtyRSA KTY = "RSA"
	// KtyOct is the key type for octet sequences, such as HMAC.
	KtyOct KTY = "oct"

	// CrvEd25519 is a curve for EdDSA.
	CrvEd25519 CRV = "Ed25519"
	// CrvP256 is a curve for ECDSA.
	CrvP256 CRV = "P-256"
	// CrvP384 is a curve for ECDSA.
	CrvP384 CRV = "P-384"
	// CrvP521 is a curve for ECDSA.
	CrvP521 CRV = "P-521"

	// HeaderKID is a JWT header for the key ID.
	HeaderKID = "kid"

	// UseEnc indicates a JWK is for encryption.
	UseEnc USE = "enc"
	// UseSig indicates a JWK is for signing.
	UseSig USE = "sig"
)

// ALG is a set of "JSON Web Signature and Encryption Algorithms" types from
// https://www.iana.org/assignments/jose/jose.xhtml(JWA) as defined in
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

// KTY is a set of "JSON Web Key Types" from https://www.iana.org/assignments/jose/jose.xhtml as mentioned in
// https://www.rfc-editor.org/rfc/rfc7517#section-4.1
type KTY string

func (kty KTY) String() string {
	return string(kty)
}

// USE is a set of "JSON Web Key Use" types from https://www.iana.org/assignments/jose/jose.xhtml as mentioned in
// https://www.rfc-editor.org/rfc/rfc7517#section-4.2
type USE string

func (use USE) String() string {
	return string(use)
}
