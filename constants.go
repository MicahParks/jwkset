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
	// ALGEdDSA is the EdDSA algorithm.
	ALGEdDSA ALG = "EdDSA"

	// KeyTypeEC is the key type for ECDSA.
	KeyTypeEC KTY = "EC"
	// KeyTypeOKP is the key type for EdDSA.
	KeyTypeOKP KTY = "OKP"
	// KeyTypeRSA is the key type for RSA.
	KeyTypeRSA KTY = "RSA"
	// KeyTypeOct is the key type for octet sequences, such as HMAC.
	KeyTypeOct KTY = "oct"

	// CurveEd25519 is a curve for EdDSA.
	CurveEd25519 CRV = "Ed25519"
	// CurveP256 is a curve for ECDSA.
	CurveP256 CRV = "P-256"
	// CurveP384 is a curve for ECDSA.
	CurveP384 CRV = "P-384"
	// CurveP521 is a curve for ECDSA.
	CurveP521 CRV = "P-521"
)

// ALG is a set of "JSON Web Signature and Encryption Algorithms" types from
// https://www.iana.org/assignments/jose/jose.xhtml(JWA) as defined in
// https://www.rfc-editor.org/rfc/rfc7518#section-7.1
type ALG string

func (alg ALG) String() string {
	return string(alg)
}

// CRV is a set of "JSON Web Key Elliptic Curve" types from https://www.iana.org/assignments/jose/jose.xhtml as
// mentioned in https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1.
type CRV string

func (crv CRV) String() string {
	return string(crv)
}

// KTY is a set of "JSON Web Key Types" from https://www.iana.org/assignments/jose/jose.xhtml as mentioned in
// https://www.rfc-editor.org/rfc/rfc7517#section-4.1
type KTY string

func (kty KTY) String() string {
	return string(kty)
}
