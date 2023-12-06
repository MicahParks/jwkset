package api

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/MicahParks/httphandle/api"
	hhconst "github.com/MicahParks/httphandle/constant"
	jt "github.com/MicahParks/jsontype"
	"github.com/MicahParks/jwkset"

	jsc "github.com/MicahParks/jwkset/website"
	"github.com/MicahParks/jwkset/website/server"
)

type NewGenRespData struct {
	JWK   string `json:"jwk"`
	PKCS8 string `json:"pkcs8"`
	PKIX  string `json:"pkix"`
}

const (
	KeyTypeRSA       keyType = "RSA"
	KeyTypeECDSA     keyType = "ECDSA"
	KeyTypeEd25519   keyType = "Ed25519"
	KeyTypeX25519    keyType = "X25519"
	KeyTypeSymmetric keyType = "Symmetric"
)

type keyType string

func (k keyType) valid() bool {
	switch k {
	case KeyTypeRSA, KeyTypeECDSA, KeyTypeEd25519, KeyTypeX25519, KeyTypeSymmetric:
		return true
	default:
		return false
	}
}

type NewGenReqData struct {
	ALG     jwkset.ALG      `json:"alg"`
	KEYOPS  []jwkset.KEYOPS `json:"keyops"`
	KeyType keyType         `json:"keyType"`
	KID     string          `json:"kid"`
	USE     jwkset.USE      `json:"use"`

	RSABits int        `json:"rsaBits"`
	ECCurve jwkset.CRV `json:"ecCurve"`
}

func (n NewGenReqData) DefaultsAndValidate() (NewGenReqData, error) {
	if !n.ALG.IANARegistered() {
		return n, fmt.Errorf(`%w: "alg" attribute is not a known IANA registered value`, jt.ErrDefaultsAndValidate)
	}
	for _, o := range n.KEYOPS {
		if !o.IANARegistered() {
			return n, fmt.Errorf(`%w: "keyops" attribute is not a known IANA registered value`, jt.ErrDefaultsAndValidate)
		}
	}
	if !n.KeyType.valid() {
		return n, fmt.Errorf(`%w: unknown key type`, jt.ErrDefaultsAndValidate)
	}
	if !n.USE.IANARegistered() {
		return n, fmt.Errorf(`%w: "use" attribute is not a known IANA registered value`, jt.ErrDefaultsAndValidate)
	}
	switch n.KeyType {
	case KeyTypeRSA:
		switch n.RSABits {
		case 1024, 2048, 4096:
		default:
			return n, fmt.Errorf(`%w: "rsaBits" attribute must be 1024, 2048, or 4096`, jt.ErrDefaultsAndValidate)
		}
	case KeyTypeECDSA:
		switch n.ECCurve {
		case jwkset.CrvP256, jwkset.CrvP384, jwkset.CrvP521:
		default:
			return n, fmt.Errorf(`%w: "ecCurve" attribute must be "P-256", "P-384", or "P-521"`, jt.ErrDefaultsAndValidate)
		}
	}
	return n, nil
}

type NewGen struct {
	s server.Server
}

func (n *NewGen) ApplyMiddleware(h http.Handler) http.Handler {
	return h
}
func (n *NewGen) Authorize(w http.ResponseWriter, r *http.Request) (authorized bool, modified *http.Request) {
	return authReCAPTCHA("newGen", n.s, w, r)
}
func (n *NewGen) ContentType() (request, response string) {
	return hhconst.ContentTypeJSON, hhconst.ContentTypeJSON
}
func (n *NewGen) HTTPMethod() string {
	return http.MethodPost
}
func (n *NewGen) Initialize(s server.Server) error {
	n.s = s
	return nil
}
func (n *NewGen) Respond(r *http.Request) (code int, body []byte, err error) {
	reqData, l, ctx, code, body, err := api.ExtractJSON[NewGenReqData](r)
	if err != nil {
		return api.ErrorResponse(ctx, code, "Failed to JSON parse request body.")
	}

	var priv any
	var pub any
	switch reqData.KeyType {
	case KeyTypeRSA:
		rsaPriv, err := rsa.GenerateKey(rand.Reader, reqData.RSABits)
		if err != nil {
			l.ErrorContext(ctx,
				"Failed to generate RSA private key.",
				hhconst.LogErr, err,
			)
			return api.ErrorResponse(ctx, http.StatusInternalServerError, hhconst.RespInternalServerError)
		}
		priv = rsaPriv
		pub = rsaPriv.Public()
		l.InfoContext(ctx, "Generated RSA private key.")
	case KeyTypeECDSA:
		var crv elliptic.Curve
		switch reqData.ECCurve {
		case jwkset.CrvP256:
			crv = elliptic.P256()
		case jwkset.CrvP384:
			crv = elliptic.P384()
		case jwkset.CrvP521:
			crv = elliptic.P521()
		default:
			l.ErrorContext(ctx, "Failed to generate EC private key due to unhandled curve.")
			return api.ErrorResponse(ctx, http.StatusInternalServerError, hhconst.RespInternalServerError)
		}
		ecPriv, err := ecdsa.GenerateKey(crv, rand.Reader)
		if err != nil {
			l.ErrorContext(ctx,
				"Failed to generate EC private key.",
				hhconst.LogErr, err,
			)
			return api.ErrorResponse(ctx, http.StatusInternalServerError, hhconst.RespInternalServerError)
		}
		priv = ecPriv
		pub = ecPriv.Public()
		l.InfoContext(ctx, "Generated EC private key.")
	case KeyTypeEd25519:
		_, edPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			l.ErrorContext(ctx, "Failed to generate Ed25519 private key.")
			return api.ErrorResponse(ctx, http.StatusInternalServerError, hhconst.RespInternalServerError)
		}
		priv = edPriv
		pub = edPriv.Public()
		l.InfoContext(ctx, "Generated Ed25519 private key.")
	case KeyTypeX25519:
		xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			l.ErrorContext(ctx, "Failed to generate X25519 private key.")
			return api.ErrorResponse(ctx, http.StatusInternalServerError, hhconst.RespInternalServerError)
		}
		priv = xPriv
		pub = xPriv.Public()
		l.InfoContext(ctx, "Generated X25519 private key.")
	case KeyTypeSymmetric:
		b := make([]byte, 64)
		_, err := rand.Read(b)
		if err != nil {
			l.ErrorContext(ctx, "Failed to generate octet sequence.")
			return api.ErrorResponse(ctx, http.StatusInternalServerError, hhconst.RespInternalServerError)
		}
		priv = b
		l.InfoContext(ctx, "Generated octet sequence.")
	default:
		l.ErrorContext(ctx, "Failed to generate key due to unhandled key type.")
		return api.ErrorResponse(ctx, http.StatusInternalServerError, hhconst.RespInternalServerError)
	}

	marshalOptions := jwkset.JWKMarshalOptions{
		Private: true,
	}
	metadata := jwkset.JWKMetadataOptions{
		ALG:    reqData.ALG,
		KID:    reqData.KID,
		KEYOPS: reqData.KEYOPS,
		USE:    reqData.USE,
	}
	options := jwkset.JWKOptions{
		Marshal:  marshalOptions,
		Metadata: metadata,
	}
	jwk, err := jwkset.NewJWKFromKey(priv, options)
	if err != nil {
		l.ErrorContext(ctx, "Failed to create JWK from key.",
			hhconst.LogErr, err,
		)
		return api.ErrorResponse(ctx, http.StatusInternalServerError, hhconst.RespInternalServerError)
	}

	j, err := json.MarshalIndent(jwk.Marshal(), "", "  ")
	if err != nil {
		l.ErrorContext(ctx, "Failed to marshal JWK.",
			hhconst.LogErr, err,
		)
		return api.ErrorResponse(ctx, http.StatusInternalServerError, hhconst.RespInternalServerError)
	}

	var pkcs8 string
	var pkix string
	if reqData.KeyType != KeyTypeSymmetric {
		p, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			l.InfoContext(ctx, "Failed to marshal private key to PKCS8.")
			return api.ErrorResponse(ctx, http.StatusInternalServerError, hhconst.RespInternalServerError)
		}
		block := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: p,
		}
		pkcs8 = string(pem.EncodeToMemory(block))
		p, err = x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			l.InfoContext(ctx, "Failed to marshal public key to PKIX.")
			return api.ErrorResponse(ctx, http.StatusInternalServerError, hhconst.RespInternalServerError)
		}
		block = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: p,
		}
		pkix = string(pem.EncodeToMemory(block))
	}

	respData := NewGenRespData{
		JWK:   string(j),
		PKCS8: pkcs8,
		PKIX:  pkix,
	}

	return api.RespondJSON(ctx, http.StatusOK, respData)
}
func (n *NewGen) URLPattern() string {
	return jsc.PathAPINewGen
}
