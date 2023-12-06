package api

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
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

type InspectReq struct {
	JWK string `json:"jwk"`
}

func (i InspectReq) DefaultsAndValidate() (InspectReq, error) {
	if i.JWK == "" {
		return i, fmt.Errorf(`%w: "jwk" attribute requried`, jt.ErrDefaultsAndValidate)
	}
	return i, nil
}

type InspectResp struct {
	JWK   string `json:"jwk"`
	PKCS8 string `json:"pkcs8"`
	PKIX  string `json:"pkix"`
}

type Inspect struct {
	s server.Server
}

func (i *Inspect) ApplyMiddleware(h http.Handler) http.Handler {
	return h
}
func (i *Inspect) Authorize(w http.ResponseWriter, r *http.Request) (authorized bool, modified *http.Request) {
	return authReCAPTCHA("inspect", i.s, w, r)
}
func (i *Inspect) ContentType() (request, response string) {
	return hhconst.ContentTypeJSON, hhconst.ContentTypeJSON
}
func (i *Inspect) HTTPMethod() string {
	return http.MethodPost
}
func (i *Inspect) Initialize(s server.Server) error {
	i.s = s
	return nil
}
func (i *Inspect) Respond(r *http.Request) (code int, body []byte, err error) {
	reqData, l, ctx, code, body, err := api.ExtractJSON[InspectReq](r)
	if err != nil {
		return api.ErrorResponse(ctx, code, "Failed to JSON parse request body.")
	}

	marshal := jwkset.JWKMarshal{}
	err = json.Unmarshal([]byte(reqData.JWK), &marshal)
	if err != nil {
		return api.ErrorResponse(ctx, http.StatusUnprocessableEntity, "Failed to JSON parse JWK.")
	}

	marshalOptions := jwkset.JWKMarshalOptions{
		Private: true,
	}
	jwk, err := jwkset.NewJWKFromMarshal(marshal, marshalOptions, jwkset.JWKValidateOptions{})
	if err != nil {
		return api.ErrorResponse(ctx, http.StatusUnprocessableEntity, fmt.Sprintf("Failed to validate JWK: %s.", err))
	}
	key := jwk.Key()

	b, err := json.MarshalIndent(jwk.Marshal(), "", "  ")
	if err != nil {
		return api.ErrorResponse(ctx, http.StatusInternalServerError, fmt.Sprintf("Failed to JSON marshal JWK: %s.", err))
	}
	resp := InspectResp{
		JWK: string(b),
	}

	type publicKeyer interface {
		Public() crypto.PublicKey
	}

	var priv, pub []byte
	var block *pem.Block
	switch k := key.(type) {
	case []byte:
	case *ecdh.PrivateKey, ed25519.PrivateKey, *ecdsa.PrivateKey, *rsa.PrivateKey:
		priv, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return api.ErrorResponse(ctx, http.StatusInternalServerError, fmt.Sprintf("Failed to PKCS #8 marshal private key: %s.", err))
		}
		pub, err = x509.MarshalPKIXPublicKey(k.(publicKeyer).Public())
		if err != nil {
			return api.ErrorResponse(ctx, http.StatusInternalServerError, fmt.Sprintf("Failed to PKIX marshal public key: %s.", err))
		}
	case *ecdh.PublicKey, ed25519.PublicKey, *ecdsa.PublicKey, *rsa.PublicKey:
		pub, err = x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return api.ErrorResponse(ctx, http.StatusInternalServerError, fmt.Sprintf("Failed to PKIX marshal public key: %s.", err))
		}
	default:
		return api.ErrorResponse(ctx, http.StatusInternalServerError, fmt.Sprintf("Unknown key cryptographic key type: %T.", k))
	}

	if priv != nil {
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: priv,
		}
		resp.PKCS8 = string(pem.EncodeToMemory(block))
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pub,
	}
	resp.PKIX = string(pem.EncodeToMemory(block))

	l.InfoContext(ctx, "Inspected JWK.")

	return api.RespondJSON(ctx, http.StatusOK, resp)
}
func (i *Inspect) URLPattern() string {
	return jsc.PathAPIInspect
}
