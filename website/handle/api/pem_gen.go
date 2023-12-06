package api

import (
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

type PemGenRespData struct {
	JWK string `json:"jwk"`
}

type PemGenReqData struct {
	ALG    jwkset.ALG      `json:"alg"`
	KEYOPS []jwkset.KEYOPS `json:"keyops"`
	KID    string          `json:"kid"`
	PEM    string          `json:"pem"`
	USE    jwkset.USE      `json:"use"`
}

func (p PemGenReqData) DefaultsAndValidate() (PemGenReqData, error) {
	if p.PEM == "" {
		return p, fmt.Errorf(`%w: "pem" attribute requried`, jt.ErrDefaultsAndValidate)
	}
	if !p.ALG.IANARegistered() {
		return p, fmt.Errorf(`%w: "alg" attribute invalid`, jt.ErrDefaultsAndValidate)
	}
	for _, o := range p.KEYOPS {
		if !o.IANARegistered() {
			return p, fmt.Errorf(`%w: "keyops" attribute invalid`, jt.ErrDefaultsAndValidate)
		}
	}
	if !p.USE.IANARegistered() {
		return p, fmt.Errorf(`%w: "use" attribute invalid`, jt.ErrDefaultsAndValidate)
	}
	return p, nil
}

type PemGen struct {
	s server.Server
}

func (p *PemGen) ApplyMiddleware(h http.Handler) http.Handler {
	return h
}
func (p *PemGen) Authorize(w http.ResponseWriter, r *http.Request) (authorized bool, modified *http.Request) {
	return authReCAPTCHA("pemGen", p.s, w, r)
}
func (p *PemGen) ContentType() (request, response string) {
	return hhconst.ContentTypeJSON, hhconst.ContentTypeJSON
}
func (p *PemGen) HTTPMethod() string {
	return http.MethodPost
}
func (p *PemGen) Initialize(s server.Server) error {
	p.s = s
	return nil
}
func (p *PemGen) Respond(r *http.Request) (code int, body []byte, err error) {
	reqData, l, ctx, code, body, err := api.ExtractJSON[PemGenReqData](r)
	if err != nil {
		return api.ErrorResponse(ctx, code, "Failed to JSON parse request body.")
	}

	rawPEM := []byte(reqData.PEM)
	block, _ := pem.Decode(rawPEM)
	if block == nil {
		return api.ErrorResponse(ctx, http.StatusBadRequest, fmt.Sprintf("Failed to decode PEM block."))
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

	var jwk jwkset.JWK
	switch block.Type {
	case "CERTIFICATE":
		certs, err := jwkset.LoadCertificates(rawPEM)
		if err != nil {
			return api.ErrorResponse(ctx, http.StatusBadRequest, fmt.Sprintf("Failed to load certificates: %s.", err))
		}
		x509Options := jwkset.JWKX509Options{
			X5C: certs,
		}
		options := jwkset.JWKOptions{
			Marshal:  marshalOptions,
			Metadata: metadata,
			X509:     x509Options,
		}
		jwk, err = jwkset.NewJWKFromX5C(options)
		if err != nil {
			return api.ErrorResponse(ctx, http.StatusInternalServerError, fmt.Sprintf("Failed to create JWK from X5C: %s.", err))
		}
		l.InfoContext(ctx, "Created JWK from certificate.")
	default:
		key, err := jwkset.LoadX509KeyInfer(block)
		if err != nil {
			return api.ErrorResponse(ctx, http.StatusBadRequest, fmt.Sprintf("Failed to load X509 key: %s.", err))
		}
		options := jwkset.JWKOptions{
			Marshal:  marshalOptions,
			Metadata: metadata,
		}
		jwk, err = jwkset.NewJWKFromKey(key, options)
		if err != nil {
			return api.ErrorResponse(ctx, http.StatusInternalServerError, fmt.Sprintf("Failed to create JWK from key: %s.", err))
		}
		l.InfoContext(ctx, "Created JWK from key.")
	}

	j, err := json.MarshalIndent(jwk.Marshal(), "", "  ")
	if err != nil {
		return api.ErrorResponse(ctx, http.StatusInternalServerError, fmt.Sprintf("Failed to marshal JSON: %s.", err))
	}

	respData := PemGenRespData{
		JWK: string(j),
	}

	return api.RespondJSON(ctx, http.StatusOK, respData)
}
func (p *PemGen) URLPattern() string {
	return jsc.PathAPIPemGen
}
