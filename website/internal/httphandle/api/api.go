package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	jt "github.com/MicahParks/jsontype"
	"github.com/google/uuid"

	"github.com/MicahParks/jwkset/website/internal/httphandle/middleware/ctxkey"
)

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func NewAPIError(ctx context.Context, code int, message string) Response {
	apiError := Error{
		Code:    code,
		Message: message,
	}
	meta := Metadata{
		RequestUUID: ctx.Value(ctxkey.ReqUUID).(uuid.UUID),
	}
	return Response{
		Data:     apiError,
		Metadata: meta,
	}
}

type Metadata struct {
	RequestUUID uuid.UUID `json:"requestUUID"`
}

type Response struct {
	Data     any      `json:"data,omitempty"`
	Metadata Metadata `json:"metadata"`
}

func AuthorizeError(ctx context.Context, code int, message string, w http.ResponseWriter) (bool, *http.Request) {
	data, err := errorBody(ctx, code, message)
	if err != nil {
		return false, nil
	}
	w.WriteHeader(code)
	_, _ = w.Write(data)
	return false, nil
}

func ErrorResponse(ctx context.Context, code int, message string) (int, []byte, error) {
	data, err := errorBody(ctx, code, message)
	if err != nil {
		return 0, nil, err
	}
	return code, data, nil
}

func ExtractJSON[ReqData jt.Defaulter[ReqData]](r *http.Request) (reqData ReqData, l *slog.Logger, ctx context.Context, code int, body []byte, err error) {
	ctx = r.Context()
	l = ctx.Value(ctxkey.Logger).(*slog.Logger)

	//goland:noinspection GoUnhandledErrorResult
	defer r.Body.Close()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		code, body, _ = ErrorResponse(ctx, http.StatusBadRequest, "Failed to read request body.")
		return reqData, l, ctx, code, body, err
	}

	err = json.Unmarshal(b, &reqData)
	if err != nil {
		code, body, _ = ErrorResponse(ctx, http.StatusUnsupportedMediaType, "Failed to JSON parse request body.")
		return reqData, l, ctx, code, body, err
	}

	reqData, err = reqData.DefaultsAndValidate()
	if err != nil {
		code, body, _ = ErrorResponse(ctx, http.StatusUnprocessableEntity, "Failed to validate request body.")
		return reqData, l, ctx, code, body, err
	}

	return reqData, l, ctx, http.StatusOK, nil, nil
}

func RespondJSON(ctx context.Context, code int, data any) (int, []byte, error) {
	meta := Metadata{
		RequestUUID: ctx.Value(ctxkey.ReqUUID).(uuid.UUID),
	}
	r := Response{
		Data:     data,
		Metadata: meta,
	}
	r.Metadata = meta
	b, err := json.Marshal(r)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to JSON marshal response: %w", err)
	}
	return code, b, nil
}

func errorBody(ctx context.Context, code int, message string) ([]byte, error) {
	data, err := json.Marshal(NewAPIError(ctx, code, message))
	if err != nil {
		return nil, fmt.Errorf("failed to JSON marshal error response: %w", err)
	}
	return data, nil
}
