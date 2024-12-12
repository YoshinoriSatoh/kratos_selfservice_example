package kratos

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
)

const (
	PATH_SESSIONS_WHOAMI = "/sessions/whoami"
)

// --------------------------------------------------------------------------
// Whoami
// --------------------------------------------------------------------------
type WhoamiRequest struct {
	Header KratosRequestHeader
}

type WhoamiResponse struct {
	Header  KratosResponseHeader
	Session *Session
}

func Whoami(ctx context.Context, r WhoamiRequest) (WhoamiResponse, error) {
	// Request to kratos
	kratosResp, _, err := requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SESSIONS_WHOAMI,
		Header: r.Header,
	})
	if err != nil {
		// 認証エラーは正常系で頻繁に発生するため、ログは抑制
		// slog.DebugContext(ctx, "Whoami", "requestKratosPublic error", err)
		return WhoamiResponse{}, err
	}

	var session Session
	if err := json.Unmarshal(kratosResp.BodyBytes, &session); err != nil {
		slog.ErrorContext(ctx, "Whoami", "json unmarshal error", err)
		return WhoamiResponse{}, err
	}

	response := WhoamiResponse{
		Header:  kratosResp.Header,
		Session: &session,
	}

	return response, nil
}
