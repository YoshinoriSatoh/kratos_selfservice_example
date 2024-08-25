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

// ------------------------- Session -------------------------
func (p *Provider) Whoami(ctx context.Context, w http.ResponseWriter, r *http.Request) (*Session, error) {
	kratosResp, err := p.requestKratosPublic(ctx, w, r, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SESSIONS_WHOAMI,
	})
	if err != nil {
		// 認証エラーは正常系で頻繁に発生するため、ログは抑制
		// slog.DebugContext(ctx, "Whoami", "requestKratosPublic error", err)
		return nil, err
	}

	var session Session
	if err := json.Unmarshal(kratosResp.BodyBytes, &session); err != nil {
		slog.ErrorContext(ctx, "Whoami", "json unmarshal error", err)
		return nil, err
	}

	return &session, nil
}
