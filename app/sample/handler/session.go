package handler

import (
	"context"
	"log/slog"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
)

func getSession(ctx context.Context) *kratos.Session {
	session := ctx.Value(ctxSession{})
	if session == nil {
		return nil
	}

	kratosSession, ok := session.(kratos.Session)
	if !ok {
		return nil
	}

	return &kratosSession
}

func isAuthenticated(session *kratos.Session) bool {
	if session == nil {
		return false
	}

	slog.Debug("isAuthenticated", "session", session)

	if kratos.SessionRequiredAal == kratos.Aal2 {
		return session.Aal == kratos.Aal2
	} else {
		return true
	}
}
