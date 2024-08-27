package handler

import (
	"context"
	"kratos_example/kratos"
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
	if session != nil {
		return true
	} else {
		return false
	}
}
