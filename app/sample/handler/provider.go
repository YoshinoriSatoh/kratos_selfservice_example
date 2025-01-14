package handler

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
	"github.com/YoshinoriSatoh/kratos_example/sms"

	"github.com/google/uuid"
)

type Provider struct {
	d Dependencies
}

type Dependencies struct {
	Sms *sms.Provider
}

type NewInput struct {
	Dependencies Dependencies
}

func New(i NewInput) (*Provider, error) {
	p := Provider{
		d: i.Dependencies,
	}
	return &p, nil
}

func (p *Provider) RegisterHandles(mux *http.ServeMux) *http.ServeMux {
	// Static files
	fileServer := http.StripPrefix("/assets/", http.FileServer(http.Dir("assets")))
	mux.HandleFunc("GET /assets/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			fileServer.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))

	// health check
	mux.Handle("GET /health", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Authentication Registration
	mux.Handle("GET /auth/registration", p.baseMiddleware(p.handleGetAuthRegistration))
	mux.Handle("POST /auth/registration/profile", p.baseMiddleware(p.handlePostAuthRegistrationProfile))
	mux.Handle("POST /auth/registration/credential/password", p.baseMiddleware(p.handlePostAuthRegistrationCredentialPassword))
	mux.Handle("POST /auth/registration/credential/oidc", p.baseMiddleware(p.handlePostAuthRegistrationCredentialOidc))
	mux.Handle("POST /auth/registration/credential/passkey", p.baseMiddleware(p.handlePostAuthRegistrationCredentialPasskey))

	// Authentication Verification
	mux.Handle("GET /auth/verification", p.baseMiddleware(p.handleGetAuthVerification))
	mux.Handle("GET /auth/verification/code", p.baseMiddleware(p.handleGetAuthVerificationCode))
	mux.Handle("POST /auth/verification/email", p.baseMiddleware(p.handlePostAuthVerificationEmail))
	mux.Handle("POST /auth/verification/code", p.baseMiddleware(p.handlePostAuthVerificationCode))

	// Authentication Login
	mux.Handle("GET /auth/login", p.baseMiddleware(p.handleGetAuthLogin))
	mux.Handle("POST /auth/login/password", p.baseMiddleware(p.handlePostAuthLoginPassword))
	mux.Handle("GET /auth/login/code", p.baseMiddleware(p.handleGetAuthLoginCode))
	mux.Handle("POST /auth/login/code", p.baseMiddleware(p.handlePostAuthLoginCode))
	mux.Handle("GET /auth/login/totp", p.baseMiddleware(p.handleGetAuthLoginTotp))
	mux.Handle("POST /auth/login/totp", p.baseMiddleware(p.handlePostAuthLoginTotp))
	mux.Handle("POST /auth/login/oidc", p.baseMiddleware(p.handlePostAuthLoginOidc))
	mux.Handle("POST /auth/login/passkey", p.baseMiddleware(p.handlePostAuthLoginPasskey))

	// Authentication Logout
	mux.Handle("POST /auth/logout", p.baseMiddleware(p.handlePostAuthLogout))

	// Authentication Recovery
	mux.Handle("GET /auth/recovery", p.baseMiddleware(p.handleGetAuthRecovery))
	mux.Handle("POST /auth/recovery/email", p.baseMiddleware(p.handlePostAuthRecoveryEmail))
	mux.Handle("POST /auth/recovery/code", p.baseMiddleware(p.handlePostAuthRecoveryCode))

	// My
	mux.Handle("GET /my", p.baseMiddleware(p.handleGetMy))
	mux.Handle("GET /my/password", p.baseMiddleware(p.handleGetMyPassword))
	mux.Handle("POST /my/password", p.baseMiddleware(p.handlePostMyPassword))
	mux.Handle("GET /my/profile", p.baseMiddleware(p.handleGetMyProfile))
	mux.Handle("POST /my/profile", p.baseMiddleware(p.handlePostMyProfile))
	mux.Handle("GET /my/totp", p.baseMiddleware(p.handleGetMyTotp))
	mux.Handle("POST /my/totp", p.baseMiddleware(p.handlePostMyTotp))

	// Top
	mux.Handle("GET /{$}", p.baseMiddleware(p.handleGetTop))

	// Item
	mux.Handle("GET /item/{id}", p.baseMiddleware(p.handleGetItem))
	mux.Handle("GET /item/{id}/purchase", p.baseMiddleware(p.handleGetItemPurchase))
	mux.Handle("POST /item/{id}/purchase", p.baseMiddleware(p.handlePostItemPurchase))

	// SMS
	mux.Handle("POST /sms/send", p.baseMiddleware(p.handlePostSmsSend))

	return mux
}

func (p *Provider) baseMiddleware(handler http.HandlerFunc) http.Handler {
	return p.fetchSession(handler)
}

type ctxRequestID struct{}
type ctxRemoteAddr struct{}
type ctxCookie struct{}
type ctxSession struct{}

func isIgnoreLogging(r *http.Request) bool {
	for _, v := range loggingIgnorePaths {
		if strings.HasSuffix(v, "/") {
			if strings.HasPrefix(r.URL.Path, v) {
				return true
			}
		} else {
			if r.URL.Path == v {
				return true
			}
		}
	}
	return false
}

var loggingIgnorePaths []string = []string{
	"/health",
	"/assets/",
	"/favicon.ico",
}

func (p *Provider) fetchSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		requestID, _ := uuid.NewRandom()
		ctx = context.WithValue(ctx, ctxRequestID{}, requestID)
		ctx = context.WithValue(ctx, ctxRemoteAddr{}, r.RemoteAddr)
		ctx = context.WithValue(ctx, ctxCookie{}, r.Header.Get("Cookie"))

		slog.DebugContext(ctx, "fetchSession", "cookies", r.Cookies())
		whoamiResp, err := kratos.Whoami(ctx, kratos.WhoamiRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		slog.DebugContext(ctx, "fetchSession", "cookies", r.Cookies())

		if kratos.SessionRequiredAal == kratos.Aal2 && err != nil && err.(kratos.ErrorGeneric).Err.ID == "session_aal2_required" &&
			r.URL.Path != "/auth/login/code" && r.URL.Path != "/auth/login/totp" && r.Method != "POST" {
			setHeadersForReplaceBody(w, "/auth/login/mfa")
			newView("auth/login/mfa.html").render(w, r, nil)
			return
		}

		if err != nil || whoamiResp.Session == nil {
			ctx = context.WithValue(ctx, ctxSession{}, nil)
		} else {
			ctx = context.WithValue(ctx, ctxSession{}, *whoamiResp.Session)
		}

		if isIgnoreLogging(r) {
			bufOfRequestBody, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(bufOfRequestBody))
			var out io.Writer = os.Stdout
			slog.InfoContext(ctx, "[Request]", "method", r.Method, "path", r.URL.Path, "body", out, "session", whoamiResp.Session)
		}

		next.ServeHTTP(w, r.WithContext(ctx))

	})
}

func makeDefaultKratosRequestHeader(r *http.Request) kratos.KratosRequestHeader {
	var cookies []string
	for _, v := range r.Cookies() {
		cookies = append(cookies, v.String())
	}
	return kratos.KratosRequestHeader{
		Cookie:   cookies,
		ClientIP: r.RemoteAddr,
	}
}
