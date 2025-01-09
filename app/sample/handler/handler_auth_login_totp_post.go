package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /auth/login/totp
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginTotp
type postAuthLoginTotpRequestParams struct {
	FlowID     string `validate:"uuid4"`
	CsrfToken  string `validate:"required"`
	Identifier string `validate:"required,email" ja:"メールアドレス"`
	TotpCode   string `validate:"required" ja:"認証コード"`
}

// Extract parameters from http request
func newPostAuthLoginTotpRequestParams(r *http.Request) *postAuthLoginTotpRequestParams {
	return &postAuthLoginTotpRequestParams{
		FlowID:     r.URL.Query().Get("flow"),
		CsrfToken:  r.PostFormValue("csrf_token"),
		Identifier: r.PostFormValue("identifier"),
		TotpCode:   r.PostFormValue("totp_code"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthLoginTotpRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID": p.FlowID,
		"CsrfToken":   p.CsrfToken,
		"Identifier":  p.Identifier,
		"Totp":        p.TotpCode,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthLoginTotpRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getAuthLoginTotpPostViews struct {
	totpForm *view
	top      *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthLoginTotpPost(w http.ResponseWriter, r *http.Request) (*postAuthLoginTotpRequestParams, getAuthLoginTotpPostViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))
	reqParams := newPostAuthLoginTotpRequestParams(r)
	views := getAuthLoginTotpPostViews{
		totpForm: newView("auth/login/_totp_form.html").addParams(reqParams.toViewParams()),
		top:      newView("top/index.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.totpForm.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthLoginTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthLoginTotpPost(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthLoginPost failed", "err", err)
		return
	}

	// update login flow
	updateLoginFlowResp, _, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Aal:    kratos.Aal2,
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:     "totp",
			CsrfToken:  reqParams.CsrfToken,
			Identifier: reqParams.Identifier,
			TotpCode:   reqParams.TotpCode,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update login flow error", "err", err)
		views.totpForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	session = &updateLoginFlowResp.Session
	slog.DebugContext(ctx, "handlePostAuthLoginTotp", "session", session)

	addCookies(w, updateLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	views.top.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}
