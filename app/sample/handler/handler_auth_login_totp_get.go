package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /auth/login/totp
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthLoginTotp
type getAuthLoginTotpRequestParams struct {
}

// Extract parameters from http request
func newGetAuthLoginTotpRequestParams(r *http.Request) *getAuthLoginTotpRequestParams {
	return &getAuthLoginTotpRequestParams{}
}

// Return parameters that can refer in view template
func (p *getAuthLoginTotpRequestParams) toViewParams() map[string]any {
	return map[string]any{}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getAuthLoginTotpRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(p))

	for k := range viewError.validationFieldErrors {
		if k == "FlowID" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
		}
	}

	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getAuthLoginTotpViews struct {
	totp *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthLoginTotp(w http.ResponseWriter, r *http.Request) (*getAuthLoginTotpRequestParams, getAuthLoginTotpViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))
	reqParams := newGetAuthLoginTotpRequestParams(r)
	views := getAuthLoginTotpViews{
		totp: newView("auth/login/totp.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.totp.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handleGetAuthLoginTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	_, views, baseViewError, err := prepareGetAuthLoginTotp(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthLoginTotp failed", "err", err)
		return
	}

	// create and update login flow for aal2, send authentication totp
	createLoginFlowAal2Resp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
		Header:  makeDefaultKratosRequestHeader(r),
		Aal:     kratos.Aal2,
		Refresh: true,
	})
	if err != nil {
		slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
		views.totp.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	updateLoginFlowResp, _, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: createLoginFlowAal2Resp.LoginFlow.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Aal:    kratos.Aal2,
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:     "totp",
			CsrfToken:  createLoginFlowAal2Resp.LoginFlow.CsrfToken,
			Identifier: createLoginFlowAal2Resp.LoginFlow.CodeAddress,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update login flow for aal2 error", "err", err)
		views.totp.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, updateLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/auth/login/totp")
	views.totp.addParams(map[string]any{
		"LoginFlowID": createLoginFlowAal2Resp.LoginFlow.FlowID,
		"CsrfToken":   createLoginFlowAal2Resp.LoginFlow.CsrfToken,
		"Identifier":  createLoginFlowAal2Resp.LoginFlow.CodeAddress,
	}).render(w, r, session)
}
