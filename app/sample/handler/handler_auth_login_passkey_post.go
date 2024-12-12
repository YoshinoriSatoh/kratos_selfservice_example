package handler

import (
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /auth/login/passkey
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginPasskey
type postAuthLoginPasskeyRequestParams struct {
	FlowID    string `validate:"uuid4"`
	CsrfToken string `validate:"required"`
	// Identifier   string `validate:"required,email" ja:"メールアドレス"`
	PasskeyLogin     string `validate:"required"`
	PasskeyChallenge string `validate:"required"`
}

// Extract parameters from http request
func newPostAuthLoginPasskeyRequestParams(r *http.Request) *postAuthLoginPasskeyRequestParams {
	return &postAuthLoginPasskeyRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		// Identifier:   r.PostFormValue("identifier"),
		PasskeyLogin:     r.PostFormValue("passkey_login"),
		PasskeyChallenge: r.PostFormValue("passkey_challenge"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthLoginPasskeyRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID": p.FlowID,
		"CsrfToken":   p.CsrfToken,
		// "Identifier":   p.Identifier,
		"PasskeyLogin":     p.PasskeyLogin,
		"PasskeyChallenge": p.PasskeyChallenge,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthLoginPasskeyRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostAuthLoginPasskey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAuthLoginPasskeyRequestParams(r)

	// prepare views
	loginFormPasskeyView := newView("auth/login/_form_passkey.html").addParams(params.toViewParams())
	topIndexView := newView("top/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		loginFormPasskeyView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))

	// update login flow
	updateLoginFlowResp, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:    "passkey",
			CsrfToken: params.CsrfToken,
			// Identifier:   params.Identifier,
			PasskeyLogin: params.PasskeyLogin,
		},
	})
	if err != nil {
		loginFormPasskeyView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	session = &updateLoginFlowResp.Session

	addCookies(w, updateLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	topIndexView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}
