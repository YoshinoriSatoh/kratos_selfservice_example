package handler

import (
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /auth/login/oidc
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLogin
type postAuthLoginOidcRequestParams struct {
	FlowID    string `validate:"uuid4"`
	CsrfToken string `validate:"required"`
	Provider  string `validate:"required"`
}

// Extract parameters from http request
func newPostAuthLoginOidcRequestParams(r *http.Request) *postAuthLoginOidcRequestParams {
	return &postAuthLoginOidcRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Provider:  r.PostFormValue("provider"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthLoginOidcRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID": p.FlowID,
		"CsrfToken":   p.CsrfToken,
		"Provider":    p.Provider,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthLoginOidcRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostAuthLoginOidc(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAuthLoginOidcRequestParams(r)

	// prepare views
	loginFormView := newView("auth/login/_form.html").addParams(params.toViewParams())
	topIndexView := newView("top/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		loginFormView.addParams(viewError.toViewParams()).render(w, r, session)
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
			Method:    "oidc",
			CsrfToken: params.CsrfToken,
			Provider:  params.Provider,
		},
	})
	if err != nil {
		loginFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	session = &updateLoginFlowResp.Session
	addCookies(w, updateLoginFlowResp.Header.Cookie)

	if updateLoginFlowResp.RedirectBrowserTo != "" {
		// w.Header().Set("HX-Redirect", updateLoginFlowResp.RedirectBrowserTo)
		redirect(w, r, updateLoginFlowResp.RedirectBrowserTo)
		return
	}

	// render
	setHeadersForReplaceBody(w, "/")
	topIndexView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}
