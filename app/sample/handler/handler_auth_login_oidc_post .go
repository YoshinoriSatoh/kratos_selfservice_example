package handler

import (
	"fmt"
	"log/slog"
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

// Views
type getAuthLoginOidcViews struct {
	index *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthLoginOidc(w http.ResponseWriter, r *http.Request) (*postAuthLoginOidcRequestParams, getAuthLoginOidcViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))
	reqParams := newPostAuthLoginOidcRequestParams(r)
	views := getAuthLoginOidcViews{
		index: newView("auth/login/index.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.index.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthLoginOidc(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthLoginOidc(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthLoginOidc failed", "err", err)
		return
	}

	// update login flow
	updateLoginFlowResp, _, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:    "oidc",
			CsrfToken: reqParams.CsrfToken,
			Provider:  reqParams.Provider,
		},
	})
	if err != nil {
		views.index.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	session = &updateLoginFlowResp.Session
	addCookies(w, updateLoginFlowResp.Header.Cookie)

	if updateLoginFlowResp.RedirectBrowserTo != "" {
		slog.DebugContext(ctx, "redirect occured", "RedirectBrowserTo", updateLoginFlowResp.RedirectBrowserTo)
		// w.Header().Set("HX-Redirect", updateLoginFlowResp.RedirectBrowserTo)
		redirect(w, r, updateLoginFlowResp.RedirectBrowserTo)
		return
	}

	// render
	setHeadersForReplaceBody(w, "/")
	views.index.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}
