package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /auth/login
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginPassword
type postAuthLoginPasswordRequestParams struct {
	FlowID                      string `validate:"uuid4"`
	CsrfToken                   string `validate:"required"`
	Identifier                  string `validate:"required,email" ja:"メールアドレス"`
	Password                    string `validate:"required" ja:"パスワード"`
	UpdateSettingsAfterLoggedIn string
}

// Extract parameters from http request
func newPostAuthLoginPasswordRequestParams(r *http.Request) *postAuthLoginPasswordRequestParams {
	return &postAuthLoginPasswordRequestParams{
		FlowID:                      r.URL.Query().Get("flow"),
		CsrfToken:                   r.PostFormValue("csrf_token"),
		Identifier:                  r.PostFormValue("identifier"),
		Password:                    r.PostFormValue("password"),
		UpdateSettingsAfterLoggedIn: r.PostFormValue("update_settings_after_logged_in"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthLoginPasswordRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID":                 p.FlowID,
		"CsrfToken":                   p.CsrfToken,
		"Identifier":                  p.Identifier,
		"Password":                    p.Password,
		"UpdateSettingsAfterLoggedIn": p.UpdateSettingsAfterLoggedIn,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthLoginPasswordRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getAuthLoginPasswordPostViews struct {
	passwordForm *view
	code         *view
	top          *view
	mfa          *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthLoginPasswordPost(w http.ResponseWriter, r *http.Request) (*postAuthLoginPasswordRequestParams, getAuthLoginPasswordPostViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))
	reqParams := newPostAuthLoginPasswordRequestParams(r)
	views := getAuthLoginPasswordPostViews{
		passwordForm: newView("auth/login/_password_form.html").addParams(reqParams.toViewParams()),
		code:         newView("auth/login/code.html").addParams(reqParams.toViewParams()),
		top:          newView("top/index.html").addParams(reqParams.toViewParams()),
		mfa:          newView("auth/login/mfa.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.passwordForm.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthLoginPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthLoginPasswordPost(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthLoginPost failed", "err", err)
		return
	}

	// update login flow
	updateLoginFlowResp, kratosReqHeaderForNext, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Aal:    kratos.Aal1,
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:     "password",
			CsrfToken:  reqParams.CsrfToken,
			Identifier: reqParams.Identifier,
			Password:   reqParams.Password,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update login flow error", "err", err)
		views.passwordForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// view authentication code input page for aal2 (MFA)
	if kratos.SessionRequiredAal == kratos.Aal2 {
		addCookies(w, updateLoginFlowResp.Header.Cookie)
		setHeadersForReplaceBody(w, "/auth/login/mfa")
		views.mfa.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	session = &updateLoginFlowResp.Session

	// update settings(profile) flow after logged in
	if reqParams.UpdateSettingsAfterLoggedIn != "" {
		// create settings
		createSettingsFlowResp, kratosReqHeaderForNext, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: kratosReqHeaderForNext,
		})
		if err != nil {
			views.code.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}

		// update settings
		updateSettingsAfterLoggedIn(ctx, w, r, session,
			createSettingsFlowResp.SettingsFlow.FlowID,
			createSettingsFlowResp.SettingsFlow.CsrfToken,
			kratosReqHeaderForNext,
			updateSettingsAfterLoggedInParamsFromString(reqParams.UpdateSettingsAfterLoggedIn))
		return
	}

	addCookies(w, updateLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	views.top.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}
