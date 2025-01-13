package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /auth/login/code
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginCode
type postAuthLoginCodeRequestParams struct {
	FlowID                      string `validate:"uuid4"`
	CsrfToken                   string `validate:"required"`
	Identifier                  string `validate:"required,email" ja:"メールアドレス"`
	Code                        string `validate:"required" ja:"認証コード"`
	UpdateSettingsAfterLoggedIn string
}

// Extract parameters from http request
func newPostAuthLoginCodeRequestParams(r *http.Request) *postAuthLoginCodeRequestParams {
	return &postAuthLoginCodeRequestParams{
		FlowID:                      r.URL.Query().Get("flow"),
		CsrfToken:                   r.PostFormValue("csrf_token"),
		Identifier:                  r.PostFormValue("identifier"),
		Code:                        r.PostFormValue("code"),
		UpdateSettingsAfterLoggedIn: r.PostFormValue("update_settings_after_logged_in"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthLoginCodeRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID":                 p.FlowID,
		"CsrfToken":                   p.CsrfToken,
		"Identifier":                  p.Identifier,
		"Code":                        p.Code,
		"UpdateSettingsAfterLoggedIn": p.UpdateSettingsAfterLoggedIn,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthLoginCodeRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getAuthLoginCodePostViews struct {
	code *view
	top  *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthLoginCodePost(w http.ResponseWriter, r *http.Request) (*postAuthLoginCodeRequestParams, getAuthLoginCodePostViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))
	reqParams := newPostAuthLoginCodeRequestParams(r)
	views := getAuthLoginCodePostViews{
		code: newView("auth/login/code.html").addParams(reqParams.toViewParams()),
		top:  newView("top/index.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.code.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthLoginCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthLoginCodePost(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthLoginPost failed", "err", err)
		return
	}

	// update login flow
	updateLoginFlowResp, kratosReqHeaderForNext, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Aal:    kratos.Aal2,
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:     "code",
			CsrfToken:  reqParams.CsrfToken,
			Identifier: reqParams.Identifier,
			Code:       reqParams.Code,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update login flow error", "err", err)
		views.code.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	session = &updateLoginFlowResp.Session

	slog.Debug("handlePostAuthLoginCode", "kratosReqHeaderForNext", kratosReqHeaderForNext, "updateLoginFlowResp", updateLoginFlowResp)

	slog.DebugContext(ctx, "handlePostAuthLoginCode", "reqParams", reqParams)
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

		slog.Debug("handlePostAuthLoginCode", "kratosReqHeaderForNext", kratosReqHeaderForNext, "createSettingsFlowResp", createSettingsFlowResp)

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
