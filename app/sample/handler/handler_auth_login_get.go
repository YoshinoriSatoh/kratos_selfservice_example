package handler

import (
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /auth/login
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthLogin
type getAuthLoginRequestParams struct {
	FlowID   string `validate:"omitempty,uuid4"`
	ReturnTo string `validate:"omitempty"`
}

// Extract parameters from http request
func newGetAuthLoginRequestParams(r *http.Request) *getAuthLoginRequestParams {
	return &getAuthLoginRequestParams{
		FlowID:   r.URL.Query().Get("flow"),
		ReturnTo: r.URL.Query().Get("return_to"),
	}
}

// Return parameters that can refer in view template
func (p *getAuthLoginRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID": p.FlowID,
		"ReturnTo":    p.ReturnTo,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getAuthLoginRequestParams) validate() *viewError {
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

func (p *Provider) handleGetAuthLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newGetAuthLoginRequestParams(r)

	// prepare views
	loginIndexView := newView("auth/login/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		loginIndexView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))

	// create or get registration Flow
	var (
		err                  error
		loginFlow            kratos.LoginFlow
		kratosResponseHeader kratos.KratosResponseHeader
	)
	if params.FlowID == "" {
		var createLoginFlowResp kratos.CreateLoginFlowResponse
		createLoginFlowResp, err = kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
			Header:  makeDefaultKratosRequestHeader(r),
			Refresh: isAuthenticated(session),
		})
		kratosResponseHeader = createLoginFlowResp.Header
		loginFlow = createLoginFlowResp.LoginFlow
	} else {
		var getLoginFlowResp kratos.GetLoginFlowResponse
		getLoginFlowResp, err = kratos.GetLoginFlow(ctx, kratos.GetLoginFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
			FlowID: params.FlowID,
		})
		kratosResponseHeader = getLoginFlowResp.Header
		loginFlow = getLoginFlowResp.LoginFlow
	}
	// OIDC Loginの場合、同一クレデンシャルが存在する場合、既存Identityとのリンクを促すためエラーにしない
	if err != nil && loginFlow.DuplicateIdentifier == "" {
		loginIndexView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// OIDC Loginの場合、同一クレデンシャルが存在する場合、既存Identityとのリンクを促す
	var (
		information        string
		traits             kratos.Traits
		showSocialLogin    bool
		identifierReadonly bool
	)
	if loginFlow.DuplicateIdentifier == "" {
		showSocialLogin = true
	} else {
		traits.Email = loginFlow.DuplicateIdentifier
		showSocialLogin = false
		information = "メールアドレスとパスワードで登録された既存のアカウントが存在します。パスワードを入力してログインすると、Googleのアカウントと連携されます。"
		identifierReadonly = true
	}

	// if existsAfterLoginHook(r, AFTER_LOGIN_HOOK_COOKIE_KEY_SETTINGS_PROFILE_UPDATE) {
	// 	information = "プロフィール更新のために、再度ログインをお願いします。"
	// }

	addCookies(w, kratosResponseHeader.Cookie)
	loginIndexView.addParams(map[string]any{
		"LoginFlowID":        loginFlow.FlowID,
		"Information":        information,
		"CsrfToken":          loginFlow.CsrfToken,
		"Traits":             traits,
		"ShowSocialLogin":    showSocialLogin,
		"ShowPasskeyLogin":   true,
		"IdentifierReadonly": identifierReadonly,
		"PasskeyChallenge":   loginFlow.PasskeyChallenge,
	}).render(w, r, session)
}
