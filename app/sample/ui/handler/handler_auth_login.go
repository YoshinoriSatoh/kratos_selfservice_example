package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/external/kratos"

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
		createLoginFlowResp, err = p.d.Kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
			Header:  makeDefaultKratosRequestHeader(r),
			Refresh: isAuthenticated(session),
		})
		kratosResponseHeader = createLoginFlowResp.Header
		loginFlow = createLoginFlowResp.LoginFlow
	} else {
		var getLoginFlowResp kratos.GetLoginFlowResponse
		getLoginFlowResp, err = p.d.Kratos.GetLoginFlow(ctx, kratos.GetLoginFlowRequest{
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

// --------------------------------------------------------------------------
// POST /auth/login
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLogin
type postAuthLoginRequestParams struct {
	FlowID     string `validate:"uuid4"`
	CsrfToken  string `validate:"required"`
	Identifier string `validate:"required,email" ja:"メールアドレス"`
	Password   string `validate:"required" ja:"パスワード"`
	Render     string
	Hook       string
}

// Extract parameters from http request
func newPostAuthLoginRequestParams(r *http.Request) *postAuthLoginRequestParams {
	return &postAuthLoginRequestParams{
		FlowID:     r.URL.Query().Get("flow"),
		Render:     r.PostFormValue("render"),
		Hook:       r.PostFormValue("hook"),
		CsrfToken:  r.PostFormValue("csrf_token"),
		Identifier: r.PostFormValue("identifier"),
		Password:   r.PostFormValue("password"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthLoginRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID": p.FlowID,
		"Render":      p.Render,
		"Hook":        p.Hook,
		"CsrfToken":   p.CsrfToken,
		"Identifier":  p.Identifier,
		"Password":    p.Password,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthLoginRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostAuthLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAuthLoginRequestParams(r)

	// prepare views
	loginFormView := newView("auth/login/_form.html").addParams(params.toViewParams())
	topIndexView := newView("top/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		slog.ErrorContext(ctx, "validation error", "viewError", viewError)
		loginFormView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))

	// update login flow
	updateLoginFlowResp, err := p.d.Kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:     "password",
			CsrfToken:  params.CsrfToken,
			Identifier: params.Identifier,
			Password:   params.Password,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update login flow error", "err", err)
		loginFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	session = &updateLoginFlowResp.Session

	if params.Hook != "" {
		h := hookFromQueryParam(params.Hook)
		if h.HookID == HookIDUpdateSettingsProfile {
			kratosRequestHeader := makeDefaultKratosRequestHeader(r)
			kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, updateLoginFlowResp.Header.Cookie)
			kratosResp, err := p.d.Kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
				FlowID: h.UpdateSettingsProfileParams.FlowID,
				Header: kratosRequestHeader,
				Body: kratos.UpdateSettingsFlowRequestBody{
					CsrfToken: params.CsrfToken,
					Method:    "profile",
					Traits:    h.UpdateSettingsProfileParams.Traits,
				},
			})
			if err != nil {
				loginFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
				return
			}
			if kratosResp.VerificationFlowID != "" {
				// transition to verification flow from settings flow
				// Transferring cookies from update registration flow response
				kratosRequestHeader := makeDefaultKratosRequestHeader(r)
				kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, kratosResp.Header.Cookie)
				// get verification flow
				getVerificationFlowResp, err := p.d.Kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
					FlowID: kratosResp.VerificationFlowID,
					Header: kratosRequestHeader,
				})
				if err != nil {
					slog.DebugContext(ctx, "get verification error", "err", err.Error())
					loginFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				whoamiResp, _ := p.d.Kratos.Whoami(ctx, kratos.WhoamiRequest{
					Header: kratosRequestHeader,
				})

				createSettingsFlowResp, err := p.d.Kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
					Header: makeDefaultKratosRequestHeader(r),
				})
				if err != nil {
					loginFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// for re-render profile form
				year, month, day := parseDate(h.UpdateSettingsProfileParams.Traits.Birthdate)
				myProfileIndexView := newView("my/profile/index.html").addParams(map[string]any{
					"SettingsFlowID": createSettingsFlowResp.SettingsFlow.FlowID,
					"Information":    "プロフィールが更新されました。",
					"CsrfToken":      createSettingsFlowResp.SettingsFlow.CsrfToken,
					"Email":          whoamiResp.Session.Identity.Traits.Email,
					"Firstname":      whoamiResp.Session.Identity.Traits.Firstname,
					"Lastname":       whoamiResp.Session.Identity.Traits.Lastname,
					"Nickname":       whoamiResp.Session.Identity.Traits.Nickname,
					"BirthdateYear":  year,
					"BirthdateMonth": month,
					"BirthdateDay":   day,
				})

				// render verification code page (replace <body> tag and push url)
				addCookies(w, getVerificationFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", getVerificationFlowResp.VerificationFlow.FlowID))
				newView("auth/verification/code.html").addParams(params.toViewParams()).addParams(map[string]any{
					"VerificationFlowID": getVerificationFlowResp.VerificationFlow.FlowID,
					"CsrfToken":          getVerificationFlowResp.VerificationFlow.CsrfToken,
					"IsUsedFlow":         getVerificationFlowResp.VerificationFlow.IsUsedFlow(),
					"Render":             myProfileIndexView.toQueryParam(),
				}).render(w, r, session)
				return
			}
			whoamiResp, _ := p.d.Kratos.Whoami(ctx, kratos.WhoamiRequest{
				Header: kratosRequestHeader,
			})

			createSettingsFlowResp, err := p.d.Kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
				Header: makeDefaultKratosRequestHeader(r),
			})
			if err != nil {
				loginFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
				return
			}
			year, month, day := parseDate(h.UpdateSettingsProfileParams.Traits.Birthdate)
			addCookies(w, updateLoginFlowResp.Header.Cookie)
			setHeadersForReplaceBody(w, "/my/profile")
			newView("my/profile/index.html").addParams(map[string]any{
				"SettingsFlowID": createSettingsFlowResp.SettingsFlow.FlowID,
				"Information":    "プロフィールが更新されました。",
				"CsrfToken":      createSettingsFlowResp.SettingsFlow.CsrfToken,
				"Email":          whoamiResp.Session.Identity.Traits.Email,
				"Firstname":      whoamiResp.Session.Identity.Traits.Firstname,
				"Lastname":       whoamiResp.Session.Identity.Traits.Lastname,
				"Nickname":       whoamiResp.Session.Identity.Traits.Nickname,
				"BirthdateYear":  year,
				"BirthdateMonth": month,
				"BirthdateDay":   day,
			}).render(w, r, whoamiResp.Session)
		}
		return
	}

	if params.Render != "" {
		v := viewFromQueryParam(params.Render)
		setHeadersForReplaceBody(w, v.Path)
		viewFromQueryParam(params.Render).render(w, r, session)
		return
	}

	addCookies(w, updateLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	topIndexView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}

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
	updateLoginFlowResp, err := p.d.Kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
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
	updateLoginFlowResp, err := p.d.Kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
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

// --------------------------------------------------------------------------
// POST /auth/logout
// --------------------------------------------------------------------------
func (p *Provider) handlePostAuthLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	topIndexView := newView("top/index.html")

	updateLogoutFlowResp, err := p.d.Kratos.Logout(ctx, kratos.LogoutRequest{
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		setHeadersForReplaceBody(w, "/")
		topIndexView.addParams(map[string]any{
			"Items": items,
		}).render(w, r, session)
	}

	// change location
	addCookies(w, updateLogoutFlowResp.Header.Cookie)
	w.Header().Set("HX-Location", "/")
}
