package handler

import (
	"fmt"
	"log/slog"
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

func (p *Provider) handleGetAuthLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &getAuthLoginRequestParams{
		FlowID:   r.URL.Query().Get("flow"),
		ReturnTo: r.URL.Query().Get("return_to"),
	}

	// prepare views
	loginIndexView := newView(TPL_AUTH_LOGIN_INDEX).addParams(map[string]any{
		"LoginFlowID": reqParams.FlowID,
		"ReturnTo":    reqParams.ReturnTo,
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	for k := range viewError.validationFieldErrors {
		if k == "FlowID" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
		}
	}
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handlePostAuthLoginPassword validation error", "messages", viewError.messages)
		loginIndexView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// create or get registration Flow
	loginFlow, kratosRespHeader, _, err := kratos.CreateOrGetLoginFlow(ctx, kratos.CreateOrGetLoginFlowRequest{
		FlowID:  reqParams.FlowID,
		Header:  makeDefaultKratosRequestHeader(r),
		Refresh: isAuthenticated(session),
		Aal:     kratos.Aal1,
	})
	// OIDC Loginの場合、同一クレデンシャルが存在する場合、既存Identityとのリンクを促すためエラーにしない
	if err != nil && loginFlow.DuplicateIdentifier == "" {
		loginIndexView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
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

	addCookies(w, kratosRespHeader.Cookie)
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
// POST /auth/login/password
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginPassword
type postAuthLoginPasswordRequestParams struct {
	FlowID                string `validate:"uuid4"`
	CsrfToken             string `validate:"required"`
	Identifier            string `validate:"required,email" ja:"メールアドレス"`
	Password              string `validate:"required" ja:"パスワード"`
	UpdateSettingsRequest string
}

func (p *Provider) handlePostAuthLoginPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &postAuthLoginPasswordRequestParams{
		FlowID:                r.URL.Query().Get("flow"),
		CsrfToken:             r.PostFormValue("csrf_token"),
		Identifier:            r.PostFormValue("identifier"),
		Password:              r.PostFormValue("password"),
		UpdateSettingsRequest: r.PostFormValue("update_settings_request"),
	}

	// prepare views
	passwordFormView := newView(TPL_AUTH_LOGIN_FORM).addParams(map[string]any{
		"LoginFlowID":           reqParams.FlowID,
		"CsrfToken":             reqParams.CsrfToken,
		"Identifier":            reqParams.Identifier,
		"Password":              reqParams.Password,
		"UpdateSettingsRequest": reqParams.UpdateSettingsRequest,
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handlePostAuthLoginPassword validation error", "messages", viewError.messages)
		passwordFormView.addParams(viewError.toViewParams()).render(w, r, session)
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
		UpdateSettingsRequest: reqParams.UpdateSettingsRequest,
	})
	if err != nil {
		slog.ErrorContext(ctx, "update login flow error", "err", err)
		passwordFormView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	session = &updateLoginFlowResp.Session
	addCookies(w, updateLoginFlowResp.Header.Cookie)

	// view profile page when updated settings after logged in. if required validation of email, view verification page with rendered profile page.
	if reqParams.UpdateSettingsRequest != "" {
		createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: kratosReqHeaderForNext,
		})
		if err != nil {
			slog.ErrorContext(ctx, "create settings flow error", "err", err)
			passwordFormView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
			return
		}

		settingsView := settingsView(updateLoginFlowResp.SettingsUpdatedMethod, session, createSettingsFlowResp.SettingsFlow)
		if updateLoginFlowResp.VerificationFlow != nil {
			// render verification code page (replace <body> tag and push url)
			addCookies(w, updateLoginFlowResp.VerificationFlowCookie)
			setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", updateLoginFlowResp.VerificationFlow.FlowID))
			newView(TPL_AUTH_VERIFICATION_CODE).addParams(map[string]any{
				"VerificationFlowID": updateLoginFlowResp.VerificationFlow.FlowID,
				"CsrfToken":          updateLoginFlowResp.VerificationFlow.CsrfToken,
				"IsUsedFlow":         updateLoginFlowResp.VerificationFlow.IsUsedFlow(),
				"Render":             settingsView.toQueryParam(),
			}).render(w, r, session)
		} else {
			settingsView.render(w, r, session)
		}
		return
	}

	// view authentication code input page for aal2 (MFA)
	if updateLoginFlowResp.RequiredAal2 {
		setHeadersForReplaceBody(w, "/auth/login/totp")
		newView(TPL_AUTH_LOGIN_TOTP).addParams(map[string]any{
			"LoginFlowID":           reqParams.FlowID,
			"CsrfToken":             reqParams.CsrfToken,
			"Identifier":            reqParams.Identifier,
			"Password":              reqParams.Password,
			"UpdateSettingsRequest": reqParams.UpdateSettingsRequest,
		}).render(w, r, session)
		return
	}

	// view top page
	setHeadersForReplaceBody(w, "/")
	newView(TPL_TOP_INDEX).addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/login/passkey
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginPasskey
type postAuthLoginPasskeyRequestParams struct {
	FlowID                string `validate:"uuid4"`
	CsrfToken             string `validate:"required"`
	PasskeyLogin          string `validate:"required"`
	PasskeyChallenge      string `validate:"required"`
	UpdateSettingsRequest string
}

func (p *Provider) handlePostAuthLoginPasskey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := postAuthLoginPasskeyRequestParams{
		FlowID:                r.URL.Query().Get("flow"),
		CsrfToken:             r.PostFormValue("csrf_token"),
		PasskeyLogin:          r.PostFormValue("passkey_login"),
		PasskeyChallenge:      r.PostFormValue("passkey_challenge"),
		UpdateSettingsRequest: r.PostFormValue("update_settings_request"),
	}

	// prepare views
	passkeyFormView := newView(TPL_AUTH_LOGIN_FORM).addParams(map[string]any{
		"LoginFlowID":           reqParams.FlowID,
		"CsrfToken":             reqParams.CsrfToken,
		"PasskeyLogin":          reqParams.PasskeyLogin,
		"PasskeyChallenge":      reqParams.PasskeyChallenge,
		"UpdateSettingsRequest": reqParams.UpdateSettingsRequest,
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handlePostAuthLoginPasskey validation error", "messages", viewError.messages)
		passkeyFormView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

	// update login flow
	updateLoginFlowResp, kratosReqHeaderForNext, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.FlowID,
		Header: kratosRequestHeader,
		Aal:    kratos.Aal1,
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:       "passkey",
			CsrfToken:    reqParams.CsrfToken,
			PasskeyLogin: reqParams.PasskeyLogin,
		},
		UpdateSettingsRequest: reqParams.UpdateSettingsRequest,
	})
	if err != nil {
		passkeyFormView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	session = &updateLoginFlowResp.Session
	addCookies(w, updateLoginFlowResp.Header.Cookie)

	// view passkey settings page when updated settings after logged in.
	if reqParams.UpdateSettingsRequest != "" {
		createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: kratosReqHeaderForNext,
		})
		if err != nil {
			slog.ErrorContext(ctx, "create settings flow error", "err", err)
			passkeyFormView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
			return
		}
		settingsView(updateLoginFlowResp.SettingsUpdatedMethod, session, createSettingsFlowResp.SettingsFlow).render(w, r, session)
		return
	}

	// view authentication code input page for aal2 (MFA)
	if updateLoginFlowResp.RequiredAal2 {
		setHeadersForReplaceBody(w, "/auth/login/totp")
		newView(TPL_AUTH_LOGIN_TOTP).addParams(map[string]any{
			"LoginFlowID":           reqParams.FlowID,
			"CsrfToken":             reqParams.CsrfToken,
			"PasskeyLogin":          reqParams.PasskeyLogin,
			"PasskeyChallenge":      reqParams.PasskeyChallenge,
			"UpdateSettingsRequest": reqParams.UpdateSettingsRequest,
		}).render(w, r, session)
		return
	}

	// view top page
	setHeadersForReplaceBody(w, "/")
	newView(TPL_TOP_INDEX).addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/login/oidc
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginOidc
type postAuthLoginOidcRequestParams struct {
	FlowID                string `validate:"uuid4"`
	CsrfToken             string `validate:"required"`
	Provider              string `validate:"required"`
	UpdateSettingsRequest string
}

func (p *Provider) handlePostAuthLoginOidc(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := postAuthLoginOidcRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Provider:  r.PostFormValue("provider"),
	}

	// prepare views
	loginView := newView(TPL_AUTH_LOGIN_INDEX).addParams(map[string]any{
		"LoginFlowID":           reqParams.FlowID,
		"CsrfToken":             reqParams.CsrfToken,
		"Provider":              reqParams.Provider,
		"UpdateSettingsRequest": reqParams.UpdateSettingsRequest,
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handlePostAuthLoginOidc validation error", "messages", viewError.messages)
		loginView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// update login flow
	updateLoginFlowResp, kratosReqHeaderForNext, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Aal:    kratos.Aal1,
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:    "oidc",
			CsrfToken: reqParams.CsrfToken,
			Provider:  reqParams.Provider,
		},
		UpdateSettingsRequest: reqParams.UpdateSettingsRequest,
	})
	if err != nil {
		loginView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	session = &updateLoginFlowResp.Session
	addCookies(w, updateLoginFlowResp.Header.Cookie)

	// view passkey settings page when updated settings after logged in.
	if reqParams.UpdateSettingsRequest != "" {
		createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: kratosReqHeaderForNext,
		})
		if err != nil {
			slog.ErrorContext(ctx, "create settings flow error", "err", err)
			loginView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
			return
		}
		settingsView(updateLoginFlowResp.SettingsUpdatedMethod, session, createSettingsFlowResp.SettingsFlow).render(w, r, session)
		return
	}

	if updateLoginFlowResp.RedirectBrowserTo != "" {
		slog.DebugContext(ctx, "redirect occured", "RedirectBrowserTo", updateLoginFlowResp.RedirectBrowserTo)
		redirect(w, r, updateLoginFlowResp.RedirectBrowserTo, map[string]string{})
		return
	}

	// render
	setHeadersForReplaceBody(w, "/")
	loginView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// GET /auth/login/code
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthLoginCode
type getAuthLoginCodeRequestParams struct {
	FlowID string `validate:"uuid4"`
}

func (p *Provider) handleGetAuthLoginCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &getAuthLoginCodeRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	loginCodeView := newView(TPL_AUTH_LOGIN_CODE)

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	for k := range viewError.validationFieldErrors {
		if k == "FlowID" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
		}
	}
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handlePostAuthLoginPassword validation error", "messages", viewError.messages)
		loginCodeView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// create and update login flow for aal2, send authentication code
	createLoginFlowAal2Resp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
		Header:  makeDefaultKratosRequestHeader(r),
		Aal:     kratos.Aal2,
		Refresh: true,
	})
	if err != nil {
		slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
		loginCodeView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update login flow
	updateLoginFlowResp, _, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: createLoginFlowAal2Resp.LoginFlow.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Aal:    kratos.Aal2,
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:     "code",
			CsrfToken:  createLoginFlowAal2Resp.LoginFlow.CsrfToken,
			Identifier: createLoginFlowAal2Resp.LoginFlow.CodeAddress,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update login flow for aal2 error", "err", err)
		loginCodeView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, updateLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/auth/login/code")
	loginCodeView.addParams(map[string]any{
		"LoginFlowID": createLoginFlowAal2Resp.LoginFlow.FlowID,
		"CsrfToken":   createLoginFlowAal2Resp.LoginFlow.CsrfToken,
		"Identifier":  createLoginFlowAal2Resp.LoginFlow.CodeAddress,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/login/code
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginCode
type postAuthLoginCodeRequestParams struct {
	FlowID                string `validate:"uuid4"`
	CsrfToken             string `validate:"required"`
	Identifier            string `validate:"required,email" ja:"メールアドレス"`
	Code                  string `validate:"required" ja:"認証コード"`
	UpdateSettingsRequest string
	SettingsFlowID        string
}

// Return parameters that can refer in view template
func (p *postAuthLoginCodeRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID":           p.FlowID,
		"CsrfToken":             p.CsrfToken,
		"Identifier":            p.Identifier,
		"Code":                  p.Code,
		"UpdateSettingsRequest": p.UpdateSettingsRequest,
		"SettingsFlowID":        p.SettingsFlowID,
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

func (p *Provider) handlePostAuthLoginCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &postAuthLoginCodeRequestParams{
		FlowID:                r.URL.Query().Get("flow"),
		CsrfToken:             r.PostFormValue("csrf_token"),
		Identifier:            r.PostFormValue("identifier"),
		Code:                  r.PostFormValue("code"),
		UpdateSettingsRequest: r.PostFormValue("update_settings_request"),
	}

	// prepare views
	loginCodeView := newView(TPL_AUTH_LOGIN_CODE).addParams(reqParams.toViewParams())

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		loginCodeView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

	// update login flow
	updateLoginFlowResp, kratosReqHeaderForNext, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.FlowID,
		Header: kratosRequestHeader,
		Aal:    kratos.Aal2,
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:     "code",
			CsrfToken:  reqParams.CsrfToken,
			Identifier: reqParams.Identifier,
			Code:       reqParams.Code,
		},
		UpdateSettingsRequest: reqParams.UpdateSettingsRequest,
	})
	if err != nil {
		slog.ErrorContext(ctx, "update login flow error", "err", err)
		loginCodeView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	session = &updateLoginFlowResp.Session
	addCookies(w, updateLoginFlowResp.Header.Cookie)

	// view passkey settings page when updated settings after logged in.
	if reqParams.UpdateSettingsRequest != "" {
		if updateLoginFlowResp.SettingsUpdatedMethod == "profile" {
			setHeadersForReplaceBody(w, "/my/profile")
			redirect(w, r, "/my/profile", map[string]string{
				"information": "プロフィールが更新されました。",
			})
		} else if updateLoginFlowResp.SettingsUpdatedMethod == "password" {
			setHeadersForReplaceBody(w, "/my/password")
			redirect(w, r, "/my/password", map[string]string{
				"information": "パスワードが設定されました。",
			})
		} else if updateLoginFlowResp.SettingsUpdatedMethod == "totp" {
			setHeadersForReplaceBody(w, "/my/totp")
			redirect(w, r, "/my/totp", map[string]string{
				"information": "認証アプリが設定されました。",
			})
		}
		return
	}

	if reqParams.SettingsFlowID != "" {
		getSettingsFlowResp, _, err := kratos.GetSettingsFlow(ctx, kratos.GetSettingsFlowRequest{
			FlowID: reqParams.SettingsFlowID,
			Header: kratosReqHeaderForNext,
		})
		if err != nil {
			slog.ErrorContext(ctx, "get settings flow error", "err", err)
			loginCodeView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
			return
		}
		setHeadersForReplaceBody(w, fmt.Sprintf("/my/password?flow=%s", reqParams.SettingsFlowID))
		newView("my/password.html").addParams(map[string]any{
			"SettingsFlowID": reqParams.SettingsFlowID,
			"CsrfToken":      getSettingsFlowResp.SettingsFlow.CsrfToken,
		}).render(w, r, session)
	}

	// view top page
	addCookies(w, updateLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	newView(TPL_TOP_INDEX).addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// GET /auth/login/totp
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthLoginTotp
type getAuthLoginTotpRequestParams struct {
	UpdateSettingsRequest string
}

func (p *Provider) handleGetAuthLoginTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &getAuthLoginTotpRequestParams{
		UpdateSettingsRequest: r.PostFormValue("update_settings_request"),
	}

	// prepare views
	totpView := newView(TPL_AUTH_LOGIN_TOTP).addParams(map[string]any{
		"UpdateSettingsRequest": reqParams.UpdateSettingsRequest,
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	for k := range viewError.validationFieldErrors {
		if k == "FlowID" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
		}
	}
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handleGetAuthLoginTotp validation error", "messages", viewError.messages)
		totpView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// create and update login flow for aal2, send authentication code
	createLoginFlowAal2Resp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
		Header:  makeDefaultKratosRequestHeader(r),
		Aal:     kratos.Aal2,
		Refresh: true,
	})
	if err != nil {
		slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
		totpView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
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
		totpView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, updateLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/auth/login/totp")
	totpView.addParams(map[string]any{
		"LoginFlowID": createLoginFlowAal2Resp.LoginFlow.FlowID,
		"CsrfToken":   createLoginFlowAal2Resp.LoginFlow.CsrfToken,
		"Identifier":  createLoginFlowAal2Resp.LoginFlow.CodeAddress,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/login/totp
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginTotp
type postAuthLoginTotpRequestParams struct {
	FlowID                string `validate:"uuid4"`
	CsrfToken             string `validate:"required"`
	Identifier            string `validate:"required,email" ja:"メールアドレス"`
	TotpCode              string `validate:"required" ja:"認証コード"`
	UpdateSettingsRequest string
}

func (p *Provider) handlePostAuthLoginTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &postAuthLoginTotpRequestParams{
		FlowID:                r.URL.Query().Get("flow"),
		CsrfToken:             r.PostFormValue("csrf_token"),
		Identifier:            r.PostFormValue("identifier"),
		TotpCode:              r.PostFormValue("totp_code"),
		UpdateSettingsRequest: r.PostFormValue("update_settings_request"),
	}

	// prepare views
	totpFormView := newView(TPL_AUTH_LOGIN_TOTP).addParams(map[string]any{
		"LoginFlowID":           reqParams.FlowID,
		"CsrfToken":             reqParams.CsrfToken,
		"Identifier":            reqParams.Identifier,
		"Totp":                  reqParams.TotpCode,
		"UpdateSettingsRequest": reqParams.UpdateSettingsRequest,
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handlePostAuthLoginTotp validation error", "messages", viewError.messages)
		totpFormView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// update login flow
	updateLoginFlowResp, kratosReqHeaderForNext, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Aal:    kratos.Aal2,
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:     "totp",
			CsrfToken:  reqParams.CsrfToken,
			Identifier: reqParams.Identifier,
			TotpCode:   reqParams.TotpCode,
		},
		UpdateSettingsRequest: reqParams.UpdateSettingsRequest,
	})
	if err != nil {
		slog.ErrorContext(ctx, "update login flow error", "err", err)
		totpFormView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	session = &updateLoginFlowResp.Session
	addCookies(w, updateLoginFlowResp.Header.Cookie)

	// view passkey settings page when updated settings after logged in.
	if reqParams.UpdateSettingsRequest != "" {
		createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: kratosReqHeaderForNext,
		})
		if err != nil {
			slog.ErrorContext(ctx, "create settings flow error", "err", err)
			totpFormView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
			return
		}
		settingsView(updateLoginFlowResp.SettingsUpdatedMethod, session, createSettingsFlowResp.SettingsFlow).render(w, r, session)
		return
	}

	// view top page
	setHeadersForReplaceBody(w, "/")
	newView(TPL_TOP_INDEX).addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/logout
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLogout
type postAuthLogoutRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
}

func (p *Provider) handlePostAuthLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &postAuthLogoutRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	logoutView := newView("auth/logout/index.html").addParams(map[string]any{
		"LogoutFlowID": reqParams.FlowID,
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	for k := range viewError.validationFieldErrors {
		if k == "FlowID" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
		}
	}
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handlePostAuthLogout validation error", "messages", viewError.messages)
		logoutView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// logout
	logoutResp, _, err := kratos.Logout(ctx, kratos.LogoutRequest{
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		slog.ErrorContext(ctx, "logout error", "err", err)
		logoutView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// change location
	addCookies(w, logoutResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	w.Header().Set("HX-Location", "/")
}
