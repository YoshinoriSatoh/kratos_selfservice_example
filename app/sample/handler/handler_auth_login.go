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

	// get request parameters
	reqParams := &getAuthLoginRequestParams{
		FlowID:   r.URL.Query().Get("flow"),
		ReturnTo: r.URL.Query().Get("return_to"),
	}

	// prepare views
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))
	loginIndexView := newView("auth/login/index.html").addParams(reqParams.toViewParams())

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
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

// Return parameters that can refer in view template
func (p *postAuthLoginPasswordRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID":           p.FlowID,
		"CsrfToken":             p.CsrfToken,
		"Identifier":            p.Identifier,
		"Password":              p.Password,
		"UpdateSettingsRequest": p.UpdateSettingsRequest,
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
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))
	passwordFormView := newView("auth/login/_password_form.html").addParams(reqParams.toViewParams())

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
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
		passwordFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
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
			passwordFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}

		settingsView := settingsView(updateLoginFlowResp.SettingsUpdatedMethod, session, createSettingsFlowResp.SettingsFlow)
		if updateLoginFlowResp.VerificationFlow != nil {
			// render verification code page (replace <body> tag and push url)
			addCookies(w, updateLoginFlowResp.VerificationFlowCookie)
			setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", updateLoginFlowResp.VerificationFlow.FlowID))
			newView("auth/verification/code.html").addParams(map[string]any{
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
		setHeadersForReplaceBody(w, "/auth/login/mfa")
		newView("auth/login/mfa.html").addParams(reqParams.toViewParams()).render(w, r, session)
		return
	}

	// view top page
	setHeadersForReplaceBody(w, "/")
	newView("top/index.html").addParams(reqParams.toViewParams()).addParams(map[string]any{
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

// Extract parameters from http request
func newPostAuthLoginPasskeyRequestParams(r *http.Request) *postAuthLoginPasskeyRequestParams {
	return &postAuthLoginPasskeyRequestParams{
		FlowID:                r.URL.Query().Get("flow"),
		CsrfToken:             r.PostFormValue("csrf_token"),
		PasskeyLogin:          r.PostFormValue("passkey_login"),
		PasskeyChallenge:      r.PostFormValue("passkey_challenge"),
		UpdateSettingsRequest: r.PostFormValue("update_settings_request"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthLoginPasskeyRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID":           p.FlowID,
		"CsrfToken":             p.CsrfToken,
		"PasskeyLogin":          p.PasskeyLogin,
		"PasskeyChallenge":      p.PasskeyChallenge,
		"UpdateSettingsRequest": p.UpdateSettingsRequest,
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

// Views
type getAuthLoginPasskeyViews struct {
	index *view
	form  *view
	mfa   *view
}

// collect rendering data and validate request parameters.
func preparePostAuthLoginPasskey(w http.ResponseWriter, r *http.Request) (*postAuthLoginPasskeyRequestParams, getAuthLoginPasskeyViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))
	reqParams := newPostAuthLoginPasskeyRequestParams(r)
	views := getAuthLoginPasskeyViews{
		index: newView("top/index.html").addParams(reqParams.toViewParams()),
		form:  newView("auth/login/_passkey_form.html").addParams(reqParams.toViewParams()),
		mfa:   newView("auth/login/mfa.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.form.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthLoginPasskey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := preparePostAuthLoginPasskey(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "preparePostAuthLoginPasskey failed", "err", err)
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
		views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
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
			views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}
		settingsView(updateLoginFlowResp.SettingsUpdatedMethod, session, createSettingsFlowResp.SettingsFlow).render(w, r, session)
		return
	}

	// view authentication code input page for aal2 (MFA)
	if kratos.SessionRequiredAal == kratos.Aal2 {
		setHeadersForReplaceBody(w, "/auth/login/mfa")
		views.mfa.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// view top page
	setHeadersForReplaceBody(w, "/")
	views.index.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/login/oidc
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLogin
type postAuthLoginOidcRequestParams struct {
	FlowID                string `validate:"uuid4"`
	CsrfToken             string `validate:"required"`
	Provider              string `validate:"required"`
	UpdateSettingsRequest string
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
		"LoginFlowID":           p.FlowID,
		"CsrfToken":             p.CsrfToken,
		"Provider":              p.Provider,
		"UpdateSettingsRequest": p.UpdateSettingsRequest,
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
		views.index.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
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
			views.index.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}
		settingsView(updateLoginFlowResp.SettingsUpdatedMethod, session, createSettingsFlowResp.SettingsFlow).render(w, r, session)
		return
	}

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

// --------------------------------------------------------------------------
// GET /auth/login/code
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthLoginCode
type getAuthLoginCodeRequestParams struct {
}

// Extract parameters from http request
func newGetAuthLoginCodeRequestParams(r *http.Request) *getAuthLoginCodeRequestParams {
	return &getAuthLoginCodeRequestParams{}
}

// Return parameters that can refer in view template
func (p *getAuthLoginCodeRequestParams) toViewParams() map[string]any {
	return map[string]any{}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getAuthLoginCodeRequestParams) validate() *viewError {
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
type getAuthLoginCodeViews struct {
	code *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthLoginCode(w http.ResponseWriter, r *http.Request) (*getAuthLoginCodeRequestParams, getAuthLoginCodeViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))
	reqParams := newGetAuthLoginCodeRequestParams(r)
	views := getAuthLoginCodeViews{
		code: newView("auth/login/code.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.code.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handleGetAuthLoginCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	_, views, baseViewError, err := prepareGetAuthLoginCode(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthLoginCode failed", "err", err)
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
		views.code.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
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
		views.code.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, updateLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/auth/login/code")
	views.code.addParams(map[string]any{
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

// Extract parameters from http request
func newPostAuthLoginCodeRequestParams(r *http.Request) *postAuthLoginCodeRequestParams {
	return &postAuthLoginCodeRequestParams{
		FlowID:                r.URL.Query().Get("flow"),
		CsrfToken:             r.PostFormValue("csrf_token"),
		Identifier:            r.PostFormValue("identifier"),
		Code:                  r.PostFormValue("code"),
		UpdateSettingsRequest: r.PostFormValue("update_settings_request"),
	}
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
		views.code.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
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
			views.code.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}
		settingsView(updateLoginFlowResp.SettingsUpdatedMethod, session, createSettingsFlowResp.SettingsFlow).render(w, r, session)
		return
	}

	if reqParams.SettingsFlowID != "" {
		getSettingsFlowResp, _, err := kratos.GetSettingsFlow(ctx, kratos.GetSettingsFlowRequest{
			FlowID: reqParams.SettingsFlowID,
			Header: kratosReqHeaderForNext,
		})
		if err != nil {
			slog.ErrorContext(ctx, "get settings flow error", "err", err)
			views.code.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
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
	views.top.addParams(map[string]any{
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

// Extract parameters from http request
func newGetAuthLoginTotpRequestParams(r *http.Request) *getAuthLoginTotpRequestParams {
	return &getAuthLoginTotpRequestParams{
		UpdateSettingsRequest: r.PostFormValue("update_settings_request"),
	}
}

// Return parameters that can refer in view template
func (p *getAuthLoginTotpRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"UpdateSettingsRequest": p.UpdateSettingsRequest,
	}
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
	reqParams, views, baseViewError, err := prepareGetAuthLoginTotp(w, r)
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
	updateLoginFlowResp, kratosReqHeaderForNext, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
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
			views.totp.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}
		settingsView(updateLoginFlowResp.SettingsUpdatedMethod, session, createSettingsFlowResp.SettingsFlow).render(w, r, session)
		return
	}

	// view top page
	setHeadersForReplaceBody(w, "/auth/login/totp")
	views.totp.addParams(map[string]any{
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

// Extract parameters from http request
func newPostAuthLoginTotpRequestParams(r *http.Request) *postAuthLoginTotpRequestParams {
	return &postAuthLoginTotpRequestParams{
		FlowID:                r.URL.Query().Get("flow"),
		CsrfToken:             r.PostFormValue("csrf_token"),
		Identifier:            r.PostFormValue("identifier"),
		TotpCode:              r.PostFormValue("totp_code"),
		UpdateSettingsRequest: r.PostFormValue("update_settings_request"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthLoginTotpRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID":           p.FlowID,
		"CsrfToken":             p.CsrfToken,
		"Identifier":            p.Identifier,
		"Totp":                  p.TotpCode,
		"UpdateSettingsRequest": p.UpdateSettingsRequest,
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

	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

	// update login flow
	updateLoginFlowResp, kratosReqHeaderForNext, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.FlowID,
		Header: kratosRequestHeader,
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

	// view passkey settings page when updated settings after logged in.
	if reqParams.UpdateSettingsRequest != "" {
		createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: kratosReqHeaderForNext,
		})
		if err != nil {
			slog.ErrorContext(ctx, "create settings flow error", "err", err)
			views.totpForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}
		settingsView(updateLoginFlowResp.SettingsUpdatedMethod, session, createSettingsFlowResp.SettingsFlow).render(w, r, session)
		return
	}

	addCookies(w, updateLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	views.top.addParams(map[string]any{
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

// Extract parameters from http request
func newPostAuthLogoutRequestParams(r *http.Request) *postAuthLogoutRequestParams {
	return &postAuthLogoutRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthLogoutRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LogoutFlowID": p.FlowID,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *postAuthLogoutRequestParams) validate() *viewError {
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
type postAuthLogoutViews struct {
	index *view
	top   *view
}

// collect rendering data and validate request parameters.
func preparePostAuthLogout(w http.ResponseWriter, r *http.Request) (*postAuthLogoutRequestParams, postAuthLogoutViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGOUT_DEFAULT",
	}))
	reqParams := newPostAuthLogoutRequestParams(r)
	views := postAuthLogoutViews{
		index: newView("auth/logout/index.html").addParams(reqParams.toViewParams()),
		top:   newView("top/index.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.index.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	_, views, _, err := preparePostAuthLogout(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "preparePostAuthLogout failed", "err", err)
		return
	}

	updateLogoutFlowResp, _, err := kratos.Logout(ctx, kratos.LogoutRequest{
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		setHeadersForReplaceBody(w, "/")
		views.top.addParams(map[string]any{
			"Items": items,
		}).render(w, r, session)
	}

	// change location
	addCookies(w, updateLogoutFlowResp.Header.Cookie)
	w.Header().Set("HX-Location", "/")
}
