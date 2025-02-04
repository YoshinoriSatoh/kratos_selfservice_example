package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
)

// --------------------------------------------------------------------------
// GET /auth/login
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthLogin
type getAuthLoginRequestParams struct {
	LoginFlowID string `form:"flow" validate:"omitempty,uuid4"`
	ReturnTo    string `form:"return_to" validate:"omitempty"`
}

func (p *Provider) handleGetAuthLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	loginIndexView := newView(TPL_AUTH_LOGIN_INDEX)

	// bind and validate request parameters
	var reqParams getAuthLoginRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthLogin bind request error", "err", err)
		loginIndexView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	loginIndexView.addParams(requestParamsToMap(reqParams))

	// create or get login flow
	var (
		loginFlow        kratos.LoginFlow
		kratosRespHeader kratos.KratosResponseHeader
	)
	if reqParams.LoginFlowID == "" {
		var createLoginFlowResp kratos.CreateLoginFlowResponse
		createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
			Header:  makeDefaultKratosRequestHeader(r),
			Refresh: isAuthenticated(session),
			Aal:     kratos.Aal1,
		})
		if err != nil {
			slog.ErrorContext(ctx, "create login flow error", "err", err)
			loginIndexView.setKratosMsg(err).render(w, r, session)
			return
		}
		kratosRespHeader = createLoginFlowResp.Header
		loginFlow = createLoginFlowResp.LoginFlow
	} else {
		var getLoginFlowResp kratos.GetLoginFlowResponse
		getLoginFlowResp, _, err := kratos.GetLoginFlow(ctx, kratos.GetLoginFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
			FlowID: reqParams.LoginFlowID,
		})
		// OIDC Loginの場合、同一クレデンシャルが存在する場合、既存Identityとのリンクを促すためエラーにしない
		if err != nil && loginFlow.DuplicateIdentifier == "" {
			slog.ErrorContext(ctx, "get login flow error", "err", err)
			loginIndexView.setKratosMsg(err).render(w, r, session)
			return
		}
		kratosRespHeader = getLoginFlowResp.Header
		loginFlow = getLoginFlowResp.LoginFlow
	}

	// update session
	addCookies(w, kratosRespHeader.Cookie)

	// render
	viewParams := map[string]any{
		"LoginFlowID":      loginFlow.FlowID,
		"CsrfToken":        loginFlow.CsrfToken,
		"PasskeyChallenge": loginFlow.PasskeyChallenge,
	}
	// OIDC Loginの場合、同一クレデンシャルが存在する場合、既存Identityとのリンクを促す
	if loginFlow.DuplicateIdentifier == "" {
		viewParams["viewParams"] = true
	} else {
		viewParams["viewParams"] = false
		viewParams["Traits"] = kratos.Traits{
			Email: loginFlow.DuplicateIdentifier,
		}
		viewParams["Information"] = "メールアドレスとパスワードで登録された既存のアカウントが存在します。パスワードを入力してログインすると、Googleのアカウントと連携されます。"
		viewParams["IdentifierReadonly"] = true
	}
	loginIndexView.addParams(viewParams).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/login/password
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginPassword
type postAuthLoginPasswordRequestParams struct {
	LoginFlowID           string `form:"flow" validate:"required,uuid4"`
	CsrfToken             string `json:"csrf_token" validate:"required"`
	Identifier            string `json:"identifier" validate:"required,email" ja:"メールアドレス"`
	Password              string `json:"password" validate:"required" ja:"パスワード"`
	UpdateSettingsRequest string `json:"update_settings_request"`
}

func (p *Provider) handlePostAuthLoginPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	passwordFormView := newView(TPL_AUTH_LOGIN_PASSWORD_FORM)

	// bind and validate request parameters
	var reqParams postAuthLoginPasswordRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthLogin bind request error", "err", err)
		passwordFormView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	passwordFormView.addParams(requestParamsToMap(reqParams))

	// update login flow
	updateLoginFlowResp, _, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.LoginFlowID,
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
		passwordFormView.setKratosMsg(err).render(w, r, session)
		return
	}

	// update session
	addCookies(w, updateLoginFlowResp.Header.Cookie)

	// view profile page when updated settings after logged in. if required validation of email, view verification page with rendered profile page.
	if reqParams.UpdateSettingsRequest != "" {
		redirectToSettingsAfterLogin(w, r, &updateLoginFlowResp)
	} else if updateLoginFlowResp.RequiredAal2 {
		// view authentication code input page for aal2 (MFA)
		// TODO: コードのMFAも対応する
		redirectUrl := fmt.Sprintf("/auth/login/totp?flow=%s&password=%s&update_settings_request=%s",
			reqParams.LoginFlowID,
			reqParams.Password,
			reqParams.UpdateSettingsRequest)
		redirect(w, r, redirectUrl, []string{"password", "update_settings_request"})
	} else {
		redirect(w, r, "/", []string{})
	}
}

// view profile page when updated settings after logged in. if required validation of email, view verification page with rendered profile page.
func redirectToSettingsAfterLogin(w http.ResponseWriter, r *http.Request, updateLoginFlowResp *kratos.UpdateLoginFlowResponse) {
	var redirectSettingsRedirectUrl string
	if updateLoginFlowResp.SettingsUpdatedMethod == "profile" {
		redirectSettingsRedirectUrl = "/my/profile?updated=true"
	} else if updateLoginFlowResp.SettingsUpdatedMethod == "password" {
		redirectSettingsRedirectUrl = "/my/password?updated=true"
	} else if updateLoginFlowResp.SettingsUpdatedMethod == "totp" {
		redirectSettingsRedirectUrl = "/my/totp?updated=true"
	}
	if updateLoginFlowResp.VerificationFlow != nil {
		// render verification code page
		redirect(w, r, fmt.Sprintf("/auth/verification/code?flow=%s&return_to=%s", updateLoginFlowResp.VerificationFlow.FlowID, redirectSettingsRedirectUrl), []string{})
	} else {
		// render profile page
		redirect(w, r, redirectSettingsRedirectUrl, []string{"information"})
	}
}

// --------------------------------------------------------------------------
// POST /auth/login/passkey
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginPasskey
type postAuthLoginPasskeyRequestParams struct {
	LoginFlowID           string `form:"flow" validate:"required,uuid4"`
	CsrfToken             string `json:"csrf_token" validate:"required"`
	PasskeyLogin          string `json:"passkey_login" validate:"required"`
	PasskeyChallenge      string `json:"passkey_challenge" validate:"required"`
	UpdateSettingsRequest string `json:"update_settings_request"`
}

func (p *Provider) handlePostAuthLoginPasskey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	passkeyFormView := newView(TPL_AUTH_LOGIN_PASSKEY_FORM)

	// bind and validate request parameters
	var reqParams postAuthLoginPasskeyRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthLoginPasskey bind request error", "err", err)
		passkeyFormView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	passkeyFormView.addParams(requestParamsToMap(reqParams))

	// update login flow
	updateLoginFlowResp, _, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.LoginFlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Aal:    kratos.Aal1,
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:       "passkey",
			CsrfToken:    reqParams.CsrfToken,
			PasskeyLogin: reqParams.PasskeyLogin,
		},
		UpdateSettingsRequest: reqParams.UpdateSettingsRequest,
	})
	if err != nil {
		slog.ErrorContext(ctx, "update login flow error", "err", err)
		passkeyFormView.setKratosMsg(err).render(w, r, session)
		return
	}

	// update session
	addCookies(w, updateLoginFlowResp.Header.Cookie)

	// view profile page when updated settings after logged in. if required validation of email, view verification page with rendered profile page.
	if reqParams.UpdateSettingsRequest != "" {
		redirectToSettingsAfterLogin(w, r, &updateLoginFlowResp)
		return
	} else if updateLoginFlowResp.RequiredAal2 {
		// view authentication code input page for aal2 (MFA)
		// TODO: コードのMFAも対応する
		redirectUrl := fmt.Sprintf("/auth/login/totp?flow=%s&passkey_login=%s&passkey_challenge=%s&update_settings_request=%s",
			reqParams.LoginFlowID,
			reqParams.PasskeyLogin,
			reqParams.PasskeyChallenge,
			reqParams.UpdateSettingsRequest)
		redirect(w, r, redirectUrl, []string{"passkey_login", "passkey_challenge", "update_settings_request"})

	} else {
		redirect(w, r, "/", []string{})
	}
}

// --------------------------------------------------------------------------
// POST /auth/login/oidc
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginOidc
type postAuthLoginOidcRequestParams struct {
	LoginFlowID           string `form:"flow" validate:"required,uuid4"`
	CsrfToken             string `json:"csrf_token" validate:"required"`
	OidcProvider          string `json:"oidc_provider" validate:"required"`
	UpdateSettingsRequest string `json:"update_settings_request"`
}

func (p *Provider) handlePostAuthLoginOidc(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	// Login oidc post is called from index page.
	loginView := newView(TPL_AUTH_LOGIN_INDEX)

	// bind and validate request parameters
	var reqParams postAuthLoginOidcRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthLoginOidc bind request error", "err", err)
		loginView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	loginView.addParams(requestParamsToMap(reqParams))

	// update login flow
	updateLoginFlowResp, _, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.LoginFlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Aal:    kratos.Aal1,
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:    "oidc",
			CsrfToken: reqParams.CsrfToken,
			Provider:  reqParams.OidcProvider,
		},
		UpdateSettingsRequest: reqParams.UpdateSettingsRequest,
	})
	if err != nil {
		slog.ErrorContext(ctx, "update login flow error", "err", err)
		loginView.setKratosMsg(err).render(w, r, session)
		return
	}

	// update session
	addCookies(w, updateLoginFlowResp.Header.Cookie)

	// view profile page when updated settings after logged in. if required validation of email, view verification page with rendered profile page.
	if reqParams.UpdateSettingsRequest != "" {
		redirectToSettingsAfterLogin(w, r, &updateLoginFlowResp)
	} else if updateLoginFlowResp.RequiredAal2 {
		// view authentication code input page for aal2 (MFA)
		// TODO: コードのMFAも対応する
		redirect(w, r, updateLoginFlowResp.RedirectBrowserTo, []string{})
	} else {
		redirect(w, r, "/", []string{})
	}
}

// --------------------------------------------------------------------------
// GET /auth/login/code
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthLoginCode
type getAuthLoginCodeRequestParams struct {
	LoginFlowID string `form:"flow" validate:"omitempty,uuid4"`
	ReturnTo    string `form:"return_to" validate:"omitempty"`
}

func (p *Provider) handleGetAuthLoginCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	loginCodeView := newView(TPL_AUTH_LOGIN_CODE)

	// bind and validate request parameters
	var reqParams getAuthLoginCodeRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handleGetAuthLoginCode bind request error", "err", err)
		loginCodeView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	loginCodeView.addParams(requestParamsToMap(reqParams))

	var loginFlow kratos.LoginFlow
	if reqParams.LoginFlowID == "" {
		// create and update login flow for aal2, send authentication code
		createLoginFlow, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
			Header:  makeDefaultKratosRequestHeader(r),
			Aal:     kratos.Aal2,
			Refresh: true,
		})
		if err != nil {
			slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
			loginCodeView.setKratosMsg(err).render(w, r, session)
			return
		}

		// update login flow
		updateLoginFlowResp, _, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
			FlowID: createLoginFlow.LoginFlow.FlowID,
			Header: makeDefaultKratosRequestHeader(r),
			Aal:    kratos.Aal2,
			Body: kratos.UpdateLoginFlowRequestBody{
				Method:     "code",
				CsrfToken:  createLoginFlow.LoginFlow.CsrfToken,
				Identifier: createLoginFlow.LoginFlow.CodeAddress,
			},
		})
		if err != nil {
			slog.ErrorContext(ctx, "update login flow for aal2 error", "err", err)
			loginCodeView.setKratosMsg(err).render(w, r, session)
			return
		}

		loginFlow = createLoginFlow.LoginFlow
		addCookies(w, updateLoginFlowResp.Header.Cookie)

	} else {
		getLoginFlowResp, _, err := kratos.GetLoginFlow(ctx, kratos.GetLoginFlowRequest{
			FlowID: reqParams.LoginFlowID,
			Header: makeDefaultKratosRequestHeader(r),
		})
		if err != nil {
			slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
			loginCodeView.setKratosMsg(err).render(w, r, session)
			return
		}
		loginFlow = getLoginFlowResp.LoginFlow
		addCookies(w, getLoginFlowResp.Header.Cookie)
	}

	loginCodeView.addParams(map[string]any{
		"LoginFlowID": loginFlow.FlowID,
		"CsrfToken":   loginFlow.CsrfToken,
		"Identifier":  loginFlow.CodeAddress,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/login/code
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginCode
type postAuthLoginCodeRequestParams struct {
	LoginFlowID           string `form:"flow" validate:"required,uuid4"`
	CsrfToken             string `json:"csrf_token" validate:"required"`
	Identifier            string `json:"identifier" validate:"required,email" ja:"メールアドレス"`
	Code                  string `json:"code" validate:"required" ja:"認証コード"`
	UpdateSettingsRequest string `json:"update_settings_request"`
}

func (p *Provider) handlePostAuthLoginCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	loginCodeView := newView(TPL_AUTH_LOGIN_CODE)

	// bind and validate request parameters
	var reqParams postAuthLoginCodeRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthLogin bind request error", "err", err)
		loginCodeView.setValidationFieldError(err).render(w, r, session)
		return
	}
	// add request params to views
	loginCodeView.addParams(requestParamsToMap(reqParams))

	// update login flow
	updateLoginFlowResp, _, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.LoginFlowID,
		Header: makeDefaultKratosRequestHeader(r),
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
		loginCodeView.setKratosMsg(err).render(w, r, session)
		return
	}

	// update session
	addCookies(w, updateLoginFlowResp.Header.Cookie)

	// view profile page when updated settings after logged in. if required validation of email, view verification page with rendered profile page.
	if reqParams.UpdateSettingsRequest != "" {
		redirectToSettingsAfterLogin(w, r, &updateLoginFlowResp)
	} else if updateLoginFlowResp.RequiredAal2 {
		// view authentication code input page for aal2 (MFA)
		// TODO: コードのMFAも対応する
		redirect(w, r, updateLoginFlowResp.RedirectBrowserTo, []string{})
	} else {
		redirect(w, r, "/", []string{})
	}
}

// --------------------------------------------------------------------------
// GET /auth/login/totp
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthLoginTotp
type getAuthLoginTotpRequestParams struct {
	LoginFlowID string `form:"flow" validate:"omitempty,uuid4"`
	ReturnTo    string `form:"return_to" validate:"omitempty"`
}

func (p *Provider) handleGetAuthLoginTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	totpView := newView(TPL_AUTH_LOGIN_TOTP)

	// bind and validate request parameters
	var reqParams getAuthLoginCodeRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handleGetAuthLoginTotp bind request error", "err", err)
		totpView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	totpView.addParams(requestParamsToMap(reqParams))

	var loginFlow kratos.LoginFlow
	if reqParams.LoginFlowID == "" {
		// create and update login flow for aal2, send authentication code
		createLoginFlow, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
			Header:  makeDefaultKratosRequestHeader(r),
			Aal:     kratos.Aal2,
			Refresh: true,
		})
		if err != nil {
			slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
			totpView.setKratosMsg(err).render(w, r, session)
			return
		}

		updateLoginFlowResp, _, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
			FlowID: createLoginFlow.LoginFlow.FlowID,
			Header: makeDefaultKratosRequestHeader(r),
			Aal:    kratos.Aal2,
			Body: kratos.UpdateLoginFlowRequestBody{
				Method:     "totp",
				CsrfToken:  createLoginFlow.LoginFlow.CsrfToken,
				Identifier: createLoginFlow.LoginFlow.CodeAddress,
			},
		})
		if err != nil {
			slog.ErrorContext(ctx, "update login flow for aal2 error", "err", err)
			totpView.setKratosMsg(err).render(w, r, session)
			return
		}

		loginFlow = createLoginFlow.LoginFlow
		addCookies(w, updateLoginFlowResp.Header.Cookie)

	} else {
		getLoginFlowResp, _, err := kratos.GetLoginFlow(ctx, kratos.GetLoginFlowRequest{
			FlowID: reqParams.LoginFlowID,
			Header: makeDefaultKratosRequestHeader(r),
		})
		if err != nil {
			slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
			totpView.setKratosMsg(err).render(w, r, session)
			return
		}
		loginFlow = getLoginFlowResp.LoginFlow
		addCookies(w, getLoginFlowResp.Header.Cookie)
	}

	totpView.addParams(map[string]any{
		"LoginFlowID": loginFlow.FlowID,
		"CsrfToken":   loginFlow.CsrfToken,
		"Identifier":  loginFlow.CodeAddress,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/login/totp
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLoginTotp
type postAuthLoginTotpRequestParams struct {
	LoginFlowID           string `form:"flow" validate:"required,uuid4"`
	CsrfToken             string `json:"csrf_token" validate:"required"`
	Identifier            string `json:"identifier" validate:"required,email" ja:"メールアドレス"`
	TotpCode              string `json:"totp_code" validate:"required" ja:"認証コード"`
	UpdateSettingsRequest string `json:"update_settings_request"`
}

func (p *Provider) handlePostAuthLoginTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	totpFormView := newView(TPL_AUTH_LOGIN_TOTP)

	// bind and validate request parameters
	var reqParams postAuthLoginTotpRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthLoginTotp bind request error", "err", err)
		totpFormView.setValidationFieldError(err).render(w, r, session)
		return
	}
	// add request params to views
	totpFormView.addParams(requestParamsToMap(reqParams))

	// update login flow
	updateLoginFlowResp, _, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.LoginFlowID,
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
		totpFormView.setKratosMsg(err).render(w, r, session)
		return
	}

	// update session
	addCookies(w, updateLoginFlowResp.Header.Cookie)

	// view profile page when updated settings after logged in. if required validation of email, view verification page with rendered profile page.
	if reqParams.UpdateSettingsRequest != "" {
		redirectToSettingsAfterLogin(w, r, &updateLoginFlowResp)
	} else if updateLoginFlowResp.RequiredAal2 {
		// view authentication code input page for aal2 (MFA)
		// TODO: コードのMFAも対応する
		redirect(w, r, updateLoginFlowResp.RedirectBrowserTo, []string{})
	} else {
		redirect(w, r, "/", []string{})
	}
}

// --------------------------------------------------------------------------
// POST /auth/logout
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLogout
type postAuthLogoutRequestParams struct {
	LoginFlowID string `form:"flow" validate:"required,uuid4"`
}

func (p *Provider) handlePostAuthLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// bind and validate request parameters
	var reqParams postAuthLogoutRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthLogout bind request error", "err", err)
		return
	}

	// logout
	logoutResp, _, err := kratos.Logout(ctx, kratos.LogoutRequest{
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		slog.ErrorContext(ctx, "logout error", "err", err)
		return
	}

	// change location
	addCookies(w, logoutResp.Header.Cookie)
	redirect(w, r, "/", []string{})
}
