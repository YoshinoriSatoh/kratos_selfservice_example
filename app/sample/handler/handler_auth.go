package handler

import (
	"fmt"
	"kratos_example/kratos"
	"log/slog"
	"net/http"
	"strings"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /auth/registration
// also used from oidc callback ui url when missing required fields in traits.
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthRegistration
type getAuthRegistrationRequestParams struct {
	FlowID              string `validate:"omitempty,uuid4"`
	PasskeyRegistration bool   `validate:"omitempty"`
}

// Extract parameters from http request
func newGetAuthRegistrationRequestParams(r *http.Request) *getAuthRegistrationRequestParams {
	return &getAuthRegistrationRequestParams{
		FlowID:              r.URL.Query().Get("flow"),
		PasskeyRegistration: r.URL.Query().Get("passkey_registration") == "true",
	}
}

// Return parameters that can refer in view template
func (p *getAuthRegistrationRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RegistrationFlowID": p.FlowID,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getAuthRegistrationRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(p))

	for k := range viewError.validationFieldErrors {
		if k == "FlowID" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
			break
		}
	}

	// Individual validations write here that cannot validate in common validations

	// slog.InfoContext(ctx, "validation error occured", "viewError", viewError)

	return viewError
}

// GET /auth/registration
func (p *Provider) handleGetAuthRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newGetAuthRegistrationRequestParams(r)

	// prepare views
	registrationIndexPasswordView := newView("auth/registration/index.html").addParams(params.toViewParams()).addParams(map[string]any{"Method": "password"})
	registrationIndexOidcView := newView("auth/registration/index.html").addParams(params.toViewParams()).addParams(map[string]any{"Method": "oidc"})
	registrationIndexPasskeyView := newView("auth/registration/index.html").addParams(params.toViewParams()).addParams(map[string]any{"Method": "passkey"})

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		registrationIndexPasswordView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// create or get registration Flow
	var (
		err                  error
		registrationFlow     kratos.RegistrationFlow
		kratosResponseHeader kratos.KratosResponseHeader
	)
	if params.FlowID == "" {
		var createRegistrationFlowResp kratos.CreateRegistrationFlowResponse
		createRegistrationFlowResp, err = p.d.Kratos.CreateRegistrationFlow(ctx, kratos.CreateRegistrationFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = createRegistrationFlowResp.Header
		registrationFlow = createRegistrationFlowResp.RegistrationFlow
	} else {
		var getRegistrationFlowResp kratos.GetRegistrationFlowResponse
		getRegistrationFlowResp, err = p.d.Kratos.GetRegistrationFlow(ctx, kratos.GetRegistrationFlowRequest{
			FlowID: params.FlowID,
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = getRegistrationFlowResp.Header
		registrationFlow = getRegistrationFlowResp.RegistrationFlow
	}
	if err != nil {
		registrationIndexPasswordView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	if registrationFlow.CredentialType == kratos.CredentialsTypePassword {

		// render page
		setCookie(w, kratosResponseHeader.Cookie)
		setHeadersForReplaceBody(w, "/auth/registration")

		if params.PasskeyRegistration {
			registrationIndexPasskeyView.addParams(map[string]any{
				"RegistrationFlowID": registrationFlow.FlowID,
				"CsrfToken":          registrationFlow.CsrfToken,
				"Traits":             registrationFlow.Traits,
				"PasskeyCreateData":  registrationFlow.PasskeyCreateData,
			}).render(w, r, session)
		} else {
			registrationIndexPasswordView.addParams(map[string]any{
				"RegistrationFlowID": registrationFlow.FlowID,
				"CsrfToken":          registrationFlow.CsrfToken,
			}).render(w, r, session)
		}

	} else if registrationFlow.CredentialType == kratos.CredentialsTypeOidc {
		// Update identity when user already registered with the same credential of provided the oidc provider.
		identities, err := p.d.Kratos.AdminListIdentities(ctx, kratos.AdminListIdentitiesRequest{
			CredentialIdentifier: registrationFlow.Traits.Email,
		})
		if err != nil {
			registrationIndexOidcView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}

		if len(identities) > 1 {
			message := pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_DEFAULT",
			})
			registrationIndexOidcView.addParams(baseViewError.setMessages([]string{message}).toViewParams()).render(w, r, session)
			return
		}
		if len(identities) == 1 {
			// Transferring cookies from create or get registration flow response
			kratosRequestHeader := makeDefaultKratosRequestHeader(r)
			// kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, kratosResponseHeader.Cookie)
			kratosRequestHeader.Cookie = strings.Join(kratosResponseHeader.Cookie, " ")

			// update Registration Flow
			kratosResp, err := p.d.Kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
				FlowID: registrationFlow.FlowID,
				Header: kratosRequestHeader,
				Body: kratos.UpdateRegistrationFlowRequestBody{
					Method:    "oidc",
					CsrfToken: registrationFlow.CsrfToken,
					Provider:  string(registrationFlow.OidcProvider),
					Traits:    identities[0].Traits,
				},
			})
			if err != nil {
				slog.ErrorContext(ctx, "update registration error", "err", err)
				registrationIndexOidcView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
				return
			}
			setCookie(w, kratosResp.Header.Cookie)
			if kratosResp.RedirectBrowserTo != "" {
				// w.Header().Set("HX-Redirect", kratosResp.RedirectBrowserTo)
				redirect(w, r, kratosResp.RedirectBrowserTo)
			}
		}

		// render page
		setCookie(w, kratosResponseHeader.Cookie) // set cookie that was responsed last from kratos (exclude admin api).
		registrationIndexOidcView.addParams(map[string]any{
			"RegistrationFlowID": registrationFlow.FlowID,
			"CsrfToken":          registrationFlow.CsrfToken,
			"Provider":           registrationFlow.OidcProvider,
			"Traits":             registrationFlow.Traits,
		}).render(w, r, session)

	} else {
		slog.ErrorContext(ctx, "invalid credential type", "credential type", registrationFlow.CredentialType)
	}
}

// --------------------------------------------------------------------------
// POST /auth/registration
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistration
type postAuthRegistrationRequestParams struct {
	FlowID               string        `validate:"required,uuid4"`
	CsrfToken            string        `validate:"required"`
	Traits               kratos.Traits `validate:"required"`
	Password             string        `validate:"required,eqfield=PasswordConfirmation" ja:"パスワード"`
	PasswordConfirmation string        `validate:"required" ja:"パスワード確認"`
}

// Extract parameters from http request
func newPostAuthRegistrationRequestParams(r *http.Request) *postAuthRegistrationRequestParams {
	return &postAuthRegistrationRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Traits: kratos.Traits{
			Email:     r.PostFormValue("traits.email"),
			Firstname: r.PostFormValue("traits.firstname"),
			Lastname:  r.PostFormValue("traits.lastname"),
			Nickname:  r.PostFormValue("traits.nickname"),
			Birthdate: fmt.Sprintf("%s-%s-%s", r.PostFormValue("birthdate_year"), r.PostFormValue("birthdate_month"), r.PostFormValue("birthdate_day")),
		},
		Password:             r.PostFormValue("password"),
		PasswordConfirmation: r.PostFormValue("password_confirmation"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthRegistrationRequestParams) toViewParams() map[string]any {
	year, month, day := parseDate(p.Traits.Birthdate)
	return map[string]any{
		"RegistrationFlowID":   p.FlowID,
		"CsrfToken":            p.CsrfToken,
		"Traits":               p.Traits,
		"BirthdateYear":        year,
		"BirthdateMonth":       month,
		"BirthdateDay":         day,
		"Password":             p.Password,
		"PasswordConfirmation": p.PasswordConfirmation,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthRegistrationRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	for k := range viewError.validationFieldErrors {
		if k == "FlowID" || k == "CsrfToken" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
			break
		}
	}
	// Individual validations write here that cannot validate in common validations

	return viewError
}

// POST /auth/registration
func (p *Provider) handlePostAuthRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAuthRegistrationRequestParams(r)

	// prepare views
	registrationFormView := newView("auth/registration/_form.html").addParams(params.toViewParams()).addParams(map[string]any{"Method": "password"})
	verificationCodeView := newView("auth/verification/code.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		registrationFormView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// update Registration Flow
	updateRegistrationFlowResp, err := p.d.Kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRegistrationFlowRequestBody{
			CsrfToken: params.CsrfToken,
			Method:    "password",
			Traits:    params.Traits,
			Password:  params.Password,
		},
	})
	if err != nil {
		slog.DebugContext(ctx, "update registration error", "err", err.Error())
		registrationFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// transition to verification flow from registration flow
	// Transferring cookies from update registration flow response
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)
	kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, updateRegistrationFlowResp.Header.Cookie)
	// get verification flow
	getVerificationFlowResp, err := p.d.Kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
		FlowID: updateRegistrationFlowResp.VerificationFlowID,
		Header: kratosRequestHeader,
	})
	if err != nil {
		slog.DebugContext(ctx, "get verification error", "err", err.Error())
		registrationFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render verification code page (replace <body> tag and push url)
	setCookie(w, getVerificationFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", getVerificationFlowResp.VerificationFlow.FlowID))
	verificationCodeView.addParams(map[string]any{
		"VerificationFlowID": getVerificationFlowResp.VerificationFlow.FlowID,
		"CsrfToken":          getVerificationFlowResp.VerificationFlow.CsrfToken,
		"IsUsedFlow":         getVerificationFlowResp.VerificationFlow.IsUsedFlow(),
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/registration/oidc
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationOidc
type postAuthRegistrationOidcRequestParams struct {
	FlowID    string        `validate:"required,uuid4"`
	CsrfToken string        `validate:"required"`
	Provider  string        `validate:"required"`
	Traits    kratos.Traits `validate:"required"`
}

// Extract parameters from http request
func newPostAuthRegistrationOidcRequestParams(r *http.Request) *postAuthRegistrationOidcRequestParams {
	return &postAuthRegistrationOidcRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Provider:  r.PostFormValue("provider"),
		Traits: kratos.Traits{
			Email:     r.PostFormValue("traits.email"),
			Firstname: r.PostFormValue("traits.firstname"),
			Lastname:  r.PostFormValue("traits.lastname"),
			Nickname:  r.PostFormValue("traits.nickname"),
			Birthdate: fmt.Sprintf("%s-%s-%s", r.PostFormValue("birthdate_year"), r.PostFormValue("birthdate_month"), r.PostFormValue("birthdate_day")),
		},
	}
}

// Return parameters that can refer in view template
func (p *postAuthRegistrationOidcRequestParams) toViewParams() map[string]any {
	year, month, day := parseDate(p.Traits.Birthdate)
	return map[string]any{
		"RegistrationFlowID": p.FlowID,
		"CsrfToken":          p.CsrfToken,
		"Traits":             p.Traits,
		"BirthdateYear":      year,
		"BirthdateMonth":     month,
		"BirthdateDay":       day,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthRegistrationOidcRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostAuthRegistrationOidc(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAuthRegistrationOidcRequestParams(r)

	// prepare views
	registrationFormOidc := newView("auth/registration/_form.html").addParams(params.toViewParams()).addParams(map[string]any{"Method": "oidc"})

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		registrationFormOidc.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// update Registration Flow
	kratosResp, err := p.d.Kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRegistrationFlowRequestBody{
			CsrfToken: params.CsrfToken,
			Method:    "oidc",
			Provider:  params.Provider,
			Traits:    params.Traits,
		},
	})
	if err != nil {
		registrationFormOidc.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	setCookie(w, kratosResp.Header.Cookie)
	if kratosResp.RedirectBrowserTo != "" {
		redirect(w, r, kratosResp.RedirectBrowserTo)
	}
}

// --------------------------------------------------------------------------
// POST /auth/registration/passkey
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationPasskey
type postAuthRegistrationPasskeyRequestParams struct {
	FlowID          string        `validate:"required,uuid4"`
	CsrfToken       string        `validate:"required"`
	Traits          kratos.Traits `validate:"required"`
	PasskeyRegister string
}

// Extract parameters from http request
func newPostAuthRegistrationPasskeyRequestParams(r *http.Request) *postAuthRegistrationPasskeyRequestParams {
	return &postAuthRegistrationPasskeyRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Traits: kratos.Traits{
			Email:     r.PostFormValue("traits.email"),
			Firstname: r.PostFormValue("traits.firstname"),
			Lastname:  r.PostFormValue("traits.lastname"),
			Nickname:  r.PostFormValue("traits.nickname"),
			Birthdate: fmt.Sprintf("%s-%s-%s", r.PostFormValue("birthdate_year"), r.PostFormValue("birthdate_month"), r.PostFormValue("birthdate_day")),
		},
		PasskeyRegister: r.PostFormValue("passkey_register"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthRegistrationPasskeyRequestParams) toViewParams() map[string]any {
	year, month, day := parseDate(p.Traits.Birthdate)
	return map[string]any{
		"RegistrationFlowID": p.FlowID,
		"CsrfToken":          p.CsrfToken,
		"Traits":             p.Traits,
		"BirthdateYear":      year,
		"BirthdateMonth":     month,
		"BirthdateDay":       day,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthRegistrationPasskeyRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostAuthRegistrationPasskey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAuthRegistrationPasskeyRequestParams(r)

	// prepare views
	registrationFormPasskeyView := newView("auth/registration/_form.html").addParams(params.toViewParams()).addParams(map[string]any{"Method": "passkey"})
	loginIndexView := newView("auth/login/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		registrationFormPasskeyView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// Registration Flow 更新
	kratosResp, err := p.d.Kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRegistrationFlowRequestBody{
			CsrfToken:       params.CsrfToken,
			Method:          "passkey",
			Traits:          params.Traits,
			PasskeyRegister: params.PasskeyRegister,
		},
	})
	if err != nil && kratosResp.DuplicateIdentifier == "" {
		registrationFormPasskeyView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	if kratosResp.RedirectBrowserTo != "" {
		redirect(w, r, kratosResp.RedirectBrowserTo)
		w.WriteHeader(http.StatusOK)
	}

	// OIDC Loginの場合、同一クレデンシャルが存在する場合、既存Identityとのリンクを促す
	var (
		information     string
		traits          kratos.Traits
		showSocialLogin bool
	)
	if kratosResp.DuplicateIdentifier == "" {
		showSocialLogin = true
	} else {
		traits.Email = kratosResp.DuplicateIdentifier
		showSocialLogin = false
		information = "メールアドレスとパスワードで登録された既存のアカウントが存在します。パスワードを入力してログインすると、Googleのアカウントと連携されます。"
	}

	// Transferring cookies from update registration flow response
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)
	kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, kratosResp.Header.Cookie)
	// create login flow
	createLoginFlowResp, err := p.d.Kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
		Header: kratosRequestHeader,
	})
	if err != nil {
		slog.DebugContext(ctx, "update verification error", "err", err.Error())
		registrationFormPasskeyView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	setCookie(w, kratosResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
	loginIndexView.addParams(map[string]any{
		"LoginFlowID":      createLoginFlowResp.LoginFlow.FlowID,
		"Information":      information,
		"CsrfToken":        createLoginFlowResp.LoginFlow.CsrfToken,
		"Traits":           traits,
		"ShowSocialLogin":  showSocialLogin,
		"ShowPasskeyLogin": true,
		"PasskeyChallenge": createLoginFlowResp.LoginFlow.PasskeyChallenge,
	}).render(w, r, session)

	// Registration flow成功時はVerification flowへリダイレクト
	// redirect(w, r, fmt.Sprintf("%s?flow=%s", "/auth/verification/code", output.VerificationFlowID))
}

// --------------------------------------------------------------------------
// GET /auth/verification
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthVerification
type getAuthVerificationRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
}

// Extract parameters from http request
func newGetAuthVerificationRequestParams(r *http.Request) *getAuthVerificationRequestParams {
	return &getAuthVerificationRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}
}

// Return parameters that can refer in view template
func (p *getAuthVerificationRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"VerificationFlowID": p.FlowID,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getAuthVerificationRequestParams) validate() *viewError {
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

// Handler GET /auth/verification
func (p *Provider) handleGetAuthVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newGetAuthVerificationRequestParams(r)

	// prepare views
	verificationIndexView := newView("auth/verification/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		verificationIndexView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_VERIFICATION_DEDAULT",
	}))

	// create or get verification Flow
	var (
		err                  error
		verificationFlow     kratos.VerificationFlow
		kratosResponseHeader kratos.KratosResponseHeader
	)
	if params.FlowID == "" {
		var createVerificatoinFlowResp kratos.CreateVerificationFlowResponse
		createVerificatoinFlowResp, err = p.d.Kratos.CreateVerificationFlow(ctx, kratos.CreateVerificationFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = createVerificatoinFlowResp.Header
		verificationFlow = createVerificatoinFlowResp.VerificationFlow
	} else {
		var getVerificatoinFlowResp kratos.GetVerificationFlowResponse
		getVerificatoinFlowResp, err = p.d.Kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
			FlowID: params.FlowID,
		})
		kratosResponseHeader = getVerificatoinFlowResp.Header
		verificationFlow = getVerificatoinFlowResp.VerificationFlow
	}
	if err != nil {
		verificationIndexView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	setCookie(w, kratosResponseHeader.Cookie)
	verificationIndexView.addParams(map[string]any{
		"VerificationFlowID": verificationFlow.FlowID,
		"CsrfToken":          verificationFlow.CsrfToken,
		"IsUsedFlow":         verificationFlow.IsUsedFlow,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// GET /auth/verification/code
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthVerificationCode
type getAuthVerificationCodeRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
}

// Extract parameters from http request
func newGetAuthVerificationCodeRequestParams(r *http.Request) *getAuthVerificationCodeRequestParams {
	return &getAuthVerificationCodeRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}
}

// Return parameters that can refer in view template
func (p *getAuthVerificationCodeRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"VerificationFlowID": p.FlowID,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getAuthVerificationCodeRequestParams) validate() *viewError {
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

// Handler GET /auth/verification/code
func (p *Provider) handleGetAuthVerificationCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newGetAuthVerificationCodeRequestParams(r)

	// prepare views
	verificationCodeView := newView("auth/verification/_code_form.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		verificationCodeView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_VERIFICATION_DEDAULT",
	}))

	// create or get verification Flow
	var (
		err                  error
		verificationFlow     kratos.VerificationFlow
		kratosResponseHeader kratos.KratosResponseHeader
	)
	if params.FlowID == "" {
		var createVerificatoinFlowResp kratos.CreateVerificationFlowResponse
		createVerificatoinFlowResp, err = p.d.Kratos.CreateVerificationFlow(ctx, kratos.CreateVerificationFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = createVerificatoinFlowResp.Header
		verificationFlow = createVerificatoinFlowResp.VerificationFlow
	} else {
		var getVerificatoinFlowResp kratos.GetVerificationFlowResponse
		getVerificatoinFlowResp, err = p.d.Kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
			FlowID: params.FlowID,
		})
		kratosResponseHeader = getVerificatoinFlowResp.Header
		verificationFlow = getVerificatoinFlowResp.VerificationFlow
	}
	if err != nil {
		verificationCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	setCookie(w, kratosResponseHeader.Cookie)
	verificationCodeView.addParams(map[string]any{
		"VerificationFlowID": verificationFlow.FlowID,
		"CsrfToken":          verificationFlow.CsrfToken,
		"IsUsedFlow":         verificationFlow.IsUsedFlow,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/verificatoin/email
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthVerificationEmail
type postAuthVerificationEmailRequestParams struct {
	FlowID    string `validate:"uuid4"`
	CsrfToken string `validate:"required"`
	Email     string `validate:"required,email" ja:"メールアドレス"`
}

// Extract parameters from http request
func newPostAuthVerificationEmailRequestParams(r *http.Request) *postAuthVerificationEmailRequestParams {
	return &postAuthVerificationEmailRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Email:     r.PostFormValue("email"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthVerificationEmailRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"VerificationFlowID": p.FlowID,
		"CsrfToken":          p.CsrfToken,
		"Email":              p.Email,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthVerificationEmailRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostAuthVerificationEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAuthVerificationEmailRequestParams(r)

	// prepare views
	verificationCodeView := newView("auth/verification/_email_form.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		verificationCodeView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_VERIFICATION_DEFAULT",
	}))

	// Verification Flow 更新
	updateVerificationFlowResp, err := p.d.Kratos.UpdateVerificationFlow(ctx, kratos.UpdateVerificationFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateVerificationFlowRequestBody{
			CsrfToken: params.CsrfToken,
			Email:     params.Email,
		},
	})
	if err != nil {
		verificationCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	setCookie(w, updateVerificationFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", params.FlowID))
	verificationCodeView.addParams(map[string]any{
		"VerificationFlowID": updateVerificationFlowResp.Flow.FlowID,
		"CsrfToken":          updateVerificationFlowResp.Flow.CsrfToken,
		"IsUsedFlow":         updateVerificationFlowResp.Flow.IsUsedFlow,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/verificatoin/code
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationCode
type postAuthVerificationCodeRequestParams struct {
	FlowID    string `validate:"uuid4"`
	CsrfToken string `validate:"required"`
	Code      string `validate:"required,len=6,number" ja:"検証コード"`
	Render    string
}

// Extract parameters from http request
func newPostAuthVerificationCodeRequestParams(r *http.Request) *postAuthVerificationCodeRequestParams {
	return &postAuthVerificationCodeRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		Render:    r.PostFormValue("render"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Code:      r.PostFormValue("code"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthVerificationCodeRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"VerificationFlowID": p.FlowID,
		"Render":             p.Render,
		"CsrfToken":          p.CsrfToken,
		"Code":               p.Code,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthVerificationCodeRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	for k := range viewError.validationFieldErrors {
		if k == "FlowID" || k == "CsrfToken" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
			break
		}
	}
	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostAuthVerificationCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAuthVerificationCodeRequestParams(r)

	// prepare views
	verificationCodeView := newView("auth/verification/_code_form.html").addParams(params.toViewParams())
	loginIndexView := newView("auth/login/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		verificationCodeView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_VERIFICATION_DEFAULT",
	}))

	// Verification Flow 更新
	updateVerificationFlowResp, err := p.d.Kratos.UpdateVerificationFlow(ctx, kratos.UpdateVerificationFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateVerificationFlowRequestBody{
			Code:      params.Code,
			CsrfToken: params.CsrfToken,
		},
	})
	if err != nil {
		slog.DebugContext(ctx, "update verification error", "err", err.Error())
		verificationCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	if params.Render != "" {
		fmt.Println(params.Render)
		v := viewFromQueryParam(params.Render)
		setHeadersForReplaceBody(w, v.Path)
		viewFromQueryParam(params.Render).render(w, r, session)
		return
	}

	// Transferring cookies from update registration flow response
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)
	kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, updateVerificationFlowResp.Header.Cookie)
	// create login flow
	createLoginFlowResp, err := p.d.Kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
		Header:  kratosRequestHeader,
		Refresh: true,
	})
	if err != nil {
		slog.DebugContext(ctx, "update verification error", "err", err.Error())
		verificationCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	setCookie(w, createLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
	loginIndexView.addParams(map[string]any{
		"LoginFlowID": createLoginFlowResp.LoginFlow.FlowID,
		"Information": "コードによる検証が完了しました。お手数ですが改めてログインしてください。",
		"CsrfToken":   createLoginFlowResp.LoginFlow.CsrfToken,
	}).render(w, r, session)
}

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

	setCookie(w, kratosResponseHeader.Cookie)
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
				setCookie(w, getVerificationFlowResp.Header.Cookie)
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
			setCookie(w, updateLoginFlowResp.Header.Cookie)
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

	setCookie(w, updateLoginFlowResp.Header.Cookie)
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
	setCookie(w, updateLoginFlowResp.Header.Cookie)

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

	setCookie(w, updateLoginFlowResp.Header.Cookie)
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
	setCookie(w, updateLogoutFlowResp.Header.Cookie)
	w.Header().Set("HX-Location", "/")
}

// --------------------------------------------------------------------------
// GET /auth/recovery
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthRecovery
type getAuthRecoveryRequestParams struct {
	FlowID string
}

// Extract parameters from http request
func newGetAuthRecoveryRequestParams(r *http.Request) *getAuthRecoveryRequestParams {
	return &getAuthRecoveryRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}
}

// Return parameters that can refer in view template
func (p *getAuthRecoveryRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RecoveryFlowID": p.FlowID,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getAuthRecoveryRequestParams) validate() *viewError {
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

func (p *Provider) handleGetAuthRecovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newGetAuthRecoveryRequestParams(r)

	// prepare views
	recoveryIndexView := newView("auth/recovery/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		recoveryIndexView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_RECOVERY_DEFAULT",
	}))

	// create or get recovery Flow
	var (
		err                  error
		recoveryFlow         kratos.RecoveryFlow
		kratosResponseHeader kratos.KratosResponseHeader
	)
	if params.FlowID == "" {
		var createRecoveryFlowResp kratos.CreateRecoveryFlowResponse
		createRecoveryFlowResp, err = p.d.Kratos.CreateRecoveryFlow(ctx, kratos.CreateRecoveryFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = createRecoveryFlowResp.Header
		recoveryFlow = createRecoveryFlowResp.RecoveryFlow
	} else {
		var getRecoveryFlowResp kratos.GetRecoveryFlowResponse
		getRecoveryFlowResp, err = p.d.Kratos.GetRecoveryFlow(ctx, kratos.GetRecoveryFlowRequest{
			FlowID: params.FlowID,
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = getRecoveryFlowResp.Header
		recoveryFlow = getRecoveryFlowResp.RecoveryFlow
	}
	if err != nil {
		recoveryIndexView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	setCookie(w, kratosResponseHeader.Cookie)
	recoveryIndexView.addParams(map[string]any{
		"RecoveryFlowID": recoveryFlow.FlowID,
		"CsrfToken":      recoveryFlow.CsrfToken,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/recovery/email
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRecoveryEmail
type postAuthRecoveryEmailRequestParams struct {
	FlowID    string `validate:"uuid4"`
	CsrfToken string `validate:"required"`
	Email     string `validate:"required,email" ja:"メールアドレス"`
}

// Extract parameters from http request
func newPostAutRecoveryEmailRequestParams(r *http.Request) *postAuthRecoveryEmailRequestParams {
	return &postAuthRecoveryEmailRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Email:     r.PostFormValue("email"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthRecoveryEmailRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RecoveryFlowID": p.FlowID,
		"CsrfToken":      p.CsrfToken,
		"Email":          p.Email,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthRecoveryEmailRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostAuthRecoveryEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAutRecoveryEmailRequestParams(r)

	// prepare views
	recoveryEmailFormView := newView("auth/recovery/_email_form.html").addParams(params.toViewParams())
	recoveryCodeFormView := newView("auth/recovery/_code_form.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		recoveryEmailFormView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_RECOVERY_DEFAULT",
	}))

	// update Recovery flow
	kratosResp, err := p.d.Kratos.UpdateRecoveryFlow(ctx, kratos.UpdateRecoveryFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRecoveryFlowRequestBody{
			CsrfToken: params.CsrfToken,
			Method:    "code",
			Email:     params.Email,
		},
	})
	if err != nil {
		recoveryEmailFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	setCookie(w, kratosResp.Header.Cookie)

	if kratosResp.RedirectBrowserTo != "" {
		redirect(w, r, kratosResp.RedirectBrowserTo)
		w.WriteHeader(http.StatusOK)
	}

	// render
	recoveryCodeFormView.addParams(map[string]any{
		"RecoveryFlowID":           params.FlowID,
		"CsrfToken":                params.CsrfToken,
		"Email":                    params.Email,
		"ShowRecoveryAnnouncement": true,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/recovery/code
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRecoveryCode
type postAuthRecoveryCodeRequestParams struct {
	FlowID    string `validate:"uuid4"`
	CsrfToken string `validate:"required"`
	Code      string `validate:"required,len=6,number" ja:"復旧コード"`
}

// Extract parameters from http request
func newPostAutRecoveryCodeRequestParams(r *http.Request) *postAuthRecoveryCodeRequestParams {
	return &postAuthRecoveryCodeRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Code:      r.PostFormValue("code"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthRecoveryCodeRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RecoveryFlowID": p.FlowID,
		"CsrfToken":      p.CsrfToken,
		"Code":           p.Code,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthRecoveryCodeRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostAuthRecoveryCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAutRecoveryCodeRequestParams(r)

	// prepare views
	recoveryCodeFormView := newView("auth/recovery/_code_form.html").addParams(params.toViewParams())
	myPasswordIndexView := newView("my/password/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		recoveryCodeFormView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_RECOVERY_DEFAULT",
	}))

	// Recovery Flow 更新
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)
	kratosResp, err := p.d.Kratos.UpdateRecoveryFlow(ctx, kratos.UpdateRecoveryFlowRequest{
		FlowID: params.FlowID,
		Header: kratosRequestHeader,
		Body: kratos.UpdateRecoveryFlowRequestBody{
			CsrfToken: params.CsrfToken,
			Method:    "code",
			Code:      params.Code,
		},
	})
	if err != nil {
		recoveryCodeFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	setCookie(w, kratosResp.Header.Cookie)
	// kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, kratosResp.Header.Cookie)
	// kratosRequestHeader.Cookie = strings.Join(kratosResp.Header.Cookie, " ")
	slog.Debug("mergeProxyResponseCookies", "kratosResp.Header.Cookie", kratosResp.Header.Cookie)
	if kratosResp.RedirectBrowserTo != "" {
		arr := strings.Split(kratosResp.RedirectBrowserTo, "=")
		settingsFlowID := arr[1]

		var cookies []string
		var hasCsrfToken bool
		for _, respcv := range kratosResp.Header.Cookie {
			slog.Debug("mergeProxyResponseCookies", "respcv", respcv)
			v := strings.Split(respcv, ";")[0]
			cookies = append(cookies, v)
			// if strings.HasPrefix(respcv, "kratos_session") {
			// 	cookies = append(cookies, v)
			// }
			if strings.HasPrefix(respcv, "csrf_token") {
				hasCsrfToken = true
				// cookies = append(cookies, v)
			}
			// 	v := strings.Split(respcv, ";")[0]
			// 	cookies = append(cookies, v)
			// }
		}
		// for _, cv := range cookies {
		// 	if strings.HasPrefix(cv, "csrf_token") {
		// 		break
		// 	}
		// 	for _, reqcv := range strings.Split(kratosRequestHeader.Cookie, " ") {
		// 		if strings.HasPrefix(reqcv, "csrf_token") {
		// 			cookies = append(cookies, reqcv)
		// 		}
		// 	}
		// }

		if !hasCsrfToken {
			for _, reqcv := range r.Header["Cookie"] {
				if strings.HasPrefix(reqcv, "csrf_token") {
					cookies = append(cookies, reqcv)
				}
			}
		}

		slog.DebugContext(ctx, "handlePostAuthRecoveryCode", "cookies", cookies)
		kratosRequestHeader.Cookie = strings.Join(cookies, "; ")

		getSettingsFlowResp, err := p.d.Kratos.GetSettingsFlow(ctx, kratos.GetSettingsFlowRequest{
			FlowID: settingsFlowID,
			Header: kratosRequestHeader,
		})
		if err != nil {
			recoveryCodeFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}
		setCookie(w, getSettingsFlowResp.Header.Cookie)
		setHeadersForReplaceBody(w, fmt.Sprintf("/my/password?flow=%s", settingsFlowID))
		myPasswordIndexView.addParams(map[string]any{
			"SettingsFlowID": settingsFlowID,
			"CsrfToken":      getSettingsFlowResp.SettingsFlow.CsrfToken,
		}).render(w, r, session)
	}
}
