package handler

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/YoshinoriSatoh/kratos_example/external/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /auth/registration
// This is also used from oidc callback ui url when missing required fields in traits.
// --------------------------------------------------------------------------

// Rendering data
type getAuthRegistrationRenderingData struct {
	reqParams            *getAuthRegistrationRequestParams
	views                getAuthRegistrationViews
	baseViewError        *viewError
	registrationFlow     kratos.RegistrationFlow
	kratosResponseHeader kratos.KratosResponseHeader
}

// Request parameters
type getAuthRegistrationRequestParams struct {
	FlowID              string `validate:"omitempty,uuid4"`
	PasskeyRegistration bool   `validate:"omitempty"`
}

// Views
type getAuthRegistrationViews struct {
	password *view
	oidc     *view
	passkey  *view
}

// Prepare rendering data
func newGetAuthRegistrationRenderingData(r *http.Request) getAuthRegistrationRenderingData {
	reqParams := &getAuthRegistrationRequestParams{
		FlowID:              r.URL.Query().Get("flow"),
		PasskeyRegistration: r.URL.Query().Get("passkey_registration") == "true",
	}
	views := getAuthRegistrationViews{
		password: newView("auth/registration/index.html").addParams(reqParams.toViewParams()).addParams(map[string]any{"Method": "password"}),
		oidc:     newView("auth/registration/index.html").addParams(reqParams.toViewParams()).addParams(map[string]any{"Method": "passkey"}),
		passkey:  newView("auth/registration/index.html").addParams(reqParams.toViewParams()).addParams(map[string]any{"Method": "oidc"}),
	}
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))
	return getAuthRegistrationRenderingData{
		reqParams:     reqParams,
		views:         views,
		baseViewError: baseViewError,
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
func (p *Provider) getAuthRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	rd := newGetAuthRegistrationRenderingData(r)

	// validate request parameters
	if viewError := rd.reqParams.validate(); viewError.hasError() {
		rd.views.password.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// create or get registration Flow
	var err error
	rd.registrationFlow, rd.kratosResponseHeader, err = p.d.Kratos.CreateOrGetRegistrationFlow(ctx, makeDefaultKratosRequestHeader(r), rd.reqParams.FlowID)
	if err != nil {
		rd.views.password.addParams(rd.baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	switch rd.registrationFlow.CredentialType {
	case kratos.CredentialsTypePassword:
		p.renderGetAuthRegistrationCredentialsTypePassword(ctx, w, r, rd)
	case kratos.CredentialsTypeOidc:
		p.renderGetAuthRegistrationCredentialsTypeOidc(ctx, w, r, rd)
	default:
		slog.ErrorContext(ctx, "invalid credential type", "credential type", rd.registrationFlow.CredentialType)
	}
}

func (p *Provider) renderGetAuthRegistrationCredentialsTypePassword(ctx context.Context, w http.ResponseWriter, r *http.Request, rd getAuthRegistrationRenderingData) {
	session := getSession(ctx)
	addCookies(w, rd.kratosResponseHeader.Cookie)
	setHeadersForReplaceBody(w, "/auth/registration")
	if rd.reqParams.PasskeyRegistration {
		rd.views.passkey.addParams(map[string]any{
			"RegistrationFlowID": rd.registrationFlow.FlowID,
			"CsrfToken":          rd.registrationFlow.CsrfToken,
			"Traits":             rd.registrationFlow.Traits,
			"PasskeyCreateData":  rd.registrationFlow.PasskeyCreateData,
		}).render(w, r, session)
	} else {
		rd.views.password.addParams(map[string]any{
			"RegistrationFlowID": rd.registrationFlow.FlowID,
			"CsrfToken":          rd.registrationFlow.CsrfToken,
		}).render(w, r, session)
	}
}

func (p *Provider) renderGetAuthRegistrationCredentialsTypeOidc(ctx context.Context, w http.ResponseWriter, r *http.Request, rd getAuthRegistrationRenderingData) {
	session := getSession(ctx)

	// Update identity when user already registered with the same credential of provided the oidc provider.
	identity, err := p.d.Kratos.AdminGetIdentity(ctx, kratos.AdminGetIdentityRequest{
		ID: rd.registrationFlow.Traits.Email,
	})
	if err != nil {
		message := pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "ERR_DEFAULT",
		})
		rd.views.oidc.addParams(rd.baseViewError.setMessages([]string{message}).toViewParams()).render(w, r, session)
		return
	}
	if identity != nil {
		// Transferring cookies from create or get registration flow response
		kratosRequestHeader := makeDefaultKratosRequestHeader(r)
		// kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, kratosResponseHeader.Cookie)
		kratosRequestHeader.Cookie = strings.Join(rd.kratosResponseHeader.Cookie, " ")

		// update Registration Flow
		kratosResp, err := p.d.Kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
			FlowID: rd.registrationFlow.FlowID,
			Header: kratosRequestHeader,
			Body: kratos.UpdateRegistrationFlowRequestBody{
				Method:    "oidc",
				CsrfToken: rd.registrationFlow.CsrfToken,
				Provider:  string(rd.registrationFlow.OidcProvider),
				Traits:    identity.Traits,
			},
		})
		if err != nil {
			slog.ErrorContext(ctx, "update registration error", "err", err)
			rd.views.oidc.addParams(rd.baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}
		addCookies(w, kratosResp.Header.Cookie)
		if kratosResp.RedirectBrowserTo != "" {
			// w.Header().Set("HX-Redirect", kratosResp.RedirectBrowserTo)
			redirect(w, r, kratosResp.RedirectBrowserTo)
		}
	}

	// render page
	addCookies(w, rd.kratosResponseHeader.Cookie) // set cookie that was responsed last from kratos (exclude admin api).
	rd.views.oidc.addParams(map[string]any{
		"RegistrationFlowID": rd.registrationFlow.FlowID,
		"CsrfToken":          rd.registrationFlow.CsrfToken,
		"Provider":           rd.registrationFlow.OidcProvider,
		"Traits":             rd.registrationFlow.Traits,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/registration/step-one
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationStepOne
type postAuthRegistrationStepOneRequestParams struct {
	FlowID    string        `validate:"required,uuid4"`
	CsrfToken string        `validate:"required"`
	Traits    kratos.Traits `validate:"required"`
}

// Extract parameters from http request
func newPostAuthRegistrationStepOneRequestParams(r *http.Request) *postAuthRegistrationStepOneRequestParams {
	return &postAuthRegistrationStepOneRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
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
func (p *postAuthRegistrationStepOneRequestParams) toViewParams() map[string]any {
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
func (params *postAuthRegistrationStepOneRequestParams) validate() *viewError {
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
func (p *Provider) handlePostAuthRegistrationStepOne(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAuthRegistrationStepOneRequestParams(r)

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
	addCookies(w, getVerificationFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", getVerificationFlowResp.VerificationFlow.FlowID))
	verificationCodeView.addParams(map[string]any{
		"VerificationFlowID": getVerificationFlowResp.VerificationFlow.FlowID,
		"CsrfToken":          getVerificationFlowResp.VerificationFlow.CsrfToken,
		"IsUsedFlow":         getVerificationFlowResp.VerificationFlow.IsUsedFlow(),
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/registration/step-two/password
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationStepTwoPassword
type postAuthRegistrationPasswordRequestParams struct {
	FlowID               string        `validate:"required,uuid4"`
	CsrfToken            string        `validate:"required"`
	Traits               kratos.Traits `validate:"required"`
	Password             string        `validate:"required,eqfield=PasswordConfirmation" ja:"パスワード"`
	PasswordConfirmation string        `validate:"required" ja:"パスワード確認"`
}

// Extract parameters from http request
func newPostAuthRegistrationPasswordRequestParams(r *http.Request) *postAuthRegistrationPasswordRequestParams {
	return &postAuthRegistrationPasswordRequestParams{
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
func (p *postAuthRegistrationPasswordRequestParams) toViewParams() map[string]any {
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
func (params *postAuthRegistrationPasswordRequestParams) validate() *viewError {
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
func (p *Provider) handlePostAuthRegistrationStepTwoPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAuthRegistrationPasswordRequestParams(r)

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
	addCookies(w, getVerificationFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", getVerificationFlowResp.VerificationFlow.FlowID))
	verificationCodeView.addParams(map[string]any{
		"VerificationFlowID": getVerificationFlowResp.VerificationFlow.FlowID,
		"CsrfToken":          getVerificationFlowResp.VerificationFlow.CsrfToken,
		"IsUsedFlow":         getVerificationFlowResp.VerificationFlow.IsUsedFlow(),
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/registration/step-two/oidc
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationStepTwoOidc
type postAuthRegistrationStepTwoOidcRequestParams struct {
	FlowID    string        `validate:"required,uuid4"`
	CsrfToken string        `validate:"required"`
	Provider  string        `validate:"required"`
	Traits    kratos.Traits `validate:"required"`
}

// Extract parameters from http request
func newpostAuthRegistrationStepTwoOidcRequestParams(r *http.Request) *postAuthRegistrationStepTwoOidcRequestParams {
	return &postAuthRegistrationStepTwoOidcRequestParams{
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
func (p *postAuthRegistrationStepTwoOidcRequestParams) toViewParams() map[string]any {
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
func (params *postAuthRegistrationStepTwoOidcRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostAuthRegistrationStepTwoOidc(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newpostAuthRegistrationStepTwoOidcRequestParams(r)

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

	addCookies(w, kratosResp.Header.Cookie)
	if kratosResp.RedirectBrowserTo != "" {
		redirect(w, r, kratosResp.RedirectBrowserTo)
	}
}

// --------------------------------------------------------------------------
// POST /auth/registration/step-two/passkey
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationStepTwoPasskey
type postAuthRegistrationStepTwoPasskeyRequestParams struct {
	FlowID          string        `validate:"required,uuid4"`
	CsrfToken       string        `validate:"required"`
	Traits          kratos.Traits `validate:"required"`
	PasskeyRegister string
}

// Extract parameters from http request
func newpostAuthRegistrationStepTwoPasskeyRequestParams(r *http.Request) *postAuthRegistrationStepTwoPasskeyRequestParams {
	return &postAuthRegistrationStepTwoPasskeyRequestParams{
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
func (p *postAuthRegistrationStepTwoPasskeyRequestParams) toViewParams() map[string]any {
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
func (params *postAuthRegistrationStepTwoPasskeyRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostAuthRegistrationStepTwoPasskey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newpostAuthRegistrationStepTwoPasskeyRequestParams(r)

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
	addCookies(w, kratosResp.Header.Cookie)
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
