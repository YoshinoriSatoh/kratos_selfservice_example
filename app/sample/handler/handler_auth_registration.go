package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /auth/registration
// This is also used from oidc callback ui url when missing required fields in traits.
// --------------------------------------------------------------------------

// Request parameters
type getAuthRegistrationRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
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

// Views
type getAuthRegistrationViews struct {
	profile *view
	oidc    *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthRegistration(w http.ResponseWriter, r *http.Request) (*getAuthRegistrationRequestParams, getAuthRegistrationViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))
	reqParams := &getAuthRegistrationRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}
	views := getAuthRegistrationViews{
		profile: newView("auth/registration/index.html").addParams(reqParams.toViewParams()).addParams(map[string]any{"Method": "profile"}),
		oidc:    newView("auth/registration/index.html").addParams(reqParams.toViewParams()).addParams(map[string]any{"Method": "oidc"}),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.profile.addParams(viewError.toViewParams()).render(w, r, session)
		err := fmt.Errorf("validation error: %v", viewError)
		slog.ErrorContext(ctx, "validation error", "viewError", viewError)
		return reqParams, views, baseViewError, err
	}

	return reqParams, views, baseViewError, nil
}

// handler
func (p *Provider) handleGetAuthRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthRegistration(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthRegistration failed", "err", err)
		return
	}

	// create or get registration Flow
	registrationFlow, kratosRespHeader, kratosReqHeaderForNext, err := kratos.KratosCreateOrGetRegistrationFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		slog.Debug("handleGetAuthRegistration", "KratosCreateOrGetRegistrationFlow err", err)
		views.profile.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	slog.Debug("handleGetAuthRegistration", "registrationFlow", registrationFlow)
	// Update identity when user already registered with the same credential of provided the oidc provider.
	if registrationFlow.OidcProvider.Provided() {
		kratosUpdateRegistrationFlowResp, _, err := kratos.KratosLinkIdentityIfExists(ctx, kratos.KratosLinkIdentityIfExistsRequest{
			CredentialIdentifier: registrationFlow.Traits.Email,
			RequestHeader:        kratosReqHeaderForNext,
			RegistrationFlow:     registrationFlow,
		})
		if err != nil {
			slog.Error("Kratos.LinkIdentityIfExists failed", "error", err)
			views.oidc.addParams(baseViewError.setMessages([]string{pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_DEFAULT",
			})}).toViewParams()).render(w, r, session)
			return
		}
		if kratosUpdateRegistrationFlowResp != nil {
			addCookies(w, kratosUpdateRegistrationFlowResp.Header.Cookie)
			if kratosUpdateRegistrationFlowResp.RedirectBrowserTo != "" {
				// w.Header().Set("HX-Redirect", kratosResp.RedirectBrowserTo)
				redirect(w, r, kratosUpdateRegistrationFlowResp.RedirectBrowserTo)
				return
			}
		}

		addCookies(w, kratosRespHeader.Cookie) // set cookie that was responsed last from kratos (exclude admin api).
		views.oidc.addParams(map[string]any{
			"RegistrationFlowID": registrationFlow.FlowID,
			"CsrfToken":          registrationFlow.CsrfToken,
			"Provider":           registrationFlow.OidcProvider,
			"Traits":             registrationFlow.Traits,
		}).render(w, r, session)
		return
	}

	addCookies(w, kratosRespHeader.Cookie)
	setHeadersForReplaceBody(w, "/auth/registration")
	views.profile.addParams(map[string]any{
		"RegistrationFlowID": registrationFlow.FlowID,
		"CsrfToken":          registrationFlow.CsrfToken,
		"Traits":             registrationFlow.Traits,
		"PasskeyCreateData":  registrationFlow.PasskeyCreateData,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/registration/credential/password
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationCredentialPassword
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

// Views
type getAuthRegistrationCredentialPasswordViews struct {
	form *view
	code *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthRegistrationCredentialPassword(w http.ResponseWriter, r *http.Request) (*postAuthRegistrationPasswordRequestParams, getAuthRegistrationCredentialPasswordViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))
	reqParams := newPostAuthRegistrationPasswordRequestParams(r)
	views := getAuthRegistrationCredentialPasswordViews{
		form: newView("auth/registration/_credential_password_form.html").addParams(reqParams.toViewParams()),
		code: newView("auth/verification/code.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.form.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

// POST /auth/registration
func (p *Provider) handlePostAuthRegistrationCredentialPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthRegistrationCredentialPassword(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthRegistrationCredentialPassword failed", "err", err)
		return
	}

	// update Registration Flow
	updateRegistrationFlowResp, kratosReqHeaderForNext, err := kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRegistrationFlowRequestBody{
			CsrfToken: reqParams.CsrfToken,
			Method:    "password",
			Traits:    reqParams.Traits,
			Password:  reqParams.Password,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update registration error", "err", err.Error())
		views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// get verification flow
	getVerificationFlowResp, _, err := kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
		FlowID: updateRegistrationFlowResp.VerificationFlowID,
		Header: kratosReqHeaderForNext,
	})
	if err != nil {
		slog.ErrorContext(ctx, "get verification error", "err", err.Error())
		views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render verification code page (replace <body> tag and push url)
	addCookies(w, getVerificationFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", getVerificationFlowResp.VerificationFlow.FlowID))
	views.code.addParams(map[string]any{
		"VerificationFlowID": getVerificationFlowResp.VerificationFlow.FlowID,
		"CsrfToken":          getVerificationFlowResp.VerificationFlow.CsrfToken,
		"IsUsedFlow":         getVerificationFlowResp.VerificationFlow.IsUsedFlow(),
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/registration/credential/passkey
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationCredentialPasskey
type postAuthRegistrationCredentialPasskeyRequestParams struct {
	FlowID          string        `validate:"required,uuid4"`
	CsrfToken       string        `validate:"required"`
	Traits          kratos.Traits `validate:"required"`
	PasskeyRegister string
}

// Extract parameters from http request
func newpostAuthRegistrationCredentialPasskeyRequestParams(r *http.Request) *postAuthRegistrationCredentialPasskeyRequestParams {
	return &postAuthRegistrationCredentialPasskeyRequestParams{
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
func (p *postAuthRegistrationCredentialPasskeyRequestParams) toViewParams() map[string]any {
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
func (params *postAuthRegistrationCredentialPasskeyRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getAuthRegistrationCredentialPasskeyViews struct {
	form *view
	code *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthRegistrationCredentialPasskey(w http.ResponseWriter, r *http.Request) (*postAuthRegistrationCredentialPasskeyRequestParams, getAuthRegistrationCredentialPasskeyViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))
	reqParams := newpostAuthRegistrationCredentialPasskeyRequestParams(r)
	views := getAuthRegistrationCredentialPasskeyViews{
		form: newView("auth/registration/_credential_passkey_form.html").addParams(reqParams.toViewParams()),
		code: newView("auth/verification/code.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.form.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthRegistrationCredentialPasskey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthRegistrationCredentialPasskey(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthRegistrationCredentialPasskey failed", "err", err)
		return
	}

	// Registration Flow 更新
	updateRegistrationFlowResp, kratosReqHeaderForNext, err := kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRegistrationFlowRequestBody{
			CsrfToken:       reqParams.CsrfToken,
			Method:          "passkey",
			Traits:          reqParams.Traits,
			PasskeyRegister: reqParams.PasskeyRegister,
		},
	})
	if err != nil {
		views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	if updateRegistrationFlowResp.DuplicateIdentifier != "" {
		views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	if updateRegistrationFlowResp.RedirectBrowserTo != "" {
		redirect(w, r, updateRegistrationFlowResp.RedirectBrowserTo)
		w.WriteHeader(http.StatusOK)
	}

	// get verification flow
	getVerificationFlowResp, _, err := kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
		FlowID: updateRegistrationFlowResp.VerificationFlowID,
		Header: kratosReqHeaderForNext,
	})
	if err != nil {
		slog.ErrorContext(ctx, "get verification error", "err", err.Error())
		views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render verification code page (replace <body> tag and push url)
	addCookies(w, getVerificationFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", getVerificationFlowResp.VerificationFlow.FlowID))
	views.code.addParams(map[string]any{
		"VerificationFlowID": getVerificationFlowResp.VerificationFlow.FlowID,
		"CsrfToken":          getVerificationFlowResp.VerificationFlow.CsrfToken,
		"IsUsedFlow":         getVerificationFlowResp.VerificationFlow.IsUsedFlow(),
	}).render(w, r, session)

	// // OIDC Loginの場合、同一クレデンシャルが存在する場合、既存Identityとのリンクを促す
	// var (
	// 	information     string
	// 	traits          kratos.Traits
	// 	showSocialLogin bool
	// )
	// if kratosResp.DuplicateIdentifier == "" {
	// 	showSocialLogin = true
	// } else {
	// 	traits.Email = kratosResp.DuplicateIdentifier
	// 	showSocialLogin = false
	// 	information = "メールアドレスとパスワードで登録された既存のアカウントが存在します。パスワードを入力してログインすると、Googleのアカウントと連携されます。"
	// }

	// // create login flow
	// createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
	// 	Header: kratosReqHeaderForNext,
	// })
	// if err != nil {
	// 	slog.ErrorContext(ctx, "update verification error", "err", err.Error())
	// 	views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
	// 	return
	// }
	// addCookies(w, kratosResp.Header.Cookie)
	// setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
	// newView("auth/login/index.html").addParams(reqParams.toViewParams()).addParams(map[string]any{
	// 	"LoginFlowID":      createLoginFlowResp.LoginFlow.FlowID,
	// 	"Information":      information,
	// 	"CsrfToken":        createLoginFlowResp.LoginFlow.CsrfToken,
	// 	"Traits":           traits,
	// 	"ShowSocialLogin":  showSocialLogin,
	// 	"ShowPasskeyLogin": true,
	// 	"PasskeyChallenge": createLoginFlowResp.LoginFlow.PasskeyChallenge,
	// }).render(w, r, session)

	// Registration flow成功時はVerification flowへリダイレクト
	// redirect(w, r, fmt.Sprintf("%s?flow=%s", "/auth/verification/code", output.VerificationFlowID))
}

// --------------------------------------------------------------------------
// POST /auth/registration/credential/oidc
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationCredentialOidc
type postAuthRegistrationCredentialOidcRequestParams struct {
	FlowID    string        `validate:"required,uuid4"`
	CsrfToken string        `validate:"required"`
	Provider  string        `validate:"required"`
	Traits    kratos.Traits `validate:"required"`
}

// Extract parameters from http request
func newpostAuthRegistrationCredentialOidcRequestParams(r *http.Request) *postAuthRegistrationCredentialOidcRequestParams {
	return &postAuthRegistrationCredentialOidcRequestParams{
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
func (p *postAuthRegistrationCredentialOidcRequestParams) toViewParams() map[string]any {
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
func (params *postAuthRegistrationCredentialOidcRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getAuthRegistrationCredentialOidcViews struct {
	form *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthRegistrationCredentialOidc(w http.ResponseWriter, r *http.Request) (*postAuthRegistrationCredentialOidcRequestParams, getAuthRegistrationCredentialOidcViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))
	reqParams := newpostAuthRegistrationCredentialOidcRequestParams(r)
	views := getAuthRegistrationCredentialOidcViews{
		form: newView("auth/registration/_profile_form.html").addParams(reqParams.toViewParams()).addParams(map[string]any{"Method": "oidc"}),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.form.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthRegistrationCredentialOidc(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthRegistrationCredentialOidc(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthRegistrationCredentialOidc failed", "err", err)
		return
	}

	// update Registration Flow
	kratosResp, _, err := kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRegistrationFlowRequestBody{
			CsrfToken: reqParams.CsrfToken,
			Method:    "oidc",
			Provider:  reqParams.Provider,
			Traits:    reqParams.Traits,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "handlePostAuthRegistrationCredentialOidc", "UpdateRegistrationFlow error", err)
		views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, kratosResp.Header.Cookie)
	if kratosResp.RedirectBrowserTo != "" {
		redirect(w, r, kratosResp.RedirectBrowserTo)
	}
}

// --------------------------------------------------------------------------
// POST /auth/registration/profile
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationProfile
type postAuthRegistrationProfileRequestParams struct {
	FlowID    string        `validate:"required,uuid4"`
	CsrfToken string        `validate:"required"`
	Traits    kratos.Traits `validate:"required"`
}

// Extract parameters from http request
func newPostAuthRegistrationProfileRequestParams(r *http.Request) *postAuthRegistrationProfileRequestParams {
	return &postAuthRegistrationProfileRequestParams{
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
func (p *postAuthRegistrationProfileRequestParams) toViewParams() map[string]any {
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
func (params *postAuthRegistrationProfileRequestParams) validate() *viewError {
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

// Views
type getAuthRegistrationProfileViews struct {
	formProfile    *view
	formCredential *view
}

// collect rendering data and validate request parameters.
func preparePostAuthRegistrationProfile(w http.ResponseWriter, r *http.Request) (*postAuthRegistrationProfileRequestParams, getAuthRegistrationProfileViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))
	reqParams := newPostAuthRegistrationProfileRequestParams(r)
	views := getAuthRegistrationProfileViews{
		formProfile:    newView("auth/registration/_profile_form.html").addParams(reqParams.toViewParams()).addParams(map[string]any{"Method": "profile"}),
		formCredential: newView("auth/registration/_credential_form.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.formProfile.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

// POST /auth/registration
func (p *Provider) handlePostAuthRegistrationProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := preparePostAuthRegistrationProfile(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "preparePostAuthRegistrationProfile failed", "err", err)
		return
	}

	// update Registration Flow
	updateRegistrationFlowResp, _, err := kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRegistrationFlowRequestBody{
			CsrfToken: reqParams.CsrfToken,
			Method:    "profile",
			Screen:    "credential-selection",
			Traits:    reqParams.Traits,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update registration error", "err", err.Error())
		views.formProfile.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// get latest registration flow
	// kratosReqHeaderForNext should return the header of UpdateRegistrationFlow, so do not get it here
	getRegistrationFlowResp, _, err := kratos.GetRegistrationFlow(ctx, kratos.GetRegistrationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		slog.ErrorContext(ctx, "get registration error", "GetRegistrationFlow error", err)
		return
	}

	// render verification code page (replace <body> tag and push url)
	addCookies(w, updateRegistrationFlowResp.Header.Cookie)
	views.formCredential.addParams(map[string]any{
		"RegistrationFlowID": reqParams.FlowID,
		"CsrfToken":          reqParams.CsrfToken,
		"PasskeyCreateData":  getRegistrationFlowResp.RegistrationFlow.PasskeyCreateData,
	}).render(w, r, session)
}
