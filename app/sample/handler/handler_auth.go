package handler

import (
	"fmt"
	"kratos_example/kratos"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /auth/registration
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthRegistration
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

	return viewError
}

// GET /auth/registration
func (p *Provider) handleGetAuthRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := getAuthRegistrationRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	registrationIndexView := newView(r, "auth/registration/index.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		registrationIndexView.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// create or get registration Flow
	var err error
	var registrationFlow kratos.RegistrationFlow
	if params.FlowID == "" {
		registrationFlow, err = p.d.Kratos.CreateRegistrationFlow(ctx, w, r, kratos.CreateRegistrationFlowInput{})
	} else {
		registrationFlow, err = p.d.Kratos.GetRegistrationFlow(ctx, w, r, kratos.GetRegistrationFlowInput{
			FlowID: params.FlowID,
		})
	}
	if err != nil {
		registrationIndexView.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}
	slog.DebugContext(ctx, "debug", "registrationFlow", registrationFlow)

	// render page
	registrationIndexView.addParams(map[string]any{
		"RegistrationFlowID": registrationFlow.FlowID,
		"CsrfToken":          registrationFlow.CsrfToken,
	}).render(w, session)
}

// --------------------------------------------------------------------------
// GET /auth/registration/oidc
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthRegistrationOidc
type getAuthRegistrationOidcRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
}

// Return parameters that can refer in view template
func (p *getAuthRegistrationOidcRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RegistrationFlowID": p.FlowID,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getAuthRegistrationOidcRequestParams) validate() *viewError {
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

	return viewError
}

// GET /auth/registration/oidc
func (p *Provider) handleGetAuthRegistrationOidc(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := getAuthRegistrationOidcRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	registrationOidcView := newView(r, "auth/registration/oidc.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		registrationOidcView.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// create or get registration Flow
	var err error
	var registrationFlow kratos.RegistrationFlow
	if params.FlowID == "" {
		registrationFlow, err = p.d.Kratos.CreateRegistrationFlow(ctx, w, r, kratos.CreateRegistrationFlowInput{})
	} else {
		registrationFlow, err = p.d.Kratos.GetRegistrationFlow(ctx, w, r, kratos.GetRegistrationFlowInput{
			FlowID: params.FlowID,
		})
	}
	if err != nil {
		registrationOidcView.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

	// Get and fill identity traits to view parameters when user already registered with the credential of provided the oidc provider,
	// if registrationFlow.CredentialType == kratos.CredentialsTypeOIDC {
	identities, err := p.d.Kratos.AdminListIdentities(ctx, w, r, kratos.AdminListIdentitiesInput{
		CredentialIdentifier: registrationFlow.Traits.Email,
	})
	if err != nil {
		registrationOidcView.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}
	if len(identities) > 1 {
		message := pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "ERR_DEFAULT",
		})
		registrationOidcView.addParams(baseViewError.setMessages([]string{message}).toViewParams()).render(w, session)
		return
	}

	if len(identities) == 1 {
		_, err = p.d.Kratos.UpdateRegistrationFlow(ctx, w, r, kratos.UpdateRegistrationFlowInput{
			FlowID:    registrationFlow.FlowID,
			CsrfToken: registrationFlow.CsrfToken,
			Method:    "oidc",
			Provider:  "google",
			Traits:    identities[0].Traits,
		})
		if err != nil {
			registrationOidcView.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
			return
		}
		// }
	}

	// render page
	registrationOidcView.addParams(map[string]any{
		"RegistrationFlowID": registrationFlow.FlowID,
		"CsrfToken":          registrationFlow.CsrfToken,
		"Traits":             registrationFlow.Traits,
	}).render(w, session)

}

// --------------------------------------------------------------------------
// GET /auth/registration/passkey
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthRegistrationPasskey
type getAuthRegistrationdPasskeyRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
}

// Return parameters that can refer in view template
func (p *getAuthRegistrationdPasskeyRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RegistrationFlowID": p.FlowID,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getAuthRegistrationdPasskeyRequestParams) validate() *viewError {
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

	return viewError
}

// GET /auth/registration/passkey
func (p *Provider) handleGetAuthRegistrationPasskey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	params := getAuthRegistrationdPasskeyRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	registrationPasskeyView := newView(r, "auth/registration/passkey.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		registrationPasskeyView.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// create or get registration Flow
	var err error
	var registrationFlow kratos.RegistrationFlow
	if params.FlowID == "" {
		registrationFlow, err = p.d.Kratos.CreateRegistrationFlow(ctx, w, r, kratos.CreateRegistrationFlowInput{})
	} else {
		registrationFlow, err = p.d.Kratos.GetRegistrationFlow(ctx, w, r, kratos.GetRegistrationFlowInput{
			FlowID: params.FlowID,
		})
	}
	if err != nil {
		registrationPasskeyView.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

	// render page
	registrationPasskeyView.addParams(map[string]any{
		"RegistrationFlowID": registrationFlow.FlowID,
		"CsrfToken":          registrationFlow.CsrfToken,
		"Traits":             registrationFlow.Traits,
		"PasskeyCreateData":  registrationFlow.PasskeyCreateData,
	}).render(w, session)
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
	var (
		year  string
		month string
		day   string
	)
	r := regexp.MustCompile(`(?P<Year>\d{4})-(?P<Month>\d{2})-(?P<Day>\d{2})`)
	if r.Match([]byte(p.Traits.Birthdate)) {
		caps := r.FindStringSubmatch(p.Traits.Birthdate)
		year = caps[1]
		month = caps[2]
		day = caps[3]
	}
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
	registrationFormView := newView("auth/registration/_form.html").addParams(params.toViewParams())
	verificationCodeView := newView("auth/verification/code.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		slog.DebugContext(ctx, "validation error", "viewError", viewError)
		registrationFormView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// update Registration Flow
	updateRegistrationFlowResponse, err := p.d.Kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
		FlowID: params.FlowID,
		Header: kratos.KratosRequestHeader{
			Cookie:   r.Header.Get("Cookie"),
			ClientIP: r.RemoteAddr,
		},
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
	// get verification flow
	getVerificationFlowResp, err := p.d.Kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
		FlowID: updateRegistrationFlowResponse.VerificationFlowID,
		Header: kratos.KratosRequestHeader{
			Cookie:   updateRegistrationFlowResponse.Header.Cookie, // Transferring cookies from update registration flow response
			ClientIP: r.RemoteAddr,
		},
	})
	if err != nil {
		slog.DebugContext(ctx, "get verification error", "err", err.Error())
		registrationFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render verification code page (replace <body> tag and push url)
	w.Header().Set("Set-Cookie", updateRegistrationFlowResponse.Header.Cookie)
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

// Return parameters that can refer in view template
func (p *postAuthRegistrationOidcRequestParams) toViewParams() map[string]any {
	var (
		year  string
		month string
		day   string
	)
	r := regexp.MustCompile(`(?P<Year>\d{4})-(?P<Month>\d{2})-(?P<Day>\d{2})`)
	if r.Match([]byte(p.Traits.Birthdate)) {
		caps := r.FindStringSubmatch(p.Traits.Birthdate)
		year = caps[1]
		month = caps[2]
		day = caps[3]
	}
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
	params := postAuthRegistrationOidcRequestParams{
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

	// prepare views
	registrationFormOidc := newView(r, "auth/registration/_form_oidc.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		registrationFormOidc.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// update Registration Flow
	kratosResp, err := p.d.Kratos.UpdateRegistrationFlow(ctx, w, r, kratos.UpdateRegistrationFlowInput{
		FlowID:    params.FlowID,
		CsrfToken: params.CsrfToken,
		Method:    "oidc",
		Provider:  params.Provider,
		Traits:    params.Traits,
	})
	if err != nil {
		registrationFormOidc.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

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

// Return parameters that can refer in view template
func (p *postAuthRegistrationPasskeyRequestParams) toViewParams() map[string]any {
	var (
		year  string
		month string
		day   string
	)
	r := regexp.MustCompile(`(?P<Year>\d{4})-(?P<Month>\d{2})-(?P<Day>\d{2})`)
	if r.Match([]byte(p.Traits.Birthdate)) {
		caps := r.FindStringSubmatch(p.Traits.Birthdate)
		year = caps[1]
		month = caps[2]
		day = caps[3]
	}
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
	params := postAuthRegistrationPasskeyRequestParams{
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

	// prepare views
	registrationFormPasskey := newView(r, "auth/registration/_form_passkey.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		registrationFormPasskey.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// Registration Flow 更新
	kratosResp, err := p.d.Kratos.UpdateRegistrationFlow(ctx, w, r, kratos.UpdateRegistrationFlowInput{
		FlowID:          params.FlowID,
		CsrfToken:       params.CsrfToken,
		Method:          "passkey",
		Traits:          params.Traits,
		PasskeyRegister: params.PasskeyRegister,
	})
	if err != nil {
		registrationFormPasskey.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

	if kratosResp.RedirectBrowserTo != "" {
		redirect(w, r, kratosResp.RedirectBrowserTo)
		w.WriteHeader(http.StatusOK)
	}

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
	params := getAuthVerificationRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	verificationIndex := newView(r, "auth/verification/index.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		verificationIndex.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_VERIFICATION_DEDAULT",
	}))

	// create or get verification Flow
	var err error
	var verificationFlow kratos.VerificationFlow
	if params.FlowID == "" {
		verificationFlow, err = p.d.Kratos.CreateVerificationFlow(ctx, w, r, kratos.CreateVerificationFlowInput{})
	} else {
		verificationFlow, err = p.d.Kratos.GetVerificationFlow(ctx, w, r, kratos.GetVerificationFlowInput{
			FlowID: params.FlowID,
		})
	}
	if err != nil {
		verificationIndex.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

	// render page
	verificationIndex.addParams(map[string]any{
		"VerificationFlowID": verificationFlow.FlowID,
		"CsrfToken":          verificationFlow.CsrfToken,
		"IsUsedFlow":         verificationFlow.IsUsedFlow,
	}).render(w, session)
}

// --------------------------------------------------------------------------
// GET /auth/registration/code
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthVerificationCode
type getAuthVerificationCodeRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
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
	params := getAuthVerificationRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	verificationCode := newView(r, "auth/verification/_code_form.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		verificationCode.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_VERIFICATION_DEDAULT",
	}))

	// create or get verification Flow
	var err error
	var verificationFlow kratos.VerificationFlow
	if params.FlowID == "" {
		verificationFlow, err = p.d.Kratos.CreateVerificationFlow(ctx, w, r, kratos.CreateVerificationFlowInput{})
	} else {
		verificationFlow, err = p.d.Kratos.GetVerificationFlow(ctx, w, r, kratos.GetVerificationFlowInput{
			FlowID: params.FlowID,
		})
	}
	if err != nil {
		verificationCode.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

	// render page
	verificationCode.addParams(map[string]any{
		"VerificationFlowID": verificationFlow.FlowID,
		"CsrfToken":          verificationFlow.CsrfToken,
		"IsUsedFlow":         verificationFlow.IsUsedFlow,
	}).render(w, session)
}

// --------------------------------------------------------------------------
// POST /auth/verificatoin/email
// --------------------------------------------------------------------------
// Request parameters for handlePostVerificationEmail
type postVerificationEmailRequestParams struct {
	FlowID    string `validate:"uuid4"`
	CsrfToken string `validate:"required"`
	Email     string `validate:"required,email" ja:"メールアドレス"`
}

// Return parameters that can refer in view template
func (p *postVerificationEmailRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"VerificationFlowID": p.FlowID,
		"CsrfToken":          p.CsrfToken,
		"Email":              p.Email,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postVerificationEmailRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostVerificationEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	params := postVerificationEmailRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Email:     r.PostFormValue("email"),
	}

	// prepare views
	verificationCode := newView(r, "auth/verification/_email_form.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		verificationCode.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// Verification Flow 更新
	updateVerificationFlowResponse, err := p.d.Kratos.UpdateVerificationFlow(ctx, w, r, kratos.UpdateVerificationFlowInput{
		FlowID:    params.FlowID,
		CsrfToken: params.CsrfToken,
		Email:     params.Email,
	})
	if err != nil {
		verificationCode.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

	// render page
	puthUrl := fmt.Sprintf("/auth/verification/code?flow=%s", params.FlowID)
	verificationCode.setPushUrl(puthUrl).addParams(map[string]any{
		"VerificationFlowID": updateVerificationFlowResponse.Flow.FlowID,
		"CsrfToken":          updateVerificationFlowResponse.Flow.CsrfToken,
		"IsUsedFlow":         updateVerificationFlowResponse.Flow.IsUsedFlow,
	}).render(w, session)
}

// --------------------------------------------------------------------------
// POST /auth/verificatoin/code
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationCode
type postVerificationCodeRequestParams struct {
	FlowID    string `validate:"uuid4"`
	CsrfToken string `validate:"required"`
	Code      string `validate:"required,len=6,number" ja:"検証コード"`
}

// Return parameters that can refer in view template
func (p *postVerificationCodeRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"VerificationFlowID": p.FlowID,
		"CsrfToken":          p.CsrfToken,
		"Code":               p.Code,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postVerificationCodeRequestParams) validate() *viewError {
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

func (p *Provider) handlePostVerificationCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := postVerificationCodeRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Code:      r.PostFormValue("code"),
	}

	// prepare views
	verificationCode := newView(r, "auth/verification/_code_form.html", params.toViewParams())
	loginIndex := newView(r, "auth/login/index.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		verificationCode.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// Verification Flow 更新
	_, err := p.d.Kratos.UpdateVerificationFlow(ctx, w, r, kratos.UpdateVerificationFlowInput{
		FlowID:    params.FlowID,
		Code:      params.Code,
		CsrfToken: params.CsrfToken,
	})
	if err != nil {
		slog.DebugContext(ctx, "update verification error", "err", err.Error())
		verificationCode.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

	loginFlow, err := p.d.Kratos.CreateLoginFlow(ctx, w, r, kratos.CreateLoginFlowInput{})
	if err != nil {
		slog.DebugContext(ctx, "update verification error", "err", err.Error())
		verificationCode.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

	// render page
	puthUrl := fmt.Sprintf("/auth/login?flow=%s", loginFlow.FlowID)
	loginIndex.setPushUrl(puthUrl).addParams(map[string]any{
		"LoginFlowID": loginFlow.FlowID,
		"Information": "コードによる検証が完了しました。お手数ですが改めてログインしてください。",
		"CsrfToken":   loginFlow.CsrfToken,
	}).render(w, session)
}

// --------------------------------------------------------------------------
// GET /auth/login
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthLogin
type getAuthLoginRequestParams struct {
	FlowID   string `validate:"omitempty,uuid4"`
	ReturnTo string
}

// Return parameters that can refer in view template
func (p *getAuthLoginRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RegistrationFlowID": p.FlowID,
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
	params := getAuthLoginRequestParams{
		FlowID:   r.URL.Query().Get("flow"),
		ReturnTo: url.QueryEscape(r.URL.Query().Get("return_to")),
	}

	// 認証済みの場合、認証時刻の更新を実施
	// プロフィール設定時に認証時刻が一定期間内である必要があり、過ぎている場合はログイン画面へリダイレクトし、ログインを促している
	refresh := isAuthenticated(session)

	// prepare views
	loginIndexView := newView(r, "auth/login/index.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		loginIndexView.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// create or get registration Flow
	var err error
	var loginFlow kratos.LoginFlow
	if params.FlowID == "" {
		loginFlow, err = p.d.Kratos.CreateLoginFlow(ctx, w, r, kratos.CreateLoginFlowInput{
			Refresh: refresh,
		})
	} else {
		loginFlow, err = p.d.Kratos.GetLoginFlow(ctx, w, r, kratos.GetLoginFlowInput{
			FlowID: params.FlowID,
		})
	}
	if err != nil {
		loginIndexView.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

	var information string
	var traits kratos.Traits
	showSocialLogin := true
	if loginFlow.DuplicateIdentifier != "" {
		traits.Email = loginFlow.DuplicateIdentifier
		showSocialLogin = false
		information = "メールアドレスとパスワードで登録された既存のアカウントが存在します。パスワードを入力してログインすると、Googleのアカウントと連携されます。"
	}

	// if existsAfterLoginHook(r, AFTER_LOGIN_HOOK_COOKIE_KEY_SETTINGS_PROFILE_UPDATE) {
	// 	information = "プロフィール更新のために、再度ログインをお願いします。"
	// }

	loginIndexView.addParams(map[string]any{
		"LoginFlowID":      loginFlow.FlowID,
		"ReturnTo":         params.ReturnTo,
		"Information":      information,
		"CsrfToken":        loginFlow.CsrfToken,
		"Traits":           traits,
		"ShowSocialLogin":  showSocialLogin,
		"ShowPasskeyLogin": true,
		"PasskeyChallenge": loginFlow.PasskeyChallenge,
	}).render(w, session)
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
}

// Return parameters that can refer in view template
func (p *postAuthLoginRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID": p.FlowID,
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

	params := postAuthLoginRequestParams{
		FlowID:     r.URL.Query().Get("flow"),
		CsrfToken:  r.PostFormValue("csrf_token"),
		Identifier: r.PostFormValue("identifier"),
		Password:   r.PostFormValue("password"),
	}

	// prepare views
	loginForm := newView(r, "auth/login/_form.html", params.toViewParams())
	topIndex := newView(r, "auth/top/index.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		loginForm.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// update login flow
	_, err := p.d.Kratos.UpdateLoginFlow(ctx, w, r, kratos.UpdateLoginFlowInput{
		FlowID:     params.FlowID,
		CsrfToken:  params.CsrfToken,
		Identifier: params.Identifier,
		Password:   params.Password,
	})
	if err != nil {
		loginForm.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

	// update session
	session, _ = p.d.Kratos.Whoami(ctx, w, r)

	// // ログインフック実行
	// hook, err := loadAfterLoginHook(r, AFTER_LOGIN_HOOK_COOKIE_KEY_SETTINGS_PROFILE_UPDATE)
	// if err != nil {
	// 	slog.Error(err.Error())
	// 	return
	// }
	// if hook.Operation == AFTER_LOGIN_HOOK_OPERATION_UPDATE_PROFILE {
	// 	hookParams, _ := hook.Params.(map[string]interface{})
	// 	err := p.updateProfile(w, r, updateProfileParams{
	// 		FlowID:    hookParams["flow_id"].(string),
	// 		Email:     hookParams["email"].(string),
	// 		Nickname:  hookParams["nickname"].(string),
	// 		Birthdate: hookParams["birthdate"].(string),
	// 	})
	// 	if err != nil {
	// 		slog.Error(err.Error())
	// 		return
	// 	}
	// }

	// // return_to 指定時はreturn_toへリダイレクト
	// returnTo := r.URL.Query().Get("return_to")
	// slog.Info(returnTo)
	// var redirectTo string
	// if returnTo != "" {
	// 	redirectTo = returnTo
	// } else {
	// 	redirectTo = "/"
	// }
	// redirect(w, r, redirectTo)

	topIndex.setPushUrl("/").addParams(map[string]any{
		"Items": items,
	}).render(w, session)
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

	params := postAuthLoginOidcRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Provider:  r.PostFormValue("provider"),
	}
	// prepare views
	loginForm := newView(r, "auth/login/_form.html", params.toViewParams())
	topIndex := newView(r, "auth/top/index.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		loginForm.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// update login flow
	_, err := p.d.Kratos.UpdateOidcLoginFlow(ctx, w, r, kratos.UpdateOidcLoginFlowInput{
		FlowID:    params.FlowID,
		CsrfToken: params.CsrfToken,
		Provider:  params.Provider,
	})
	if err != nil {
		loginForm.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

	// update session
	session, _ = p.d.Kratos.Whoami(ctx, w, r)

	// render
	topIndex.setPushUrl("/").addParams(map[string]any{
		"Items": items,
	}).render(w, session)
}

// --------------------------------------------------------------------------
// POST /auth/logout
// --------------------------------------------------------------------------

func (p *Provider) handlePostAuthLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	topIndex := newView(r, "auth/top/index.html", map[string]any{})

	err := p.d.Kratos.Logout(ctx, w, r)
	// http.SetCookie(w, &http.Cookie{
	// 	Name:     pkgVars.cookieParams.SessionCookieName,
	// 	Value:    "",
	// 	MaxAge:   -1,
	// 	Path:     pkgVars.cookieParams.Path,
	// 	Domain:   pkgVars.cookieParams.Domain,
	// 	Secure:   pkgVars.cookieParams.Secure,
	// 	HttpOnly: true,
	// })
	if err != nil {
		topIndex.setPushUrl("/").addParams(map[string]any{
			"Items": items,
		}).render(w, session)
	}

	// update session
	session, _ = p.d.Kratos.Whoami(ctx, w, r)

	// render
	topIndex.setPushUrl("/").addParams(map[string]any{
		"Items": items,
	}).render(w, session)
}

// --------------------------------------------------------------------------
// GET /auth/recovery
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthRecovery
type getAuthRecoveryRequestParams struct {
	FlowID string
}

// Return parameters that can refer in view template
func (p *getAuthRecoveryRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RegistrationFlowID": p.FlowID,
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
	params := getAuthRecoveryRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	recoveryIndexView := newView(r, "auth/recovery/index.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		recoveryIndexView.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	var err error
	var recoveryFlow kratos.RecoveryFlow
	if params.FlowID == "" {
		recoveryFlow, err = p.d.Kratos.CreateRecoveryFlow(ctx, w, r, kratos.CreateRecoveryFlowInput{})
	} else {
		recoveryFlow, err = p.d.Kratos.GetRecoveryFlow(ctx, w, r, kratos.GetRecoveryFlowInput{
			FlowID: params.FlowID,
		})
	}
	if err != nil {
		recoveryIndexView.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

	// render page
	recoveryIndexView.addParams(map[string]any{
		"RecoveryFlowID": recoveryFlow.FlowID,
		"CsrfToken":      recoveryFlow.CsrfToken,
	}).render(w, session)
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

// Return parameters that can refer in view template
func (p *postAuthRecoveryEmailRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RegistrationFlowID": p.FlowID,
		"CsrfToken":          p.CsrfToken,
		"Email":              p.Email,
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
	params := postAuthRecoveryEmailRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Email:     r.PostFormValue("email"),
	}

	// prepare views
	recoveryCodeFormView := newView(r, "auth/recovery/_code_form.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		recoveryCodeFormView.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// update Recovery flow
	kratosResp, err := p.d.Kratos.UpdateRecoveryFlow(ctx, w, r, kratos.UpdateRecoveryFlowInput{
		FlowID:    params.FlowID,
		CsrfToken: params.CsrfToken,
		Email:     params.Email,
	})
	if err != nil {
		recoveryCodeFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

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
	}).render(w, session)
}

// --------------------------------------------------------------------------
// POST /auth/recovery/code
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRecoveryCode
type postAuthRecoveryCodeRequestParams struct {
	FlowID    string `validate:"uuid4"`
	CsrfToken string `validate:"required"`
	Code      string `validate:"required,,len=6,number" ja:"復旧コード"`
}

// Return parameters that can refer in view template
func (p *postAuthRecoveryCodeRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RegistrationFlowID": p.FlowID,
		"CsrfToken":          p.CsrfToken,
		"Code":               p.Code,
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
	params := postAuthRecoveryCodeRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Code:      r.PostFormValue("code"),
	}

	// prepare views
	recoveryCodeFormView := newView(r, "auth/recovery/_code_form.html", params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		recoveryCodeFormView.addParams(viewError.toViewParams()).render(w, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// Recovery Flow 更新
	kratosResp, err := p.d.Kratos.UpdateRecoveryFlow(ctx, w, r, kratos.UpdateRecoveryFlowInput{
		FlowID:    params.FlowID,
		CsrfToken: params.CsrfToken,
		Code:      params.Code,
	})
	if err != nil {
		recoveryCodeFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, session)
		return
	}

	if kratosResp.RedirectBrowserTo != "" {
		redirect(w, r, kratosResp.RedirectBrowserTo)
		w.WriteHeader(http.StatusOK)
	}
}
