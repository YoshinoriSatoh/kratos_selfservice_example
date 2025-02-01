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

// handler
func (p *Provider) handleGetAuthRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &getAuthRegistrationRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	profileView := newView(TPL_AUTH_REGISTRATION_INDEX).addParams(map[string]any{
		"RegistrationFlowID": reqParams.FlowID,
		"Method":             "profile",
	})
	oidcView := newView(TPL_AUTH_REGISTRATION_INDEX).addParams(map[string]any{
		"RegistrationFlowID": reqParams.FlowID,
		"Method":             "oidc",
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	for k := range viewError.validationFieldErrors {
		if k == "FlowID" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
			break
		}
	}
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handleGetAuthRegistration validation error", "messages", viewError.messages)
		profileView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// create or get registration Flow
	registrationFlow, kratosRespHeader, kratosReqHeaderForNext, err := kratos.KratosCreateOrGetRegistrationFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		slog.Debug("handleGetAuthRegistration", "KratosCreateOrGetRegistrationFlow err", err)
		profileView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
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
			oidcView.addParams(newViewError().setMessages([]string{pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_DEFAULT",
			})}).toViewParams()).render(w, r, session)
			return
		}
		if kratosUpdateRegistrationFlowResp != nil {
			addCookies(w, kratosUpdateRegistrationFlowResp.Header.Cookie)
			if kratosUpdateRegistrationFlowResp.RedirectBrowserTo != "" {
				redirect(w, r, kratosUpdateRegistrationFlowResp.RedirectBrowserTo, map[string]string{})
				return
			}
		}

		addCookies(w, kratosRespHeader.Cookie)
		oidcView.addParams(map[string]any{
			"RegistrationFlowID": registrationFlow.FlowID,
			"CsrfToken":          registrationFlow.CsrfToken,
			"Provider":           registrationFlow.OidcProvider,
			"Traits":             registrationFlow.Traits,
		}).render(w, r, session)
		return
	}

	addCookies(w, kratosRespHeader.Cookie)
	setHeadersForReplaceBody(w, "/auth/registration")
	profileView.addParams(map[string]any{
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

// POST /auth/registration
func (p *Provider) handlePostAuthRegistrationCredentialPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &postAuthRegistrationPasswordRequestParams{
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

	// prepare views
	year, month, day := parseDate(reqParams.Traits.Birthdate)
	formView := newView(TPL_AUTH_REGISTRATION_FORM).addParams(map[string]any{
		"RegistrationFlowID":   reqParams.FlowID,
		"CsrfToken":            reqParams.CsrfToken,
		"Traits":               reqParams.Traits,
		"BirthdateYear":        year,
		"BirthdateMonth":       month,
		"BirthdateDay":         day,
		"Password":             reqParams.Password,
		"PasswordConfirmation": reqParams.PasswordConfirmation,
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	for k := range viewError.validationFieldErrors {
		if k == "FlowID" || k == "CsrfToken" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
			break
		}
	}
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handlePostAuthRegistrationCredentialPassword validation error", "messages", viewError.messages)
		formView.addParams(viewError.toViewParams()).render(w, r, session)
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
		formView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// get verification flow
	getVerificationFlowResp, _, err := kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
		FlowID: updateRegistrationFlowResp.VerificationFlowID,
		Header: kratosReqHeaderForNext,
	})
	if err != nil {
		slog.ErrorContext(ctx, "get verification error", "err", err.Error())
		formView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render verification code page (replace <body> tag and push url)
	addCookies(w, getVerificationFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", getVerificationFlowResp.VerificationFlow.FlowID))
	newView(TPL_AUTH_VERIFICATION_CODE).addParams(map[string]any{
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

func (p *Provider) handlePostAuthRegistrationCredentialPasskey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &postAuthRegistrationCredentialPasskeyRequestParams{
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
	year, month, day := parseDate(reqParams.Traits.Birthdate)
	formView := newView(TPL_AUTH_REGISTRATION_FORM).addParams(map[string]any{
		"RegistrationFlowID": reqParams.FlowID,
		"CsrfToken":          reqParams.CsrfToken,
		"Traits":             reqParams.Traits,
		"BirthdateYear":      year,
		"BirthdateMonth":     month,
		"BirthdateDay":       day,
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handlePostAuthRegistrationCredentialPasskey validation error", "messages", viewError.messages)
		formView.addParams(viewError.toViewParams()).render(w, r, session)
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
		formView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}
	if updateRegistrationFlowResp.DuplicateIdentifier != "" {
		formView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	if updateRegistrationFlowResp.RedirectBrowserTo != "" {
		redirect(w, r, updateRegistrationFlowResp.RedirectBrowserTo, map[string]string{})
		w.WriteHeader(http.StatusOK)
	}

	// get verification flow
	getVerificationFlowResp, _, err := kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
		FlowID: updateRegistrationFlowResp.VerificationFlowID,
		Header: kratosReqHeaderForNext,
	})
	if err != nil {
		slog.ErrorContext(ctx, "get verification error", "err", err.Error())
		formView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render verification code page (replace <body> tag and push url)
	addCookies(w, getVerificationFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", getVerificationFlowResp.VerificationFlow.FlowID))
	newView(TPL_AUTH_VERIFICATION_CODE).addParams(map[string]any{
		"VerificationFlowID": getVerificationFlowResp.VerificationFlow.FlowID,
		"CsrfToken":          getVerificationFlowResp.VerificationFlow.CsrfToken,
		"IsUsedFlow":         getVerificationFlowResp.VerificationFlow.IsUsedFlow(),
	}).render(w, r, session)
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

func (p *Provider) handlePostAuthRegistrationCredentialOidc(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &postAuthRegistrationCredentialOidcRequestParams{
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
	year, month, day := parseDate(reqParams.Traits.Birthdate)
	formView := newView(TPL_AUTH_REGISTRATION_FORM).addParams(map[string]any{
		"RegistrationFlowID": reqParams.FlowID,
		"CsrfToken":          reqParams.CsrfToken,
		"Traits":             reqParams.Traits,
		"BirthdateYear":      year,
		"BirthdateMonth":     month,
		"BirthdateDay":       day,
		"Method":             "oidc",
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handlePostAuthRegistrationCredentialOidc validation error", "messages", viewError.messages)
		formView.addParams(viewError.toViewParams()).render(w, r, session)
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
		formView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, kratosResp.Header.Cookie)
	if kratosResp.RedirectBrowserTo != "" {
		redirect(w, r, kratosResp.RedirectBrowserTo, map[string]string{})
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

func (p *Provider) handlePostAuthRegistrationProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &postAuthRegistrationProfileRequestParams{
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

	// prepare views
	year, month, day := parseDate(reqParams.Traits.Birthdate)
	profileFormView := newView(TPL_AUTH_REGISTRATION_FORM).addParams(map[string]any{
		"RegistrationFlowID": reqParams.FlowID,
		"CsrfToken":          reqParams.CsrfToken,
		"Traits":             reqParams.Traits,
		"BirthdateYear":      year,
		"BirthdateMonth":     month,
		"BirthdateDay":       day,
		"Method":             "profile",
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	for k := range viewError.validationFieldErrors {
		if k == "FlowID" || k == "CsrfToken" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
			break
		}
	}
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handlePostAuthRegistrationProfile validation error", "messages", viewError.messages)
		profileFormView.addParams(viewError.toViewParams()).render(w, r, session)
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
		profileFormView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
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
	newView(TPL_AUTH_REGISTRATION_FORM).addParams(map[string]any{
		"RegistrationFlowID": reqParams.FlowID,
		"CsrfToken":          reqParams.CsrfToken,
		"PasskeyCreateData":  getRegistrationFlowResp.RegistrationFlow.PasskeyCreateData,
	}).render(w, r, session)
}
