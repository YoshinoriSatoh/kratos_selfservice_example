package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
)

// --------------------------------------------------------------------------
// GET /auth/registration
// This is also used from oidc callback ui url when missing required fields in traits.
// --------------------------------------------------------------------------

// Request parameters
type getAuthRegistrationRequestParams struct {
	FlowID   string `form:"flow" validate:"omitempty,uuid4"`
	ReturnTo string `form:"return_to" validate:"omitempty"`
}

// handler
func (p *Provider) handleGetAuthRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	registrationIndexView := newView(TPL_AUTH_REGISTRATION_INDEX)

	// bind and validate request parameters
	var reqParams getAuthRegistrationRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handleGetAuthRegistration bind request error", "err", err)
		registrationIndexView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	registrationIndexView.addParams(requestParamsToMap(reqParams))

	// create or get registration Flow
	response, _, _, err := kratos.CreateOrGetRegistrationFlow(ctx, kratos.CreateOrGetRegistrationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		slog.ErrorContext(ctx, "create registration flow error", "err", err)
		registrationIndexView.setKratosMsg(err).render(w, r, session)
		return
	}

	slog.Debug("handleGetAuthRegistration", "registrationFlow", response)

	addCookies(w, response.UpdateRegistrationFlowResponse.Header.Cookie)

	// Update identity when user already registered with the same credential of provided the oidc provider.
	if response.UpdateRegistrationFlowResponse != nil {
		if response.UpdateRegistrationFlowResponse.RedirectBrowserTo != "" {
			redirect(w, r, response.UpdateRegistrationFlowResponse.RedirectBrowserTo, []string{})
			return
		}
	}

	registrationIndexView.addParams(map[string]any{
		"RegistrationFlowID": response.RegistrationFlow.FlowID,
		"CsrfToken":          response.RegistrationFlow.CsrfToken,
		"Traits":             response.RegistrationFlow.Traits,
		"PasskeyCreateData":  response.RegistrationFlow.PasskeyCreateData,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/registration/profile
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationProfile
type postAuthRegistrationProfileRequestParams struct {
	FlowID    string        `form:"flow" validate:"required,uuid4"`
	CsrfToken string        `json:"csrf_token" validate:"required"`
	Traits    kratos.Traits `validate:"required"`
	Provider  string        `json:"provider" validate:"required"`
}

func (p *Provider) handlePostAuthRegistrationProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	profileFormView := newView(TPL_AUTH_REGISTRATION_PROFILE_FORM)

	// bind and validate request parameters
	var reqParams postAuthRegistrationProfileRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthRegistrationProfile bind request error", "err", err)
		profileFormView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	year, month, day := parseDate(reqParams.Traits.Birthdate)
	profileFormView.addParams(requestParamsToMap(reqParams))
	profileFormView.addParams(map[string]any{
		"BirthdateYear":  year,
		"BirthdateMonth": month,
		"BirthdateDay":   day,
		"Method":         "profile",
	})

	// update Registration Flow
	var updateRegistrationFlowResp kratos.UpdateRegistrationFlowResponse
	var err error
	if reqParams.Provider == "oidc" {
		updateRegistrationFlowResp, _, err = kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
			FlowID: reqParams.FlowID,
			Header: makeDefaultKratosRequestHeader(r),
			Body: kratos.UpdateRegistrationFlowRequestBody{
				CsrfToken: reqParams.CsrfToken,
				Method:    "oidc",
				Provider:  reqParams.Provider,
				Traits:    reqParams.Traits,
			},
		})
	} else {
		updateRegistrationFlowResp, _, err = kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
			FlowID: reqParams.FlowID,
			Header: makeDefaultKratosRequestHeader(r),
			Body: kratos.UpdateRegistrationFlowRequestBody{
				CsrfToken: reqParams.CsrfToken,
				Method:    "profile",
				Screen:    "credential-selection",
				Traits:    reqParams.Traits,
			},
		})
	}
	if err != nil {
		slog.ErrorContext(ctx, "update registration error", "err", err)
		profileFormView.setKratosMsg(err).render(w, r, session)
		return
	}

	addCookies(w, updateRegistrationFlowResp.Header.Cookie)
	if updateRegistrationFlowResp.RedirectBrowserTo != "" {
		redirect(w, r, updateRegistrationFlowResp.RedirectBrowserTo, []string{})
		return
	}
	redirect(w, r, fmt.Sprintf("/auth/registration/credential?flow=%s", reqParams.FlowID), []string{})
}

// --------------------------------------------------------------------------
// GET /auth/registration/credential
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthRegistrationCredential
type getAuthRegistrationCredentialRequestParams struct {
	FlowID string `form:"flow" validate:"required,uuid4"`
}

func (p *Provider) handleGetAuthRegistrationCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	credentialView := newView(TPL_AUTH_REGISTRATION_CREDENTIAL)

	// bind and validate request parameters
	var reqParams getAuthRegistrationCredentialRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handleGetAuthRegistrationCredential bind request error", "err", err)
		credentialView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	credentialView.addParams(requestParamsToMap(reqParams))

	// create or get registration Flow
	response, kratosRespHeader, _, err := kratos.CreateOrGetRegistrationFlow(ctx, kratos.CreateOrGetRegistrationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		slog.ErrorContext(ctx, "create registration flow error", "err", err)
		credentialView.setKratosMsg(err).render(w, r, session)
		return
	}

	// Update identity when user already registered with the same credential of provided the oidc provider.
	if response.UpdateRegistrationFlowResponse != nil {
		addCookies(w, response.UpdateRegistrationFlowResponse.Header.Cookie)
		if response.UpdateRegistrationFlowResponse.RedirectBrowserTo != "" {
			redirect(w, r, response.UpdateRegistrationFlowResponse.RedirectBrowserTo, []string{})
			return
		}

		credentialView.addParams(map[string]any{
			"RegistrationFlowID": reqParams.FlowID,
			"Method":             "oidc",
			"CsrfToken":          response.RegistrationFlow.CsrfToken,
			"Provider":           response.RegistrationFlow.OidcProvider,
			"Traits":             response.RegistrationFlow.Traits,
		}).render(w, r, session)
		return
	}

	addCookies(w, kratosRespHeader.Cookie)
	credentialView.addParams(map[string]any{
		"RegistrationFlowID": response.RegistrationFlow.FlowID,
		"CsrfToken":          response.RegistrationFlow.CsrfToken,
		"Traits":             response.RegistrationFlow.Traits,
		"PasskeyCreateData":  response.RegistrationFlow.PasskeyCreateData,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/registration/credential/password
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationCredentialPassword
type postAuthRegistrationPasswordRequestParams struct {
	FlowID               string        `form:"flow" validate:"required,uuid4"`
	CsrfToken            string        `json:"csrf_token" validate:"required"`
	Traits               kratos.Traits `validate:"required"`
	Password             string        `json:"password" validate:"required,eqfield=PasswordConfirmation" ja:"パスワード"`
	PasswordConfirmation string        `json:"password_confirmation" validate:"required" ja:"パスワード確認"`
}

func (p *Provider) handlePostAuthRegistrationCredentialPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	credentialPasswordFormView := newView(TPL_AUTH_REGISTRATION_CREDENTIAL_PASSWORD_FORM)

	// bind and validate request parameters
	var reqParams postAuthRegistrationPasswordRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthRegistrationCredentialPassword bind request error", "err", err)
		credentialPasswordFormView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	year, month, day := parseDate(reqParams.Traits.Birthdate)
	credentialPasswordFormView.addParams(requestParamsToMap(reqParams))
	credentialPasswordFormView.addParams(map[string]any{
		"BirthdateYear":  year,
		"BirthdateMonth": month,
		"BirthdateDay":   day,
	})

	// update Registration Flow
	updateRegistrationFlowResp, _, err := kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
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
		slog.ErrorContext(ctx, "update registration error", "err", err)
		credentialPasswordFormView.setKratosMsg(err).render(w, r, session)
		return
	}

	// render verification code page
	addCookies(w, updateRegistrationFlowResp.VerificationFlowCookie)
	redirect(w, r, fmt.Sprintf("/auth/verification/code?flow=%s", updateRegistrationFlowResp.VerificationFlow.FlowID), []string{})
}

// --------------------------------------------------------------------------
// POST /auth/registration/credential/passkey
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationCredentialPasskey
type postAuthRegistrationCredentialPasskeyRequestParams struct {
	FlowID          string        `form:"flow" validate:"required,uuid4"`
	CsrfToken       string        `json:"csrf_token" validate:"required"`
	Traits          kratos.Traits `validate:"required"`
	PasskeyRegister string        `json:"passkey_register"`
}

func (p *Provider) handlePostAuthRegistrationCredentialPasskey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	credentialPasskeyFormView := newView(TPL_AUTH_REGISTRATION_CREDENTIAL_PASSKEY_FORM)

	// bind and validate request parameters
	var reqParams postAuthRegistrationCredentialPasskeyRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthRegistrationCredentialPasskey bind request error", "err", err)
		credentialPasskeyFormView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	year, month, day := parseDate(reqParams.Traits.Birthdate)
	credentialPasskeyFormView.addParams(requestParamsToMap(reqParams))
	credentialPasskeyFormView.addParams(map[string]any{
		"BirthdateYear":  year,
		"BirthdateMonth": month,
		"BirthdateDay":   day,
	})

	// update Registration Flow
	updateRegistrationFlowResp, _, err := kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
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
		slog.ErrorContext(ctx, "update registration error", "err", err)
		credentialPasskeyFormView.setKratosMsg(err).render(w, r, session)
		return
	}

	if updateRegistrationFlowResp.RedirectBrowserTo != "" {
		slog.Debug("handlePostAuthRegistrationCredentialPasskey", "redirectBrowserTo", updateRegistrationFlowResp.RedirectBrowserTo)
		redirect(w, r, updateRegistrationFlowResp.RedirectBrowserTo, []string{})
		return
	}

	// render verification code page
	addCookies(w, updateRegistrationFlowResp.VerificationFlowCookie)
	redirect(w, r, fmt.Sprintf("/auth/verification/code?flow=%s", updateRegistrationFlowResp.VerificationFlow.FlowID), []string{})
}
