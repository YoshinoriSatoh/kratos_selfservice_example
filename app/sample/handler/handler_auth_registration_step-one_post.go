package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

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
	updateRegistrationFlowResp, err := kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
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
	getVerificationFlowResp, err := kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
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
