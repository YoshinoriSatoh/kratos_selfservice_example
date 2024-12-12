package handler

import (
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

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

// Views
type getAuthVerificationCodeViews struct {
	verificationCode *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthVerificationCode(w http.ResponseWriter, r *http.Request) (*getAuthVerificationCodeRequestParams, getAuthVerificationCodeViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newGetAuthVerificationCodeRequestParams(r)

	// prepare views
	views := getAuthVerificationCodeViews{
		verificationCode: newView("auth/verification/_code_form.html").addParams(params.toViewParams()),
	}

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		views.verificationCode.addParams(viewError.toViewParams()).render(w, r, session)
		return params, views, viewError, nil
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_VERIFICATION_DEDAULT",
	}))

	return params, views, baseViewError, nil
}

// Handler GET /auth/verification/code
func (p *Provider) handleGetAuthVerificationCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	params, views, baseViewError, err := prepareGetAuthVerificationCode(w, r)
	if err != nil {
		views.verificationCode.addParams(baseViewError.toViewParams()).render(w, r, session)
		return
	}

	// create or get verification Flow
	verificationFlow, kratosResponseHeader, _, err := kratos.CreateOrGetVerificationFlow(ctx, makeDefaultKratosRequestHeader(r), params.FlowID)
	if err != nil {
		views.verificationCode.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	addCookies(w, kratosResponseHeader.Cookie)
	views.verificationCode.addParams(map[string]any{
		"VerificationFlowID": verificationFlow.FlowID,
		"CsrfToken":          verificationFlow.CsrfToken,
		"IsUsedFlow":         verificationFlow.IsUsedFlow,
	}).render(w, r, session)
}
