package handler

import (
	"fmt"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

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

// collect rendering data and validate request parameters.
func preparePostAuthVerificationEmail(w http.ResponseWriter, r *http.Request) (*postAuthVerificationEmailRequestParams, *view, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAuthVerificationEmailRequestParams(r)

	// prepare views
	verificationCodeView := newView("auth/verification/_email_form.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		verificationCodeView.addParams(viewError.toViewParams()).render(w, r, session)
		return params, verificationCodeView, viewError, nil
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_VERIFICATION_DEFAULT",
	}))

	return params, verificationCodeView, baseViewError, nil
}

func (p *Provider) handlePostAuthVerificationEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	params, verificationCodeView, baseViewError, err := preparePostAuthVerificationEmail(w, r)
	if err != nil {
		verificationCodeView.addParams(baseViewError.toViewParams()).render(w, r, session)
		return
	}

	// Verification Flow 更新
	updateVerificationFlowResp, _, err := kratos.UpdateVerificationFlow(ctx, kratos.UpdateVerificationFlowRequest{
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
	addCookies(w, updateVerificationFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", params.FlowID))
	verificationCodeView.addParams(map[string]any{
		"VerificationFlowID": updateVerificationFlowResp.Flow.FlowID,
		"CsrfToken":          updateVerificationFlowResp.Flow.CsrfToken,
		"IsUsedFlow":         updateVerificationFlowResp.Flow.IsUsedFlow,
	}).render(w, r, session)
}
