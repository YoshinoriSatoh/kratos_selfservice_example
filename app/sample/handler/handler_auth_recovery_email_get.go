package handler

import (
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

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
	kratosResp, err := kratos.UpdateRecoveryFlow(ctx, kratos.UpdateRecoveryFlowRequest{
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
	addCookies(w, kratosResp.Header.Cookie)

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
