package handler

import (
	"fmt"
	"log/slog"
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

// Views
type getAuthRecoveryEmailViews struct {
	emailForm *view
	codeForm  *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthRecoveryEmail(w http.ResponseWriter, r *http.Request) (*postAuthRecoveryEmailRequestParams, getAuthRecoveryEmailViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_RECOVERY_DEFAULT",
	}))
	reqParams := newPostAutRecoveryEmailRequestParams(r)
	views := getAuthRecoveryEmailViews{
		emailForm: newView("auth/recovery/_email_form.html").addParams(reqParams.toViewParams()),
		codeForm:  newView("auth/recovery/_code_form.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.emailForm.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthRecoveryEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthRecoveryEmail(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthRecoveryEmail failed", "err", err)
		return
	}

	// update Recovery flow
	kratosResp, _, err := kratos.UpdateRecoveryFlow(ctx, kratos.UpdateRecoveryFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRecoveryFlowRequestBody{
			CsrfToken: reqParams.CsrfToken,
			Method:    "code",
			Email:     reqParams.Email,
		},
	})
	if err != nil {
		views.emailForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	addCookies(w, kratosResp.Header.Cookie)

	if kratosResp.RedirectBrowserTo != "" {
		redirect(w, r, kratosResp.RedirectBrowserTo)
		w.WriteHeader(http.StatusOK)
	}

	// render
	views.codeForm.addParams(map[string]any{
		"RecoveryFlowID":           reqParams.FlowID,
		"CsrfToken":                reqParams.CsrfToken,
		"Email":                    reqParams.Email,
		"ShowRecoveryAnnouncement": true,
	}).render(w, r, session)
}
