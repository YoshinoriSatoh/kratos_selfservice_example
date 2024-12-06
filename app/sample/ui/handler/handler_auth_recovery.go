package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/YoshinoriSatoh/kratos_example/external/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /auth/recovery
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthRecovery
type getAuthRecoveryRequestParams struct {
	FlowID string
}

// Extract parameters from http request
func newGetAuthRecoveryRequestParams(r *http.Request) *getAuthRecoveryRequestParams {
	return &getAuthRecoveryRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}
}

// Return parameters that can refer in view template
func (p *getAuthRecoveryRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RecoveryFlowID": p.FlowID,
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
	params := newGetAuthRecoveryRequestParams(r)

	// prepare views
	recoveryIndexView := newView("auth/recovery/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		recoveryIndexView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_RECOVERY_DEFAULT",
	}))

	// create or get recovery Flow
	var (
		err                  error
		recoveryFlow         kratos.RecoveryFlow
		kratosResponseHeader kratos.KratosResponseHeader
	)
	if params.FlowID == "" {
		var createRecoveryFlowResp kratos.CreateRecoveryFlowResponse
		createRecoveryFlowResp, err = p.d.Kratos.CreateRecoveryFlow(ctx, kratos.CreateRecoveryFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = createRecoveryFlowResp.Header
		recoveryFlow = createRecoveryFlowResp.RecoveryFlow
	} else {
		var getRecoveryFlowResp kratos.GetRecoveryFlowResponse
		getRecoveryFlowResp, err = p.d.Kratos.GetRecoveryFlow(ctx, kratos.GetRecoveryFlowRequest{
			FlowID: params.FlowID,
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = getRecoveryFlowResp.Header
		recoveryFlow = getRecoveryFlowResp.RecoveryFlow
	}
	if err != nil {
		recoveryIndexView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	addCookies(w, kratosResponseHeader.Cookie)
	recoveryIndexView.addParams(map[string]any{
		"RecoveryFlowID": recoveryFlow.FlowID,
		"CsrfToken":      recoveryFlow.CsrfToken,
	}).render(w, r, session)
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
	kratosResp, err := p.d.Kratos.UpdateRecoveryFlow(ctx, kratos.UpdateRecoveryFlowRequest{
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

// --------------------------------------------------------------------------
// POST /auth/recovery/code
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRecoveryCode
type postAuthRecoveryCodeRequestParams struct {
	FlowID    string `validate:"uuid4"`
	CsrfToken string `validate:"required"`
	Code      string `validate:"required,len=6,number" ja:"復旧コード"`
}

// Extract parameters from http request
func newPostAutRecoveryCodeRequestParams(r *http.Request) *postAuthRecoveryCodeRequestParams {
	return &postAuthRecoveryCodeRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Code:      r.PostFormValue("code"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthRecoveryCodeRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RecoveryFlowID": p.FlowID,
		"CsrfToken":      p.CsrfToken,
		"Code":           p.Code,
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
	params := newPostAutRecoveryCodeRequestParams(r)

	// prepare views
	recoveryCodeFormView := newView("auth/recovery/_code_form.html").addParams(params.toViewParams())
	myPasswordIndexView := newView("my/password/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		recoveryCodeFormView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_RECOVERY_DEFAULT",
	}))

	// Recovery Flow 更新
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)
	kratosResp, err := p.d.Kratos.UpdateRecoveryFlow(ctx, kratos.UpdateRecoveryFlowRequest{
		FlowID: params.FlowID,
		Header: kratosRequestHeader,
		Body: kratos.UpdateRecoveryFlowRequestBody{
			CsrfToken: params.CsrfToken,
			Method:    "code",
			Code:      params.Code,
		},
	})
	if err != nil {
		recoveryCodeFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, kratosResp.Header.Cookie)
	if kratosResp.RedirectBrowserTo != "" {
		arr := strings.Split(kratosResp.RedirectBrowserTo, "=")
		settingsFlowID := arr[1]
		kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, kratosResp.Header.Cookie)

		getSettingsFlowResp, err := p.d.Kratos.GetSettingsFlow(ctx, kratos.GetSettingsFlowRequest{
			FlowID: settingsFlowID,
			Header: kratosRequestHeader,
		})
		if err != nil {
			recoveryCodeFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}
		addCookies(w, getSettingsFlowResp.Header.Cookie)
		setHeadersForReplaceBody(w, fmt.Sprintf("/my/password?flow=%s", settingsFlowID))
		myPasswordIndexView.addParams(map[string]any{
			"SettingsFlowID": settingsFlowID,
			"CsrfToken":      getSettingsFlowResp.SettingsFlow.CsrfToken,
		}).render(w, r, session)
	}
}
