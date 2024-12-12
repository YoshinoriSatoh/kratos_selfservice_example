package handler

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /auth/verification
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthVerification
type getAuthVerificationRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
}

// Extract parameters from http request
func newGetAuthVerificationRequestParams(r *http.Request) *getAuthVerificationRequestParams {
	return &getAuthVerificationRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}
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

// Views
type getAuthVerificationViews struct {
	index *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthVerification(w http.ResponseWriter, r *http.Request) (*getAuthVerificationRequestParams, getAuthVerificationViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_VERIFICATION_DEFAULT",
	}))
	reqParams := newGetAuthVerificationRequestParams(r)
	views := getAuthVerificationViews{
		index: newView("auth/verification/index.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.index.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

// Handler GET /auth/verification
func (p *Provider) handleGetAuthVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthVerification(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthVerification failed", "err", err)
		return
	}

	// create or get verification Flow
	verificationFlow, kratosResponseHeader, err := kratos.CreateOrGetVerificationFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		views.index.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	addCookies(w, kratosResponseHeader.Cookie)
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)
	kratosRequestHeader.Cookie = strings.Join(kratosResponseHeader.Cookie, " ")
	views.index.addParams(map[string]any{
		"VerificationFlowID": verificationFlow.FlowID,
		"CsrfToken":          verificationFlow.CsrfToken,
		"IsUsedFlow":         verificationFlow.IsUsedFlow,
	}).render(w, r, session)
}

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

// Handler GET /auth/verification/code
func (p *Provider) handleGetAuthVerificationCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newGetAuthVerificationCodeRequestParams(r)

	// prepare views
	verificationCodeView := newView("auth/verification/_code_form.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		verificationCodeView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_VERIFICATION_DEDAULT",
	}))

	// create or get verification Flow
	verificationFlow, kratosResponseHeader, err := kratos.CreateOrGetVerificationFlow(ctx, makeDefaultKratosRequestHeader(r), params.FlowID)
	if err != nil {
		verificationCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	addCookies(w, kratosResponseHeader.Cookie)
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)
	kratosRequestHeader.Cookie = strings.Join(kratosResponseHeader.Cookie, " ")
	verificationCodeView.addParams(map[string]any{
		"VerificationFlowID": verificationFlow.FlowID,
		"CsrfToken":          verificationFlow.CsrfToken,
		"IsUsedFlow":         verificationFlow.IsUsedFlow,
	}).render(w, r, session)
}

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

func (p *Provider) handlePostAuthVerificationEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAuthVerificationEmailRequestParams(r)

	// prepare views
	verificationCodeView := newView("auth/verification/_email_form.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		verificationCodeView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_VERIFICATION_DEFAULT",
	}))

	// Verification Flow 更新
	updateVerificationFlowResp, err := kratos.UpdateVerificationFlow(ctx, kratos.UpdateVerificationFlowRequest{
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

// --------------------------------------------------------------------------
// POST /auth/verificatoin/code
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationCode
type postAuthVerificationCodeRequestParams struct {
	FlowID    string `validate:"uuid4"`
	CsrfToken string `validate:"required"`
	Code      string `validate:"required,len=6,number" ja:"検証コード"`
	Render    string
}

// Extract parameters from http request
func newPostAuthVerificationCodeRequestParams(r *http.Request) *postAuthVerificationCodeRequestParams {
	return &postAuthVerificationCodeRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		Render:    r.PostFormValue("render"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Code:      r.PostFormValue("code"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthVerificationCodeRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"VerificationFlowID": p.FlowID,
		"Render":             p.Render,
		"CsrfToken":          p.CsrfToken,
		"Code":               p.Code,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthVerificationCodeRequestParams) validate() *viewError {
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

func (p *Provider) handlePostAuthVerificationCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newPostAuthVerificationCodeRequestParams(r)

	// prepare views
	verificationCodeView := newView("auth/verification/_code_form.html").addParams(params.toViewParams())
	loginIndexView := newView("auth/login/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		verificationCodeView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_VERIFICATION_DEFAULT",
	}))

	// Verification Flow 更新
	updateVerificationFlowResp, err := kratos.UpdateVerificationFlow(ctx, kratos.UpdateVerificationFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateVerificationFlowRequestBody{
			Code:      params.Code,
			CsrfToken: params.CsrfToken,
		},
	})
	if err != nil {
		slog.DebugContext(ctx, "update verification error", "err", err.Error())
		verificationCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	if params.Render != "" {
		fmt.Println(params.Render)
		v := viewFromQueryParam(params.Render)
		setHeadersForReplaceBody(w, v.Path)
		viewFromQueryParam(params.Render).render(w, r, session)
		return
	}

	// Transferring cookies from update registration flow response
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)
	kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, updateVerificationFlowResp.Header.Cookie)
	// create login flow
	createLoginFlowResp, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
		Header:  kratosRequestHeader,
		Refresh: true,
	})
	if err != nil {
		slog.DebugContext(ctx, "update verification error", "err", err.Error())
		verificationCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	addCookies(w, createLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
	loginIndexView.addParams(map[string]any{
		"LoginFlowID": createLoginFlowResp.LoginFlow.FlowID,
		"Information": "コードによる検証が完了しました。お手数ですが改めてログインしてください。",
		"CsrfToken":   createLoginFlowResp.LoginFlow.CsrfToken,
	}).render(w, r, session)
}
