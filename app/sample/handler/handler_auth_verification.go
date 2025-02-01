package handler

import (
	"fmt"
	"log/slog"
	"net/http"

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

// Handler GET /auth/verification
func (p *Provider) handleGetAuthVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &getAuthVerificationRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	indexView := newView(TPL_AUTH_VERIFICATION_INDEX).addParams(map[string]any{
		"VerificationFlowID": reqParams.FlowID,
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	for k := range viewError.validationFieldErrors {
		if k == "FlowID" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
		}
	}
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handleGetAuthVerification validation error", "messages", viewError.messages)
		indexView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// create or get verification Flow
	verificationFlow, kratosResponseHeader, _, err := kratos.CreateOrGetVerificationFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		indexView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	addCookies(w, kratosResponseHeader.Cookie)
	indexView.addParams(map[string]any{
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

// Handler GET /auth/verification/code
func (p *Provider) handleGetAuthVerificationCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &getAuthVerificationCodeRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	verificationCodeView := newView(TPL_AUTH_VERIFICATION_CODE_FORM).addParams(map[string]any{
		"VerificationFlowID": reqParams.FlowID,
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	for k := range viewError.validationFieldErrors {
		if k == "FlowID" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
		}
	}
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handleGetAuthVerificationCode validation error", "messages", viewError.messages)
		verificationCodeView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// create or get verification Flow
	verificationFlow, kratosResponseHeader, _, err := kratos.CreateOrGetVerificationFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		verificationCodeView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	addCookies(w, kratosResponseHeader.Cookie)
	verificationCodeView.addParams(map[string]any{
		"VerificationFlowID": verificationFlow.FlowID,
		"CsrfToken":          verificationFlow.CsrfToken,
		"IsUsedFlow":         verificationFlow.IsUsedFlow,
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

// Handler POST /auth/verification/code
func (p *Provider) handlePostAuthVerificationCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &postAuthVerificationCodeRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		Render:    r.PostFormValue("render"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Code:      r.PostFormValue("code"),
	}

	// prepare views
	verificationCodeView := newView(TPL_AUTH_VERIFICATION_CODE_FORM).addParams(map[string]any{
		"VerificationFlowID": reqParams.FlowID,
		"Render":             reqParams.Render,
		"CsrfToken":          reqParams.CsrfToken,
		"Code":               reqParams.Code,
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
		slog.ErrorContext(ctx, "handlePostAuthVerificationCode validation error", "messages", viewError.messages)
		verificationCodeView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// Verification Flow 更新
	_, kratosReqHeaderForNext, err := kratos.UpdateVerificationFlow(ctx, kratos.UpdateVerificationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateVerificationFlowRequestBody{
			Code:      reqParams.Code,
			CsrfToken: reqParams.CsrfToken,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update verification error", "err", err)
		verificationCodeView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	if reqParams.Render != "" {
		fmt.Println(reqParams.Render)
		v := viewFromQueryParam(reqParams.Render)
		setHeadersForReplaceBody(w, v.Path)
		viewFromQueryParam(reqParams.Render).render(w, r, session)
		return
	}

	// create login flow after verification
	loginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
		Header:  kratosReqHeaderForNext,
		Refresh: true,
		Aal:     kratos.Aal1,
	})
	if err != nil {
		slog.ErrorContext(ctx, "create login flow error", "err", err)
		verificationCodeView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render login page
	addCookies(w, loginFlowResp.Header.Cookie)
	newView(TPL_AUTH_LOGIN_INDEX).addParams(map[string]any{
		"LoginFlowID": loginFlowResp.LoginFlow.FlowID,
		"Information": pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "コードによる検証が完了しました。お手数ですが改めてログインしてください。",
		}),
		"CsrfToken": loginFlowResp.LoginFlow.CsrfToken,
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

// Handler POST /auth/verification/email
func (p *Provider) handlePostAuthVerificationEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &postAuthVerificationEmailRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Email:     r.PostFormValue("email"),
	}

	// prepare views
	verificationEmailView := newView(TPL_AUTH_VERIFICATION_FORM).addParams(map[string]any{
		"VerificationFlowID": reqParams.FlowID,
		"CsrfToken":          reqParams.CsrfToken,
		"Email":              reqParams.Email,
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
		slog.ErrorContext(ctx, "handlePostAuthVerificationEmail validation error", "messages", viewError.messages)
		verificationEmailView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// update verification flow
	verificationFlowResp, _, err := kratos.UpdateVerificationFlow(ctx, kratos.UpdateVerificationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateVerificationFlowRequestBody{
			Email:     reqParams.Email,
			CsrfToken: reqParams.CsrfToken,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update verification error", "err", err)
		verificationEmailView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	addCookies(w, verificationFlowResp.Header.Cookie)
	verificationEmailView.addParams(map[string]any{
		"VerificationFlowID": verificationFlowResp.Flow.FlowID,
		"CsrfToken":          verificationFlowResp.Flow.CsrfToken,
		"IsUsedFlow":         verificationFlowResp.Flow.IsUsedFlow,
	}).render(w, r, session)
}
