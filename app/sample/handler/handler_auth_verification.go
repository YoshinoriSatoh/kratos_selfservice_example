package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
)

// --------------------------------------------------------------------------
// GET /auth/verification
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthVerification
type getAuthVerificationRequestParams struct {
	FlowID   string `form:"flow" validate:"omitempty,uuid4"`
	ReturnTo string `form:"return_to" validate:"omitempty"`
}

// Handler GET /auth/verification
func (p *Provider) handleGetAuthVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	indexView := newView(TPL_AUTH_VERIFICATION_INDEX)

	// bind and validate request parameters
	var reqParams getAuthVerificationRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handleGetAuthVerification bind request error", "err", err)
		indexView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	indexView.addParams(requestParamsToMap(reqParams))

	// create or get verification Flow
	response, kratosResponseHeader, _, err := kratos.CreateOrGetVerificationFlow(ctx, kratos.CreateOrGetVerificationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		slog.ErrorContext(ctx, "create verification flow error", "err", err)
		indexView.setKratosMsg(err).render(w, r, session)
		return
	}

	// render page
	addCookies(w, kratosResponseHeader.Cookie)
	indexView.addParams(map[string]any{
		"VerificationFlowID": response.VerificationFlow.FlowID,
		"CsrfToken":          response.VerificationFlow.CsrfToken,
		"IsUsedFlow":         response.VerificationFlow.IsUsedFlow,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/verificatoin/email
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthVerificationEmail
type postAuthVerificationEmailRequestParams struct {
	FlowID    string `form:"flow" validate:"uuid4"`
	CsrfToken string `json:"csrf_token" validate:"required"`
	Email     string `json:"email" validate:"required,email" ja:"メールアドレス"`
}

// Handler POST /auth/verification/email
func (p *Provider) handlePostAuthVerificationEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	verificationEmailView := newView(TPL_AUTH_VERIFICATION_FORM)

	// bind and validate request parameters
	var reqParams postAuthVerificationEmailRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthVerificationEmail bind request error", "err", err)
		verificationEmailView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	verificationEmailView.addParams(requestParamsToMap(reqParams))

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
		verificationEmailView.setKratosMsg(err).render(w, r, session)
		return
	}

	addCookies(w, verificationFlowResp.Header.Cookie)
	redirect(w, r, fmt.Sprintf("/auth/registration/credential?flow=%s", reqParams.FlowID), []string{})
}

// --------------------------------------------------------------------------
// GET /auth/verification/code
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthVerificationCode
type getAuthVerificationCodeRequestParams struct {
	FlowID   string `form:"flow" validate:"omitempty,uuid4"`
	ReturnTo string `form:"return_to" validate:"omitempty"`
}

// Handler GET /auth/verification/code
func (p *Provider) handleGetAuthVerificationCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	verificationCodeView := newView(TPL_AUTH_VERIFICATION_CODE_FORM)

	// bind and validate request parameters
	var reqParams getAuthVerificationCodeRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handleGetAuthVerificationCode bind request error", "err", err)
		verificationCodeView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	verificationCodeView.addParams(requestParamsToMap(reqParams))

	// create or get verification Flow
	response, kratosResponseHeader, _, err := kratos.CreateOrGetVerificationFlow(ctx, kratos.CreateOrGetVerificationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		slog.ErrorContext(ctx, "create verification flow error", "err", err)
		verificationCodeView.setKratosMsg(err).render(w, r, session)
		return
	}

	// render page
	addCookies(w, kratosResponseHeader.Cookie)
	verificationCodeView.addParams(map[string]any{
		"VerificationFlowID": response.VerificationFlow.FlowID,
		"CsrfToken":          response.VerificationFlow.CsrfToken,
		"IsUsedFlow":         response.VerificationFlow.IsUsedFlow,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/verificatoin/code
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthVerificationCode
type postAuthVerificationCodeRequestParams struct {
	FlowID    string `form:"flow" validate:"uuid4"`
	CsrfToken string `json:"csrf_token" validate:"required"`
	Code      string `json:"code" validate:"required,len=6,number" ja:"検証コード"`
	Render    string `form:"render" validate:"omitempty"`
}

// Handler POST /auth/verification/code
func (p *Provider) handlePostAuthVerificationCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	verificationCodeView := newView(TPL_AUTH_VERIFICATION_CODE_FORM)

	// bind and validate request parameters
	var reqParams postAuthVerificationCodeRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthVerificationCode bind request error", "err", err)
		verificationCodeView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	verificationCodeView.addParams(requestParamsToMap(reqParams))

	// update verification flow
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
		verificationCodeView.setKratosMsg(err).render(w, r, session)
		return
	}

	if reqParams.Render != "" {
		v := viewFromQueryParam(reqParams.Render)
		redirect(w, r, v.Path, []string{})
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
		verificationCodeView.setKratosMsg(err).render(w, r, session)
		return
	}

	addCookies(w, loginFlowResp.Header.Cookie)
	redirectUrlForPush := fmt.Sprintf("/auth/login?flow=%s", reqParams.FlowID)
	redirect(w, r, fmt.Sprintf("%s?information=%s", redirectUrlForPush, "コードによる検証が完了しました。お手数ですが改めてログインしてください。"), []string{"information"})
}
