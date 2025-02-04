package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
)

// --------------------------------------------------------------------------
// GET /auth/recovery
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthRecovery
type getAuthRecoveryRequestParams struct {
	FlowID   string `form:"flow" validate:"omitempty,uuid4"`
	ReturnTo string `form:"return_to" validate:"omitempty"`
}

func (p *Provider) handleGetAuthRecovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	recoveryView := newView(TPL_AUTH_RECOVERY_INDEX)

	// bind and validate request parameters
	var reqParams getAuthRecoveryRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handleGetAuthRecovery bind request error", "err", err)
		recoveryView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	recoveryView.addParams(requestParamsToMap(reqParams))

	var (
		kratosRespHeader kratos.KratosResponseHeader
		err              error
	)
	if reqParams.FlowID == "" {
		var createRecoveryFlowResp kratos.CreateRecoveryFlowResponse
		createRecoveryFlowResp, _, err = kratos.CreateRecoveryFlow(ctx, kratos.CreateRecoveryFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		if err != nil {
			slog.ErrorContext(ctx, "create recovery flow error", "err", err)
			recoveryView.setKratosMsg(err).render(w, r, session)
			return
		}
		kratosRespHeader = createRecoveryFlowResp.Header
		recoveryView.addParams(map[string]any{
			"RecoveryFlowID": createRecoveryFlowResp.RecoveryFlow.FlowID,
			"CsrfToken":      createRecoveryFlowResp.RecoveryFlow.CsrfToken,
		})
	} else {
		var getRecoveryFlowResp kratos.GetRecoveryFlowResponse
		getRecoveryFlowResp, _, err = kratos.GetRecoveryFlow(ctx, kratos.GetRecoveryFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
			FlowID: reqParams.FlowID,
		})
		if err != nil {
			slog.ErrorContext(ctx, "get recovery flow error", "err", err)
			recoveryView.setKratosMsg(err).render(w, r, session)
			return
		}
		kratosRespHeader = getRecoveryFlowResp.Header
		recoveryView.addParams(map[string]any{
			"RecoveryFlowID": getRecoveryFlowResp.RecoveryFlow.FlowID,
			"CsrfToken":      getRecoveryFlowResp.RecoveryFlow.CsrfToken,
		})
	}

	// add cookies to the request header
	addCookies(w, kratosRespHeader.Cookie)

	// render page
	recoveryView.render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /auth/recovery/email
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRecoveryEmail
type postAuthRecoveryEmailRequestParams struct {
	FlowID    string `form:"flow" validate:"uuid4"`
	CsrfToken string `json:"csrf_token" validate:"required"`
	Email     string `json:"email" validate:"required,email" ja:"メールアドレス"`
}

func (p *Provider) handlePostAuthRecoveryEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	emailFormView := newView(TPL_AUTH_RECOVERY_FORM)

	// bind and validate request parameters
	var reqParams postAuthRecoveryEmailRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthRecoveryEmail bind request error", "err", err)
		emailFormView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	emailFormView.addParams(requestParamsToMap(reqParams))

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
		slog.ErrorContext(ctx, "update recovery flow error", "err", err)
		emailFormView.setKratosMsg(err).render(w, r, session)
		return
	}

	addCookies(w, kratosResp.Header.Cookie)
	redirect(w, r, fmt.Sprintf("/auth/recovery?flow=%s", reqParams.FlowID), []string{})
}

// --------------------------------------------------------------------------
// POST /auth/recovery/code
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRecoveryCode
type postAuthRecoveryCodeRequestParams struct {
	FlowID    string `form:"flow" validate:"uuid4"`
	CsrfToken string `json:"csrf_token" validate:"required"`
	Code      string `json:"code" validate:"required,len=6,number" ja:"復旧コード"`
}

func (p *Provider) handlePostAuthRecoveryCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// views
	recoveryCodeFormView := newView(TPL_AUTH_RECOVERY_CODE_FORM)

	// bind and validate request parameters
	var reqParams postAuthRecoveryCodeRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostAuthRecoveryCode bind request error", "err", err)
		recoveryCodeFormView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// add request params to views
	recoveryCodeFormView.addParams(requestParamsToMap(reqParams))

	// Recovery Flow 更新
	kratosResp, _, err := kratos.UpdateRecoveryFlow(ctx, kratos.UpdateRecoveryFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRecoveryFlowRequestBody{
			CsrfToken: reqParams.CsrfToken,
			Method:    "code",
			Code:      reqParams.Code,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update recovery flow error", "err", err)
		recoveryCodeFormView.setKratosMsg(err).render(w, r, session)
		return
	}

	if kratosResp.LoginFlow != nil {
		addCookies(w, kratosResp.LoginFlowCookie)
		redirectUrl := fmt.Sprintf("/auth/login/code?flow=%s&information=%s", kratosResp.LoginFlow.FlowID, "パスワード更新のために再度ログインをお願いします。")
		redirect(w, r, redirectUrl, []string{})
	} else {
		addCookies(w, kratosResp.Header.Cookie)
		redirect(w, r, fmt.Sprintf("/my/password?flow=%s", kratosResp.SettingsFlow.FlowID), []string{})
	}
}
