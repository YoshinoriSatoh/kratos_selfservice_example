package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /auth/recovery
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthRecovery
type getAuthRecoveryRequestParams struct {
	FlowID string
}

func (p *Provider) handleGetAuthRecovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &getAuthRecoveryRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	recoveryView := newView(TPL_AUTH_RECOVERY_INDEX).addParams(map[string]any{
		"RecoveryFlowID": reqParams.FlowID,
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
		slog.ErrorContext(ctx, "handleGetAuthRecovery validation error", "messages", viewError.messages)
		recoveryView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// create or get recovery Flow
	recoveryFlow, kratosResponseHeader, _, err := kratos.CreateOrGetRecoveryFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		recoveryView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	// add cookies to the request header
	addCookies(w, kratosResponseHeader.Cookie)

	// render page
	recoveryView.addParams(map[string]any{
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

func (p *Provider) handlePostAuthRecoveryEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &postAuthRecoveryEmailRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Email:     r.PostFormValue("email"),
	}

	// prepare views
	emailFormView := newView(TPL_AUTH_RECOVERY_FORM).addParams(map[string]any{
		"RecoveryFlowID": reqParams.FlowID,
		"CsrfToken":      reqParams.CsrfToken,
		"Email":          reqParams.Email,
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handlePostAuthRecoveryEmail validation error", "messages", viewError.messages)
		emailFormView.addParams(viewError.toViewParams()).render(w, r, session)
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
		emailFormView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}
	addCookies(w, kratosResp.Header.Cookie)

	// リダイレクトしない形に修正
	// if kratosResp.RedirectBrowserTo != "" {
	// 	redirect(w, r, kratosResp.RedirectBrowserTo)
	// 	w.WriteHeader(http.StatusOK)
	// }

	// render
	newView(TPL_AUTH_RECOVERY_CODE_FORM).addParams(map[string]any{
		"RecoveryFlowID":           reqParams.FlowID,
		"CsrfToken":                reqParams.CsrfToken,
		"Email":                    reqParams.Email,
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

func (p *Provider) handlePostAuthRecoveryCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &postAuthRecoveryCodeRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Code:      r.PostFormValue("code"),
	}

	// prepare views
	recoveryCodeFormView := newView(TPL_AUTH_RECOVERY_CODE_FORM).addParams(map[string]any{
		"RecoveryFlowID": reqParams.FlowID,
		"CsrfToken":      reqParams.CsrfToken,
		"Code":           reqParams.Code,
	})

	// validate request parameters
	viewError := newViewError().extract(pkgVars.validate.Struct(reqParams))
	if viewError.hasError() {
		slog.ErrorContext(ctx, "handlePostAuthRecoveryCode validation error", "messages", viewError.messages)
		recoveryCodeFormView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// Recovery Flow 更新
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)
	kratosResp, _, err := kratos.UpdateRecoveryFlow(ctx, kratos.UpdateRecoveryFlowRequest{
		FlowID: reqParams.FlowID,
		Header: kratosRequestHeader,
		Body: kratos.UpdateRecoveryFlowRequestBody{
			CsrfToken: reqParams.CsrfToken,
			Method:    "code",
			Code:      reqParams.Code,
		},
	})
	if err != nil {
		recoveryCodeFormView.addParams(newViewError().extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, kratosResp.Header.Cookie)

	if kratosResp.LoginFlow != nil {
		addCookies(w, kratosResp.LoginFlowCookie)
		setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login/code?flow=%s", kratosResp.LoginFlow.FlowID))
		newView(TPL_AUTH_LOGIN_CODE).addParams(map[string]any{
			"LoginFlowID":    kratosResp.LoginFlow.FlowID,
			"Information":    "パスワード更新のために再度ログインをお願いします。",
			"CsrfToken":      kratosResp.LoginFlow.CsrfToken,
			"Identifier":     kratosResp.LoginFlow.CodeAddress,
			"SettingsFlowID": kratosResp.SettingsFlow.FlowID,
		}).render(w, r, session)
		return
	}

	addCookies(w, kratosResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/my/password?flow=%s", kratosResp.SettingsFlow.FlowID))
	newView(TPL_MY_PASSWORD).addParams(map[string]any{
		"SettingsFlowID": kratosResp.SettingsFlow.FlowID,
		"CsrfToken":      kratosResp.SettingsFlow.CsrfToken,
	}).render(w, r, session)
}
