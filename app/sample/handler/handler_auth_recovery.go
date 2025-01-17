package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

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

// Views
type getAuthRecoveryViews struct {
	index *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthRecovery(w http.ResponseWriter, r *http.Request) (*getAuthRecoveryRequestParams, getAuthRecoveryViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_RECOVERY_DEFAULT",
	}))
	reqParams := newGetAuthRecoveryRequestParams(r)
	views := getAuthRecoveryViews{
		index: newView("auth/recovery/index.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.index.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handleGetAuthRecovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthRecovery(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthRecovery failed", "err", err)
		return
	}

	// create or get recovery Flow
	recoveryFlow, kratosResponseHeader, _, err := kratos.CreateOrGetRecoveryFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		views.index.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// add cookies to the request header
	addCookies(w, kratosResponseHeader.Cookie)

	// render page
	views.index.addParams(map[string]any{
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

// Views
type getAuthRecoveryCodeViews struct {
	recoveryCodeForm *view
	myPassword       *view
	loginCode        *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthRecoveryCode(w http.ResponseWriter, r *http.Request) (*postAuthRecoveryCodeRequestParams, getAuthRecoveryCodeViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_RECOVERY_DEFAULT",
	}))
	reqParams := newPostAutRecoveryCodeRequestParams(r)
	views := getAuthRecoveryCodeViews{
		recoveryCodeForm: newView("auth/recovery/_code_form.html").addParams(reqParams.toViewParams()),
		myPassword:       newView("my/password.html").addParams(reqParams.toViewParams()),
		loginCode:        newView("auth/login/code.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.recoveryCodeForm.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthRecoveryCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthRecoveryCode(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthRecoveryCode failed", "err", err)
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
		views.recoveryCodeForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, kratosResp.Header.Cookie)
	if kratosResp.RedirectBrowserTo != "" {
		arr := strings.Split(kratosResp.RedirectBrowserTo, "=")
		settingsFlowID := arr[1]
		kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, kratosResp.Header.Cookie)

		getSettingsFlowResp, _, err := kratos.GetSettingsFlow(ctx, kratos.GetSettingsFlowRequest{
			FlowID: settingsFlowID,
			Header: kratosRequestHeader,
		})
		if err != nil {
			slog.ErrorContext(ctx, "handlePostAuthRecoveryCode", "err", err)
			var errGeneric kratos.ErrorGeneric
			if errors.As(err, &errGeneric) && err.(kratos.ErrorGeneric).Err.ID == "session_aal2_required" {
				afterLoggedInParams := &showSettingsAfterLoggedInParams{
					FlowID:    reqParams.FlowID,
					CsrfToken: getSettingsFlowResp.SettingsFlow.CsrfToken,
					Method:    "password",
				}
				// create and update login flow for aal2, send authentication code
				createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosRequestHeader,
					Aal:     kratos.Aal2,
					Refresh: true,
				})
				if err != nil {
					slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
					views.recoveryCodeForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// update login flow for aal2, send authentication code
				_, _, err = kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
					FlowID: createLoginFlowResp.LoginFlow.FlowID,
					Header: kratosRequestHeader,
					Aal:    kratos.Aal2,
					Body: kratos.UpdateLoginFlowRequestBody{
						Method:     "code",
						CsrfToken:  createLoginFlowResp.LoginFlow.CsrfToken,
						Identifier: createLoginFlowResp.LoginFlow.CodeAddress,
					},
				})
				if err != nil {
					slog.ErrorContext(ctx, "update login flow for aal2 error", "err", err)
					views.recoveryCodeForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}
				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login/code?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				views.loginCode.addParams(map[string]any{
					"LoginFlowID":               createLoginFlowResp.LoginFlow.FlowID,
					"Information":               "パスワード更新のために再度ログインをお願いします。",
					"CsrfToken":                 createLoginFlowResp.LoginFlow.CsrfToken,
					"Identifier":                createLoginFlowResp.LoginFlow.CodeAddress,
					"ShowSettingsAfterLoggedIn": afterLoggedInParams.toString(),
				}).render(w, r, session)
				return
			}
			views.recoveryCodeForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}
		addCookies(w, getSettingsFlowResp.Header.Cookie)
		setHeadersForReplaceBody(w, fmt.Sprintf("/my/password?flow=%s", settingsFlowID))
		views.myPassword.addParams(map[string]any{
			"SettingsFlowID": settingsFlowID,
			"CsrfToken":      getSettingsFlowResp.SettingsFlow.CsrfToken,
		}).render(w, r, session)
	}
}
