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
				// afterLoggedInParams := &showSettingsAfterLoggedInParams{
				// 	FlowID: reqParams.FlowID,
				// 	Method: "password",
				// }
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
