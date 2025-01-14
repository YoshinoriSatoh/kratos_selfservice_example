package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /my/totp
// --------------------------------------------------------------------------
type postMyTotpRequestPostForm struct {
	FlowID     string `validate:"required,uuid4"`
	CsrfToken  string `validate:"required"`
	TotpCode   string `validate:"omitempty" ja:"認証コード"`
	TotpUnlink string `validate:"omitempty"`
}

// Extract parameters from http request
func newMyTotpRequestParams(r *http.Request) *postMyTotpRequestPostForm {
	return &postMyTotpRequestPostForm{
		FlowID:     r.URL.Query().Get("flow"),
		CsrfToken:  r.PostFormValue("csrf_token"),
		TotpCode:   r.PostFormValue("totp_code"),
		TotpUnlink: r.PostFormValue("totp_unlink"),
	}
}

// Return parameters that can refer in view template
func (p *postMyTotpRequestPostForm) toViewParams() map[string]any {
	return map[string]any{
		"SettingsTotpID": p.FlowID,
		"CsrfToken":      p.CsrfToken,
		"TotpCode":       p.TotpCode,
		"TotpUnlink":     p.TotpUnlink,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postMyTotpRequestPostForm) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))
	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getMyTotpPostViews struct {
	totpForm   *view
	loginIndex *view
	loginCode  *view
}

// collect rendering data and validate request parameters.
func prepareGetMyTotpPost(w http.ResponseWriter, r *http.Request) (*postMyTotpRequestPostForm, getMyTotpPostViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
	}))
	reqParams := newMyTotpRequestParams(r)
	views := getMyTotpPostViews{
		totpForm:   newView("my/profile/_totp_form.html").addParams(reqParams.toViewParams()),
		loginIndex: newView("auth/login/index.html").addParams(reqParams.toViewParams()),
		loginCode:  newView("auth/login/code.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.totpForm.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

// Handler POST /my/totp
func (p *Provider) handlePostMyTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetMyTotpPost(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetMyTotpPost failed", "err", err)
		return
	}

	// update settings flow
	_, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: reqParams.FlowID,
		Header: kratosRequestHeader,
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken:  reqParams.CsrfToken,
			Method:     "totp",
			TotpCode:   reqParams.TotpCode,
			TotpUnlink: reqParams.TotpUnlink,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "handlePostMyTotp", "err", err)
		// render login form when session expired privileged_session_max_age, and re-render totp form.
		// redirect not use. htmx implementation policy.
		var errGeneric kratos.ErrorGeneric
		if errors.As(err, &errGeneric) && err.(kratos.ErrorGeneric).Err.ID == "session_refresh_required" {
			afterLoggedInParams := &updateSettingsAfterLoggedInParams{
				FlowID:   reqParams.FlowID,
				Method:   "totp",
				TotpCode: reqParams.TotpCode,
			}

			if kratos.SessionRequiredAal == kratos.Aal1 {
				// create login flow
				createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosReqHeaderForNext,
					Aal:     kratos.Aal1,
					Refresh: true,
				})
				if err != nil {
					views.totpForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// render login form
				addCookies(w, kratosRequestHeader.Cookie)
				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				views.loginIndex.addParams(map[string]any{
					"LoginFlowID":                 createLoginFlowResp.LoginFlow.FlowID,
					"Information":                 "認証アプリ設定のために再度ログインをお願いします。",
					"CsrfToken":                   createLoginFlowResp.LoginFlow.CsrfToken,
					"UpdateSettingsAfterLoggedIn": afterLoggedInParams.toString(),
				}).render(w, r, session)

			} else if kratos.SessionRequiredAal == kratos.Aal2 {
				// create and update login flow for aal2, send authentication code
				createLoginFlowResp, kratosReqHeaderForNext, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosRequestHeader,
					Aal:     kratos.Aal2,
					Refresh: true,
				})
				if err != nil {
					slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
					views.totpForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				_, _, err = kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
					FlowID: createLoginFlowResp.LoginFlow.FlowID,
					Header: kratosReqHeaderForNext,
					Aal:    kratos.Aal2,
					Body: kratos.UpdateLoginFlowRequestBody{
						Method:     "code",
						CsrfToken:  createLoginFlowResp.LoginFlow.CsrfToken,
						Identifier: createLoginFlowResp.LoginFlow.CodeAddress,
					},
				})
				if err != nil {
					slog.ErrorContext(ctx, "update login flow for aal2 error", "err", err)
					views.totpForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// addCookies(w, kratosRequestHeader.Cookie)
				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login/code?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				views.loginCode.addParams(map[string]any{
					"LoginFlowID":                 createLoginFlowResp.LoginFlow.FlowID,
					"Information":                 "認証アプリ更新のために再度ログインをお願いします。",
					"CsrfToken":                   createLoginFlowResp.LoginFlow.CsrfToken,
					"Identifier":                  createLoginFlowResp.LoginFlow.CodeAddress,
					"UpdateSettingsAfterLoggedIn": afterLoggedInParams.toString(),
				}).render(w, r, session)
			}
			return
		}

		// render form with error
		views.totpForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
		Header: kratosReqHeaderForNext,
	})
	session = whoamiResp.Session

	// create or get settings Flow
	createSettingsTotpResp, kratosReqHeader, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		views.totpForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	slog.DebugContext(ctx, "handlePostMyTotp", "createSettingsTotpResp", createSettingsTotpResp)

	// render top page
	addCookies(w, kratosReqHeader.Cookie)
	views.totpForm.addParams(map[string]any{
		"SettingsFlowID": createSettingsTotpResp.SettingsFlow.FlowID,
		"CsrfToken":      createSettingsTotpResp.SettingsFlow.CsrfToken,
		"TotpQR":         "src=" + createSettingsTotpResp.SettingsFlow.TotpQR,
		"TotpRegisted":   createSettingsTotpResp.SettingsFlow.TotpUnlink,
	}).render(w, r, session)
}
