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
		"SettingsFlowID": p.FlowID,
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
	form       *view
	loginIndex *view
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
		form:       newView("my/profile/_form.html").addParams(reqParams.toViewParams()),
		loginIndex: newView("auth/login/index.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.form.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

// Handler POST /my/totp
func (p *Provider) handlePostMyTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetMyTotpPost(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetMyTotpPost failed", "err", err)
		return
	}

	// update settings flow
	kratosResp, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
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
			// create login flow
			createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
				Header:  kratosReqHeaderForNext,
				Refresh: true,
			})
			if err != nil {
				views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
				return
			}

			// for re-render totp form
			myProfileIndexView := newView("my/profile/index.html").addParams(map[string]any{
				"SettingsFlowID": reqParams.FlowID,
				"Information":    "ログインされました。TOTPを更新できます。",
				"CsrfToken":      reqParams.CsrfToken,
				"TotpCode":       reqParams.TotpCode,
			})

			hook := &hook{
				HookID: HookIDUpdateSettingsProfile,
				UpdateSettingsProfileParams: HookParamsUpdateSettingsProfile{
					FlowID:    reqParams.FlowID,
					CsrfToken: reqParams.CsrfToken,
				},
			}

			// render login form
			addCookies(w, createLoginFlowResp.Header.Cookie)
			setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
			views.loginIndex.addParams(map[string]any{
				"LoginFlowID": createLoginFlowResp.LoginFlow.FlowID,
				"Information": "TOTP更新のために再度ログインをお願いします。",
				"CsrfToken":   createLoginFlowResp.LoginFlow.CsrfToken,
				"Render":      myProfileIndexView.toQueryParam(),
				"Hook":        hook.toQueryParam(),
			}).render(w, r, session)
			return
		}

		// render form with error
		views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
		Header: kratosReqHeaderForNext,
	})
	session = whoamiResp.Session

	// render top page
	addCookies(w, kratosResp.Header.Cookie)
	views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
}
