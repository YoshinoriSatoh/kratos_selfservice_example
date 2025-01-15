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
// POST /my/password
// --------------------------------------------------------------------------
type postMyPasswordRequestParams struct {
	FlowID               string `validate:"uuid4"`
	CsrfToken            string `validate:"required"`
	Password             string `validate:"required" ja:"パスワード"`
	PasswordConfirmation string `validate:"required" ja:"パスワード確認"`
}

// Extract parameters from http request
func newMyPasswordRequestParams(r *http.Request) *postMyPasswordRequestParams {
	return &postMyPasswordRequestParams{
		FlowID:               r.URL.Query().Get("flow"),
		CsrfToken:            r.PostFormValue("csrf_token"),
		Password:             r.PostFormValue("password"),
		PasswordConfirmation: r.PostFormValue("password_confirmation"),
	}
}

// Return parameters that can refer in view template
func (p *postMyPasswordRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"SettingsFlowID":       p.FlowID,
		"CsrfToken":            p.CsrfToken,
		"Password":             p.Password,
		"PasswordConfirmation": p.PasswordConfirmation,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postMyPasswordRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))
	if params.Password != params.PasswordConfirmation {
		viewError.validationFieldErrors["Password"] = validationFieldError{
			Tag:     "Password",
			Message: "パスワードとパスワード確認が一致しません",
		}
	}
	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getMyPasswordPostViews struct {
	passwordForm *view
	loginIndex   *view
	loginCode    *view
}

// collect rendering data and validate request parameters.
func prepareGetMyPasswordPost(w http.ResponseWriter, r *http.Request) (*postMyPasswordRequestParams, getMyPasswordPostViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
	}))
	reqParams := newMyPasswordRequestParams(r)
	views := getMyPasswordPostViews{
		passwordForm: newView("my/_password_form.html").addParams(reqParams.toViewParams()),
		loginIndex:   newView("auth/login/index.html").addParams(reqParams.toViewParams()),
		loginCode:    newView("auth/login/code.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.passwordForm.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostMyPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)
	slog.Debug("", "session", session)
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetMyPasswordPost(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetMyPasswordPost failed", "err", err)
		return
	}

	// prepare views
	topIndexView := newView("top/index.html").addParams(reqParams.toViewParams())

	kratosResp, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: reqParams.FlowID,
		Header: kratosRequestHeader,
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken: reqParams.CsrfToken,
			Method:    "password",
			Password:  reqParams.Password,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "handlePostMyPassword", "err", err)
		// render login form when session expired privileged_session_max_age, and re-render profile form.
		// redirect not use. htmx implementation policy.
		var errGeneric kratos.ErrorGeneric
		if errors.As(err, &errGeneric) && err.(kratos.ErrorGeneric).Err.ID == "session_refresh_required" {
			afterLoggedInParams := &updateSettingsAfterLoggedInParams{
				FlowID:    reqParams.FlowID,
				CsrfToken: reqParams.CsrfToken,
				Method:    "password",
				Password:  reqParams.Password,
			}

			if kratos.SessionRequiredAal == kratos.Aal1 {
				// create login flow
				createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosReqHeaderForNext,
					Aal:     kratos.Aal1,
					Refresh: true,
				})
				if err != nil {
					views.passwordForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// render login form
				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				views.loginIndex.addParams(map[string]any{
					"LoginFlowID":                 createLoginFlowResp.LoginFlow.FlowID,
					"Information":                 "パスワード更新のために再度ログインをお願いします。",
					"CsrfToken":                   createLoginFlowResp.LoginFlow.CsrfToken,
					"UpdateSettingsAfterLoggedIn": afterLoggedInParams.toString(),
				}).render(w, r, session)

			} else if kratos.SessionRequiredAal == kratos.Aal2 {
				// create and update login flow for aal2, send authentication code
				createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosRequestHeader,
					Aal:     kratos.Aal2,
					Refresh: true,
				})
				if err != nil {
					slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
					views.passwordForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
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
					views.passwordForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login/code?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				views.loginCode.addParams(map[string]any{
					"LoginFlowID":                 createLoginFlowResp.LoginFlow.FlowID,
					"Information":                 "パスワード更新のために再度ログインをお願いします。",
					"CsrfToken":                   createLoginFlowResp.LoginFlow.CsrfToken,
					"Identifier":                  createLoginFlowResp.LoginFlow.CodeAddress,
					"UpdateSettingsAfterLoggedIn": afterLoggedInParams.toString(),
				}).render(w, r, session)
			}
			return
		}

		// render form with error
		views.passwordForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, kratosResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	topIndexView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}
