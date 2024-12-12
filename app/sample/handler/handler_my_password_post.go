package handler

import (
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

func (p *Provider) handlePostMyPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)
	slog.Debug("", "session", session)
	// collect request parameters
	params := newMyPasswordRequestParams(r)

	// prepare views
	myPasswordFormView := newView("my/password/_form.html").addParams(params.toViewParams())
	topIndexView := newView("top/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		myPasswordFormView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
	}))

	kratosResp, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken: params.CsrfToken,
			Method:    "password",
			Password:  params.Password,
		},
	})
	if err != nil {
		myPasswordFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, kratosResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	topIndexView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}
