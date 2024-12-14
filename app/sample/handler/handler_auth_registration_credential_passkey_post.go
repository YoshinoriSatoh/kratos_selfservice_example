package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /auth/registration/credenail/passkey
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationCredentialPasskey
type postAuthRegistrationCredentialPasskeyRequestParams struct {
	FlowID          string        `validate:"required,uuid4"`
	CsrfToken       string        `validate:"required"`
	Traits          kratos.Traits `validate:"required"`
	PasskeyRegister string
}

// Extract parameters from http request
func newpostAuthRegistrationCredentialPasskeyRequestParams(r *http.Request) *postAuthRegistrationCredentialPasskeyRequestParams {
	return &postAuthRegistrationCredentialPasskeyRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Traits: kratos.Traits{
			Email:     r.PostFormValue("traits.email"),
			Firstname: r.PostFormValue("traits.firstname"),
			Lastname:  r.PostFormValue("traits.lastname"),
			Nickname:  r.PostFormValue("traits.nickname"),
			Birthdate: fmt.Sprintf("%s-%s-%s", r.PostFormValue("birthdate_year"), r.PostFormValue("birthdate_month"), r.PostFormValue("birthdate_day")),
		},
		PasskeyRegister: r.PostFormValue("passkey_register"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthRegistrationCredentialPasskeyRequestParams) toViewParams() map[string]any {
	year, month, day := parseDate(p.Traits.Birthdate)
	return map[string]any{
		"RegistrationFlowID": p.FlowID,
		"CsrfToken":          p.CsrfToken,
		"Traits":             p.Traits,
		"BirthdateYear":      year,
		"BirthdateMonth":     month,
		"BirthdateDay":       day,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthRegistrationCredentialPasskeyRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getAuthRegistrationCredentialPasskeyViews struct {
	form *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthRegistrationCredentialPasskey(w http.ResponseWriter, r *http.Request) (*postAuthRegistrationCredentialPasskeyRequestParams, getAuthRegistrationCredentialPasskeyViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))
	reqParams := newpostAuthRegistrationCredentialPasskeyRequestParams(r)
	views := getAuthRegistrationCredentialPasskeyViews{
		form: newView("auth/registration/_form_credenail_passkey.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.form.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthRegistrationCredentialPasskey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthRegistrationCredentialPasskey(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthRegistrationCredentialPasskey failed", "err", err)
		return
	}

	// Registration Flow 更新
	kratosResp, kratosReqHeaderForNext, err := kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRegistrationFlowRequestBody{
			CsrfToken:       reqParams.CsrfToken,
			Method:          "passkey",
			Traits:          reqParams.Traits,
			PasskeyRegister: reqParams.PasskeyRegister,
		},
	})
	if err != nil && kratosResp.DuplicateIdentifier == "" {
		views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	if kratosResp.RedirectBrowserTo != "" {
		redirect(w, r, kratosResp.RedirectBrowserTo)
		w.WriteHeader(http.StatusOK)
	}

	// OIDC Loginの場合、同一クレデンシャルが存在する場合、既存Identityとのリンクを促す
	var (
		information     string
		traits          kratos.Traits
		showSocialLogin bool
	)
	if kratosResp.DuplicateIdentifier == "" {
		showSocialLogin = true
	} else {
		traits.Email = kratosResp.DuplicateIdentifier
		showSocialLogin = false
		information = "メールアドレスとパスワードで登録された既存のアカウントが存在します。パスワードを入力してログインすると、Googleのアカウントと連携されます。"
	}

	// create login flow
	createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
		Header: kratosReqHeaderForNext,
	})
	if err != nil {
		slog.ErrorContext(ctx, "update verification error", "err", err.Error())
		views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	addCookies(w, kratosResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
	newView("auth/login/index.html").addParams(reqParams.toViewParams()).addParams(map[string]any{
		"LoginFlowID":      createLoginFlowResp.LoginFlow.FlowID,
		"Information":      information,
		"CsrfToken":        createLoginFlowResp.LoginFlow.CsrfToken,
		"Traits":           traits,
		"ShowSocialLogin":  showSocialLogin,
		"ShowPasskeyLogin": true,
		"PasskeyChallenge": createLoginFlowResp.LoginFlow.PasskeyChallenge,
	}).render(w, r, session)

	// Registration flow成功時はVerification flowへリダイレクト
	// redirect(w, r, fmt.Sprintf("%s?flow=%s", "/auth/verification/code", output.VerificationFlowID))
}
