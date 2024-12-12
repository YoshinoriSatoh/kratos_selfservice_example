package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /auth/registration/step-two/passkey
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationStepTwoPasskey
type postAuthRegistrationStepTwoPasskeyRequestParams struct {
	FlowID          string        `validate:"required,uuid4"`
	CsrfToken       string        `validate:"required"`
	Traits          kratos.Traits `validate:"required"`
	PasskeyRegister string
}

// Extract parameters from http request
func newpostAuthRegistrationStepTwoPasskeyRequestParams(r *http.Request) *postAuthRegistrationStepTwoPasskeyRequestParams {
	return &postAuthRegistrationStepTwoPasskeyRequestParams{
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
func (p *postAuthRegistrationStepTwoPasskeyRequestParams) toViewParams() map[string]any {
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
func (params *postAuthRegistrationStepTwoPasskeyRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostAuthRegistrationStepTwoPasskey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newpostAuthRegistrationStepTwoPasskeyRequestParams(r)

	// prepare views
	registrationFormPasskeyView := newView("auth/registration/_form.html").addParams(params.toViewParams()).addParams(map[string]any{"Method": "passkey"})
	loginIndexView := newView("auth/login/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		registrationFormPasskeyView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// Registration Flow 更新
	kratosResp, err := kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRegistrationFlowRequestBody{
			CsrfToken:       params.CsrfToken,
			Method:          "passkey",
			Traits:          params.Traits,
			PasskeyRegister: params.PasskeyRegister,
		},
	})
	if err != nil && kratosResp.DuplicateIdentifier == "" {
		registrationFormPasskeyView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
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

	// Transferring cookies from update registration flow response
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)
	kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, kratosResp.Header.Cookie)
	// create login flow
	createLoginFlowResp, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
		Header: kratosRequestHeader,
	})
	if err != nil {
		slog.DebugContext(ctx, "update verification error", "err", err.Error())
		registrationFormPasskeyView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	addCookies(w, kratosResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
	loginIndexView.addParams(map[string]any{
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
