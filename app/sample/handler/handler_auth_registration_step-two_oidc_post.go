package handler

import (
	"fmt"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /auth/registration/step-two/oidc
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationStepTwoOidc
type postAuthRegistrationStepTwoOidcRequestParams struct {
	FlowID    string        `validate:"required,uuid4"`
	CsrfToken string        `validate:"required"`
	Provider  string        `validate:"required"`
	Traits    kratos.Traits `validate:"required"`
}

// Extract parameters from http request
func newpostAuthRegistrationStepTwoOidcRequestParams(r *http.Request) *postAuthRegistrationStepTwoOidcRequestParams {
	return &postAuthRegistrationStepTwoOidcRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Provider:  r.PostFormValue("provider"),
		Traits: kratos.Traits{
			Email:     r.PostFormValue("traits.email"),
			Firstname: r.PostFormValue("traits.firstname"),
			Lastname:  r.PostFormValue("traits.lastname"),
			Nickname:  r.PostFormValue("traits.nickname"),
			Birthdate: fmt.Sprintf("%s-%s-%s", r.PostFormValue("birthdate_year"), r.PostFormValue("birthdate_month"), r.PostFormValue("birthdate_day")),
		},
	}
}

// Return parameters that can refer in view template
func (p *postAuthRegistrationStepTwoOidcRequestParams) toViewParams() map[string]any {
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
func (params *postAuthRegistrationStepTwoOidcRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostAuthRegistrationStepTwoOidc(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newpostAuthRegistrationStepTwoOidcRequestParams(r)

	// prepare views
	registrationFormOidc := newView("auth/registration/_form.html").addParams(params.toViewParams()).addParams(map[string]any{"Method": "oidc"})

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		registrationFormOidc.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))

	// update Registration Flow
	kratosResp, err := kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRegistrationFlowRequestBody{
			CsrfToken: params.CsrfToken,
			Method:    "oidc",
			Provider:  params.Provider,
			Traits:    params.Traits,
		},
	})
	if err != nil {
		registrationFormOidc.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, kratosResp.Header.Cookie)
	if kratosResp.RedirectBrowserTo != "" {
		redirect(w, r, kratosResp.RedirectBrowserTo)
	}
}
