package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /auth/registration/credenail/oidc
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationCredentialOidc
type postAuthRegistrationCredentialOidcRequestParams struct {
	FlowID    string        `validate:"required,uuid4"`
	CsrfToken string        `validate:"required"`
	Provider  string        `validate:"required"`
	Traits    kratos.Traits `validate:"required"`
}

// Extract parameters from http request
func newpostAuthRegistrationCredentialOidcRequestParams(r *http.Request) *postAuthRegistrationCredentialOidcRequestParams {
	return &postAuthRegistrationCredentialOidcRequestParams{
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
func (p *postAuthRegistrationCredentialOidcRequestParams) toViewParams() map[string]any {
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
func (params *postAuthRegistrationCredentialOidcRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getAuthRegistrationCredentialOidcViews struct {
	form *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthRegistrationCredentialOidc(w http.ResponseWriter, r *http.Request) (*postAuthRegistrationCredentialOidcRequestParams, getAuthRegistrationCredentialOidcViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))
	reqParams := newpostAuthRegistrationCredentialOidcRequestParams(r)
	views := getAuthRegistrationCredentialOidcViews{
		form: newView("auth/registration/_form_profile.html").addParams(reqParams.toViewParams()).addParams(map[string]any{"Method": "oidc"}),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.form.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthRegistrationCredentialOidc(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthRegistrationCredentialOidc(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthRegistrationCredentialOidc failed", "err", err)
		return
	}

	// update Registration Flow
	kratosResp, _, err := kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRegistrationFlowRequestBody{
			CsrfToken: reqParams.CsrfToken,
			Method:    "oidc",
			Provider:  reqParams.Provider,
			Traits:    reqParams.Traits,
		},
	})
	if err != nil {
		views.form.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, kratosResp.Header.Cookie)
	if kratosResp.RedirectBrowserTo != "" {
		redirect(w, r, kratosResp.RedirectBrowserTo)
	}
}
