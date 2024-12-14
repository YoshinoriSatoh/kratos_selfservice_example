package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /auth/registration/profile
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationProfile
type postAuthRegistrationProfileRequestParams struct {
	FlowID    string        `validate:"required,uuid4"`
	CsrfToken string        `validate:"required"`
	Traits    kratos.Traits `validate:"required"`
}

// Extract parameters from http request
func newPostAuthRegistrationProfileRequestParams(r *http.Request) *postAuthRegistrationProfileRequestParams {
	return &postAuthRegistrationProfileRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
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
func (p *postAuthRegistrationProfileRequestParams) toViewParams() map[string]any {
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
func (params *postAuthRegistrationProfileRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	for k := range viewError.validationFieldErrors {
		if k == "FlowID" || k == "CsrfToken" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
			break
		}
	}
	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getAuthRegistrationProfileViews struct {
	formProfile    *view
	formCredential *view
}

// collect rendering data and validate request parameters.
func preparePostAuthRegistrationProfile(w http.ResponseWriter, r *http.Request) (*postAuthRegistrationProfileRequestParams, getAuthRegistrationProfileViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))
	reqParams := newPostAuthRegistrationProfileRequestParams(r)
	views := getAuthRegistrationProfileViews{
		formProfile:    newView("auth/registration/_form_profile.html").addParams(reqParams.toViewParams()).addParams(map[string]any{"Method": "profile"}),
		formCredential: newView("auth/registration/_form_credential.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.formProfile.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

// POST /auth/registration
func (p *Provider) handlePostAuthRegistrationProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := preparePostAuthRegistrationProfile(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "preparePostAuthRegistrationProfile failed", "err", err)
		return
	}

	// update Registration Flow
	updateRegistrationFlowResp, _, err := kratos.UpdateRegistrationFlow(ctx, kratos.UpdateRegistrationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateRegistrationFlowRequestBody{
			CsrfToken: reqParams.CsrfToken,
			Method:    "profile",
			Screen:    "credential-selection",
			Traits:    reqParams.Traits,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update registration error", "err", err.Error())
		views.formProfile.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// get latest registration flow
	// kratosReqHeaderForNext should return the header of UpdateRegistrationFlow, so do not get it here
	getRegistrationFlowResp, _, err := kratos.GetRegistrationFlow(ctx, kratos.GetRegistrationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		slog.ErrorContext(ctx, "get registration error", "GetRegistrationFlow error", err)
		return
	}

	// render verification code page (replace <body> tag and push url)
	addCookies(w, updateRegistrationFlowResp.Header.Cookie)
	views.formCredential.addParams(map[string]any{
		"RegistrationFlowID": reqParams.FlowID,
		"CsrfToken":          reqParams.CsrfToken,
		"PasskeyCreateData":  getRegistrationFlowResp.RegistrationFlow.PasskeyCreateData,
	}).render(w, r, session)
}
