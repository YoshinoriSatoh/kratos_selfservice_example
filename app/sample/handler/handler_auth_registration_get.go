package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /auth/registration
// This is also used from oidc callback ui url when missing required fields in traits.
// --------------------------------------------------------------------------

// Request parameters
type getAuthRegistrationRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
}

// Return parameters that can refer in view template
func (p *getAuthRegistrationRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RegistrationFlowID": p.FlowID,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getAuthRegistrationRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(p))

	for k := range viewError.validationFieldErrors {
		if k == "FlowID" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
			break
		}
	}

	// Individual validations write here that cannot validate in common validations

	// slog.InfoContext(ctx, "validation error occured", "viewError", viewError)

	return viewError
}

// Views
type getAuthRegistrationViews struct {
	profile *view
	oidc    *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthRegistration(w http.ResponseWriter, r *http.Request) (*getAuthRegistrationRequestParams, getAuthRegistrationViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_REGISTRATION_DEFAULT",
	}))
	reqParams := &getAuthRegistrationRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}
	views := getAuthRegistrationViews{
		profile: newView("auth/registration/index.html").addParams(reqParams.toViewParams()).addParams(map[string]any{"Method": "profile"}),
		oidc:    newView("auth/registration/index.html").addParams(reqParams.toViewParams()).addParams(map[string]any{"Method": "oidc"}),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.profile.addParams(viewError.toViewParams()).render(w, r, session)
		err := fmt.Errorf("validation error: %v", viewError)
		slog.ErrorContext(ctx, "validation error", "viewError", viewError)
		return reqParams, views, baseViewError, err
	}

	return reqParams, views, baseViewError, nil
}

// handler
func (p *Provider) handleGetAuthRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthRegistration(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthRegistration failed", "err", err)
		return
	}

	// create or get registration Flow
	registrationFlow, kratosRespHeader, kratosReqHeaderForNext, err := kratos.KratosCreateOrGetRegistrationFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		views.profile.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// Update identity when user already registered with the same credential of provided the oidc provider.
	if registrationFlow.OidcProvider.Provided() {
		kratosUpdateRegistrationFlowResp, _, err := kratos.KratosLinkIdentityIfExists(ctx, kratos.KratosLinkIdentityIfExistsRequest{
			CredentialIdentifier: registrationFlow.Traits.Email,
			RequestHeader:        kratosReqHeaderForNext,
			RegistrationFlow:     registrationFlow,
		})
		if err != nil {
			slog.Error("Kratos.LinkIdentityIfExists failed", "error", err)
			views.oidc.addParams(baseViewError.setMessages([]string{pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_DEFAULT",
			})}).toViewParams()).render(w, r, session)
			return
		}
		if kratosUpdateRegistrationFlowResp != nil {
			addCookies(w, kratosUpdateRegistrationFlowResp.Header.Cookie)
			if kratosUpdateRegistrationFlowResp.RedirectBrowserTo != "" {
				// w.Header().Set("HX-Redirect", kratosResp.RedirectBrowserTo)
				redirect(w, r, kratosUpdateRegistrationFlowResp.RedirectBrowserTo)
				return
			}
		}

		addCookies(w, kratosRespHeader.Cookie) // set cookie that was responsed last from kratos (exclude admin api).
		views.oidc.addParams(map[string]any{
			"RegistrationFlowID": registrationFlow.FlowID,
			"CsrfToken":          registrationFlow.CsrfToken,
			"Provider":           registrationFlow.OidcProvider,
			"Traits":             registrationFlow.Traits,
		}).render(w, r, session)
		return
	}

	addCookies(w, kratosRespHeader.Cookie)
	setHeadersForReplaceBody(w, "/auth/registration")
	views.profile.addParams(map[string]any{
		"RegistrationFlowID": registrationFlow.FlowID,
		"CsrfToken":          registrationFlow.CsrfToken,
		"Traits":             registrationFlow.Traits,
		"PasskeyCreateData":  registrationFlow.PasskeyCreateData,
	}).render(w, r, session)
}
