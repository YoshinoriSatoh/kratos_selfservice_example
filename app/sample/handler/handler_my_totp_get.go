package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /my/totp
// --------------------------------------------------------------------------
type getMyTotpRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
}

// Extract parameters from http request
func newGetMyTotpRequestParams(r *http.Request) *getMyTotpRequestParams {
	return &getMyTotpRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}
}

// Return parameters that can refer in view template
func (p *getMyTotpRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"SettingsFlowID": p.FlowID,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getMyTotpRequestParams) validate() *viewError {
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
type getMyTotpViews struct {
	totp *view
}

// collect rendering data and validate request parameters.
func prepareGetMyTotp(w http.ResponseWriter, r *http.Request) (*getMyTotpRequestParams, getMyTotpViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
	}))
	reqParams := newGetMyTotpRequestParams(r)
	views := getMyTotpViews{
		totp: newView("my/totp.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.totp.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handleGetMyTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetMyTotp(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetMyTotp failed", "err", err)
		return
	}

	// create or get settings Flow
	settingsFlow, kratosResponseHeader, _, err := kratos.CreateOrGetSettingsFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		views.totp.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	slog.DebugContext(ctx, "handleGetMyTotp", "settingsFlow", settingsFlow)

	// add cookies to the request header
	addCookies(w, kratosResponseHeader.Cookie)

	views.totp.addParams(map[string]any{
		"SettingsFlowID": settingsFlow.FlowID,
		"CsrfToken":      settingsFlow.CsrfToken,
		"TotpQR":         "src=" + settingsFlow.TotpQR,
		"TotpRegisted":   settingsFlow.TotpUnlink,
	}).render(w, r, session)
}
