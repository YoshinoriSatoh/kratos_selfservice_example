package handler

import (
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /my/password
// --------------------------------------------------------------------------
type getMyPasswordRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
}

// Extract parameters from http request
func newGetMyPasswordRequestParams(r *http.Request) *getMyPasswordRequestParams {
	return &getMyPasswordRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}
}

// Return parameters that can refer in view template
func (p *getMyPasswordRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"SettingsFlowID": p.FlowID,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getMyPasswordRequestParams) validate() *viewError {
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

func (p *Provider) handleGetMyPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newGetMyPasswordRequestParams(r)

	// prepare views
	myPasswordIndexView := newView("my/password/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		myPasswordIndexView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
	}))

	// create or get settings Flow
	var (
		err                  error
		settingsFlow         kratos.SettingsFlow
		kratosResponseHeader kratos.KratosResponseHeader
	)
	if params.FlowID == "" {
		var createSettingsFlowResp kratos.CreateSettingsFlowResponse
		createSettingsFlowResp, err = kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = createSettingsFlowResp.Header
		settingsFlow = createSettingsFlowResp.SettingsFlow
	} else {
		var getSettingsFlowResp kratos.GetSettingsFlowResponse
		getSettingsFlowResp, err = kratos.GetSettingsFlow(ctx, kratos.GetSettingsFlowRequest{
			FlowID: params.FlowID,
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = getSettingsFlowResp.Header
		settingsFlow = getSettingsFlowResp.SettingsFlow
	}
	if err != nil {
		myPasswordIndexView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	addCookies(w, kratosResponseHeader.Cookie)
	myPasswordIndexView.addParams(map[string]any{
		"SettingsFlowID": settingsFlow.FlowID,
		"CsrfToken":      settingsFlow.CsrfToken,
	}).render(w, r, session)
}
