package handler

import (
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /auth/recovery
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthRecovery
type getAuthRecoveryRequestParams struct {
	FlowID string
}

// Extract parameters from http request
func newGetAuthRecoveryRequestParams(r *http.Request) *getAuthRecoveryRequestParams {
	return &getAuthRecoveryRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}
}

// Return parameters that can refer in view template
func (p *getAuthRecoveryRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RecoveryFlowID": p.FlowID,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getAuthRecoveryRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(p))

	for k := range viewError.validationFieldErrors {
		if k == "FlowID" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
		}
	}

	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handleGetAuthRecovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newGetAuthRecoveryRequestParams(r)

	// prepare views
	recoveryIndexView := newView("auth/recovery/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		recoveryIndexView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_RECOVERY_DEFAULT",
	}))

	// create or get recovery Flow
	var (
		err                  error
		recoveryFlow         kratos.RecoveryFlow
		kratosResponseHeader kratos.KratosResponseHeader
	)
	if params.FlowID == "" {
		var createRecoveryFlowResp kratos.CreateRecoveryFlowResponse
		createRecoveryFlowResp, err = kratos.CreateRecoveryFlow(ctx, kratos.CreateRecoveryFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = createRecoveryFlowResp.Header
		recoveryFlow = createRecoveryFlowResp.RecoveryFlow
	} else {
		var getRecoveryFlowResp kratos.GetRecoveryFlowResponse
		getRecoveryFlowResp, err = kratos.GetRecoveryFlow(ctx, kratos.GetRecoveryFlowRequest{
			FlowID: params.FlowID,
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = getRecoveryFlowResp.Header
		recoveryFlow = getRecoveryFlowResp.RecoveryFlow
	}
	if err != nil {
		recoveryIndexView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	addCookies(w, kratosResponseHeader.Cookie)
	recoveryIndexView.addParams(map[string]any{
		"RecoveryFlowID": recoveryFlow.FlowID,
		"CsrfToken":      recoveryFlow.CsrfToken,
	}).render(w, r, session)
}
