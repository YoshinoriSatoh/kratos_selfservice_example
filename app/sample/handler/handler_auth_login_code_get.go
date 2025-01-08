package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /auth/login/code
// --------------------------------------------------------------------------
// Request parameters for handleGetAuthLoginCode
type getAuthLoginCodeRequestParams struct {
	FlowID   string `validate:"omitempty,uuid4"`
	ReturnTo string `validate:"omitempty"`
}

// Extract parameters from http request
func newGetAuthLoginCodeRequestParams(r *http.Request) *getAuthLoginCodeRequestParams {
	return &getAuthLoginCodeRequestParams{
		FlowID:   r.URL.Query().Get("flow"),
		ReturnTo: r.URL.Query().Get("return_to"),
	}
}

// Return parameters that can refer in view template
func (p *getAuthLoginCodeRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID": p.FlowID,
		"ReturnTo":    p.ReturnTo,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getAuthLoginCodeRequestParams) validate() *viewError {
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

// Views
type getAuthLoginCodeViews struct {
	code *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthLoginCode(w http.ResponseWriter, r *http.Request) (*getAuthLoginRequestParams, getAuthLoginCodeViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))
	reqParams := newGetAuthLoginRequestParams(r)
	views := getAuthLoginCodeViews{
		code: newView("auth/login/index.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.code.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handleGetAuthLoginCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthLoginCode(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthLoginCode failed", "err", err)
		return
	}

	// get login Flow
	kratosResp, _, err := kratos.GetLoginFlow(ctx, kratos.GetLoginFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		views.code.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	views.code.addParams(map[string]any{
		"LoginFlowID": reqParams.FlowID,
		"CsrfToken":   kratosResp.LoginFlow.CsrfToken,
	}).render(w, r, session)
}
