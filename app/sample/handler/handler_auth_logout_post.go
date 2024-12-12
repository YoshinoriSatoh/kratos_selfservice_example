package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /auth/logout
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLogout
type postAuthLogoutRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
}

// Extract parameters from http request
func newPostAuthLogoutRequestParams(r *http.Request) *postAuthLogoutRequestParams {
	return &postAuthLogoutRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthLogoutRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LogoutFlowID": p.FlowID,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *postAuthLogoutRequestParams) validate() *viewError {
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
type postAuthLogoutViews struct {
	index *view
	top   *view
}

// collect rendering data and validate request parameters.
func preparePostAuthLogout(w http.ResponseWriter, r *http.Request) (*postAuthLogoutRequestParams, postAuthLogoutViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGOUT_DEFAULT",
	}))
	reqParams := newPostAuthLogoutRequestParams(r)
	views := postAuthLogoutViews{
		index: newView("auth/logout/index.html").addParams(reqParams.toViewParams()),
		top:   newView("top/index.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.index.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	_, views, _, err := preparePostAuthLogout(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "preparePostAuthLogout failed", "err", err)
		return
	}

	updateLogoutFlowResp, _, err := kratos.Logout(ctx, kratos.LogoutRequest{
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		setHeadersForReplaceBody(w, "/")
		views.top.addParams(map[string]any{
			"Items": items,
		}).render(w, r, session)
	}

	// change location
	addCookies(w, updateLogoutFlowResp.Header.Cookie)
	w.Header().Set("HX-Location", "/")
}
