package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /my
// --------------------------------------------------------------------------
type getMyRequestParams struct {
}

// Extract parameters from http request
func newGetMyRequestParams(r *http.Request) *getMyRequestParams {
	return &getMyRequestParams{}
}

// Return parameters that can refer in view template
func (p *getMyRequestParams) toViewParams() map[string]any {
	return map[string]any{}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getMyRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(p))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getMyViews struct {
	index *view
}

// collect rendering data and validate request parameters.
func prepareGetMy(w http.ResponseWriter, r *http.Request) (*getMyRequestParams, getMyViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
	}))
	reqParams := newGetMyRequestParams(r)
	views := getMyViews{
		index: newView("my/index.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.index.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handleGetMy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	_, views, _, err := prepareGetMy(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetMy failed", "err", err)
		return
	}

	views.index.render(w, r, session)
}
