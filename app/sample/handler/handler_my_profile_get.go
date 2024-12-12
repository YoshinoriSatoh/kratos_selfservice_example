package handler

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// GET /my/profile
// --------------------------------------------------------------------------
type getMyProfileRequestParams struct {
	FlowID         string `validate:"omitempty,uuid4"`
	SavedEmail     string
	SavedFirstname string
	SavedLastname  string
	SavedNickname  string
	SavedBirthdate string
}

// Extract parameters from http request
func newGetMyProfileRequestParams(r *http.Request) *getMyProfileRequestParams {
	return &getMyProfileRequestParams{
		FlowID:         r.URL.Query().Get("flow"),
		SavedEmail:     r.URL.Query().Get("email"),
		SavedFirstname: r.URL.Query().Get("firstname"),
		SavedLastname:  r.URL.Query().Get("lastname"),
		SavedNickname:  r.URL.Query().Get("nickname"),
		SavedBirthdate: r.URL.Query().Get("birthdate"),
	}
}

// Return parameters that can refer in view template
func (p *getMyProfileRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"SettingsFlowID": p.FlowID,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (p *getMyProfileRequestParams) validate() *viewError {
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
type getMyProfileViews struct {
	index *view
}

// collect rendering data and validate request parameters.
func prepareGetMyProfile(w http.ResponseWriter, r *http.Request) (*getMyProfileRequestParams, getMyProfileViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
	}))
	reqParams := newGetMyProfileRequestParams(r)
	views := getMyProfileViews{
		index: newView("my/profile/index.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.index.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handleGetMyProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetMyProfile(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetMyProfile failed", "err", err)
		return
	}

	// create or get settings Flow
	settingsFlow, kratosResponseHeader, err := kratos.CreateOrGetSettingsFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		views.index.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// add cookies to the request header
	addCookies(w, kratosResponseHeader.Cookie)
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)
	kratosRequestHeader.Cookie = strings.Join(kratosResponseHeader.Cookie, " ")

	// render page
	year, month, day := parseDate(session.Identity.Traits.Birthdate)

	email := session.Identity.Traits.Email
	if reqParams.SavedEmail != "" {
		email = reqParams.SavedEmail
	}
	firstname := session.Identity.Traits.Firstname
	if reqParams.SavedFirstname != "" {
		firstname = reqParams.SavedFirstname
	}
	lastname := session.Identity.Traits.Lastname
	if reqParams.SavedLastname != "" {
		lastname = reqParams.SavedLastname
	}
	nickname := session.Identity.Traits.Nickname
	if reqParams.SavedNickname != "" {
		nickname = reqParams.SavedNickname
	}
	views.index.addParams(map[string]any{
		"SettingsFlowID": settingsFlow.FlowID,
		"CsrfToken":      settingsFlow.CsrfToken,
		"Email":          email,
		"Firstname":      firstname,
		"Lastname":       lastname,
		"Nickname":       nickname,
		"BirthdateYear":  year,
		"BirthdateMonth": month,
		"BirthdateDay":   day,
	}).render(w, r, session)
}
