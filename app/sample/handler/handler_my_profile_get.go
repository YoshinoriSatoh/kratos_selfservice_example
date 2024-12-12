package handler

import (
	"net/http"

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

func (p *Provider) handleGetMyProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newGetMyProfileRequestParams(r)

	// prepare views
	myProfileIndexView := newView("my/profile/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		myProfileIndexView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
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
		myProfileIndexView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	// var information string
	// if existsAfterLoginHook(r, AFTER_LOGIN_HOOK_COOKIE_KEY_SETTINGS_PROFILE_UPDATE) {
	// 	information = "プロフィールを更新しました。"
	// 	deleteAfterLoginHook(w, AFTER_LOGIN_HOOK_COOKIE_KEY_SETTINGS_PROFILE_UPDATE)
	// }
	year, month, day := parseDate(session.Identity.Traits.Birthdate)
	addCookies(w, kratosResponseHeader.Cookie)

	email := session.Identity.Traits.Email
	if params.SavedEmail != "" {
		email = params.SavedEmail
	}
	firstname := session.Identity.Traits.Firstname
	if params.SavedFirstname != "" {
		firstname = params.SavedFirstname
	}
	lastname := session.Identity.Traits.Lastname
	if params.SavedLastname != "" {
		lastname = params.SavedLastname
	}
	nickname := session.Identity.Traits.Nickname
	if params.SavedNickname != "" {
		nickname = params.SavedNickname
	}
	myProfileIndexView.addParams(map[string]any{
		"SettingsFlowID": settingsFlow.FlowID,
		"CsrfToken":      settingsFlow.CsrfToken,
		"Email":          email,
		"Firstname":      firstname,
		"Lastname":       lastname,
		"Nickname":       nickname,
		"BirthdateYear":  year,
		"BirthdateMonth": month,
		"BirthdateDay":   day,
		// "Information":    information,
	}).render(w, r, session)
}
