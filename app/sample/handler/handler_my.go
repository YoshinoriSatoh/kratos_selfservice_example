package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"kratos_example/kratos"

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
	params := newGetAuthRegistrationRequestParams(r)

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
		createSettingsFlowResp, err = p.d.Kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = createSettingsFlowResp.Header
		settingsFlow = createSettingsFlowResp.SettingsFlow
	} else {
		var getSettingsFlowResp kratos.GetSettingsFlowResponse
		getSettingsFlowResp, err = p.d.Kratos.GetSettingsFlow(ctx, kratos.GetSettingsFlowRequest{
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
	setCookie(w, kratosResponseHeader.Cookie)
	myPasswordIndexView.addParams(map[string]any{
		"SettingsFlowID": settingsFlow.FlowID,
		"CsrfToken":      settingsFlow.CsrfToken,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /my/password
// --------------------------------------------------------------------------
type postMyPasswordRequestParams struct {
	FlowID               string `validate:"uuid4"`
	CsrfToken            string `validate:"required"`
	Password             string `validate:"required" ja:"パスワード"`
	PasswordConfirmation string `validate:"required" ja:"パスワード確認"`
}

// Extract parameters from http request
func newMyPasswordRequestParams(r *http.Request) *postMyPasswordRequestParams {
	return &postMyPasswordRequestParams{
		FlowID:               r.URL.Query().Get("flow"),
		CsrfToken:            r.PostFormValue("csrf_token"),
		Password:             r.PostFormValue("password"),
		PasswordConfirmation: r.PostFormValue("password_confirmation"),
	}
}

// Return parameters that can refer in view template
func (p *postMyPasswordRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"RecoveryFlowID":       p.FlowID,
		"CsrfToken":            p.CsrfToken,
		"Password":             p.Password,
		"PasswordConfirmation": p.PasswordConfirmation,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postMyPasswordRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))
	if params.Password != params.PasswordConfirmation {
		viewError.validationFieldErrors["Password"] = validationFieldError{
			Tag:     "Password",
			Message: "パスワードとパスワード確認が一致しません",
		}
	}
	// Individual validations write here that cannot validate in common validations

	return viewError
}

func (p *Provider) handlePostMyPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newMyPasswordRequestParams(r)

	// prepare views
	myPasswordFormView := newView("my/password/_form.html").addParams(params.toViewParams())
	topIndexView := newView("top/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		myPasswordFormView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
	}))

	kratosResp, err := p.d.Kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken: params.CsrfToken,
			Method:    "password",
			Password:  params.Password,
		},
	})
	if err != nil {
		myPasswordFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	setCookie(w, kratosResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	topIndexView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}

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
		createSettingsFlowResp, err = p.d.Kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		kratosResponseHeader = createSettingsFlowResp.Header
		settingsFlow = createSettingsFlowResp.SettingsFlow
	} else {
		var getSettingsFlowResp kratos.GetSettingsFlowResponse
		getSettingsFlowResp, err = p.d.Kratos.GetSettingsFlow(ctx, kratos.GetSettingsFlowRequest{
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
	setCookie(w, kratosResponseHeader.Cookie)

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

// --------------------------------------------------------------------------
// POST /my/profile
// --------------------------------------------------------------------------
type postMyProfileRequestPostForm struct {
	FlowID    string `validate:"required,uuid4"`
	CsrfToken string `validate:"required"`
	Email     string `validate:"omitempty,email" ja:"メールアドレス"`
	Firstname string `validate:"omitempty" ja:"氏名(性)"`
	Lastname  string `validate:"omitempty" ja:"氏名(名)"`
	Nickname  string `validate:"omitempty" ja:"ニックネーム"`
	Birthdate string `validate:"omitempty,date" ja:"生年月日"`
}

// Extract parameters from http request
func newMyProfileRequestParams(r *http.Request) *postMyProfileRequestPostForm {
	return &postMyProfileRequestPostForm{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Email:     r.PostFormValue("email"),
		Firstname: r.PostFormValue("firstname"),
		Lastname:  r.PostFormValue("lastname"),
		Nickname:  r.PostFormValue("nickname"),
		Birthdate: fmt.Sprintf("%s-%s-%s", r.PostFormValue("birthdate_year"), r.PostFormValue("birthdate_month"), r.PostFormValue("birthdate_day")),
	}
}

// Return parameters that can refer in view template
func (p *postMyProfileRequestPostForm) toViewParams() map[string]any {
	year, month, day := parseDate(p.Birthdate)
	return map[string]any{
		"SettingsFlowID": p.FlowID,
		"CsrfToken":      p.CsrfToken,
		"Email":          p.Email,
		"Firstname":      p.Firstname,
		"Lastname":       p.Lastname,
		"Nickname":       p.Nickname,
		"BirthdateYear":  year,
		"BirthdateMonth": month,
		"BirthdateDay":   day,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postMyProfileRequestPostForm) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))
	// Individual validations write here that cannot validate in common validations

	return viewError
}

func makeTraitsForUpdateSettings(session *kratos.Session, params *postMyProfileRequestPostForm) kratos.Traits {
	traits := session.Identity.Traits
	if params.Email != "" {
		traits.Email = params.Email
	}
	if params.Firstname != "" {
		traits.Firstname = params.Firstname
	}
	if params.Lastname != "" {
		traits.Lastname = params.Lastname
	}
	if params.Nickname != "" {
		traits.Nickname = params.Nickname
	}
	if params.Birthdate != "" {
		traits.Birthdate = params.Birthdate
	}
	return traits
}

// Handler POST /my/profile
func (p *Provider) handlePostMyProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect request parameters
	params := newMyProfileRequestParams(r)

	// prepare views
	myProfileFormView := newView("my/profile/_form.html").addParams(params.toViewParams())
	loginIndexView := newView("auth/login/index.html").addParams(params.toViewParams())
	verificationCodeView := newView("auth/verification/code.html").addParams(params.toViewParams())
	topIndexView := newView("top/index.html").addParams(params.toViewParams())

	// validate request parameters
	if viewError := params.validate(); viewError.hasError() {
		myProfileFormView.addParams(viewError.toViewParams()).render(w, r, session)
		return
	}

	// base view error
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
	}))

	// update settings flow
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)
	kratosResp, err := p.d.Kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: params.FlowID,
		Header: kratosRequestHeader,
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken: params.CsrfToken,
			Method:    "profile",
			Traits:    makeTraitsForUpdateSettings(session, params),
		},
	})
	if err != nil {
		// render login form when session expired privileged_session_max_age, and re-render profile form.
		// redirect not use. htmx implementation policy.
		var errGeneric kratos.ErrorGeneric
		if errors.As(err, &errGeneric) && err.(kratos.ErrorGeneric).Err.ID == "session_refresh_required" {
			// create login flow
			kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, kratosResp.Header.Cookie)
			createLoginFlowResp, err := p.d.Kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
				Header:  kratosRequestHeader,
				Refresh: true,
			})
			if err != nil {
				myProfileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
				return
			}

			// for re-render profile form
			year, month, day := parseDate(params.Birthdate)
			myProfileIndexView := newView("my/profile/index.html").addParams(map[string]any{
				"SettingsFlowID": params.FlowID,
				"Information":    "ログインされました。プロフィールを更新できます。",
				"CsrfToken":      params.CsrfToken,
				"Email":          params.Email,
				"Firstname":      params.Firstname,
				"Lastname":       params.Lastname,
				"Nickname":       params.Nickname,
				"BirthdateYear":  year,
				"BirthdateMonth": month,
				"BirthdateDay":   day,
			})

			// render login form
			setCookie(w, createLoginFlowResp.Header.Cookie)
			setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
			loginIndexView.addParams(map[string]any{
				"LoginFlowID": createLoginFlowResp.LoginFlow.FlowID,
				"Information": "プロフィール更新のために再度ログインをお願いします。",
				"CsrfToken":   createLoginFlowResp.LoginFlow.CsrfToken,
				"Render":      myProfileIndexView.toQueryParam(),
			}).render(w, r, session)
			return
		}

		// render form with error
		myProfileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	if kratosResp.VerificationFlowID != "" {
		// transition to verification flow from settings flow
		// Transferring cookies from update registration flow response
		kratosRequestHeader := makeDefaultKratosRequestHeader(r)
		kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, kratosResp.Header.Cookie)
		// get verification flow
		getVerificationFlowResp, err := p.d.Kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
			FlowID: kratosResp.VerificationFlowID,
			Header: kratosRequestHeader,
		})
		if err != nil {
			slog.DebugContext(ctx, "get verification error", "err", err.Error())
			myProfileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}

		// render verification code page (replace <body> tag and push url)
		setCookie(w, getVerificationFlowResp.Header.Cookie)
		setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", getVerificationFlowResp.VerificationFlow.FlowID))
		verificationCodeView.addParams(map[string]any{
			"VerificationFlowID": getVerificationFlowResp.VerificationFlow.FlowID,
			"CsrfToken":          getVerificationFlowResp.VerificationFlow.CsrfToken,
			"IsUsedFlow":         getVerificationFlowResp.VerificationFlow.IsUsedFlow(),
		}).render(w, r, session)
		return
	}

	// render top page
	setCookie(w, kratosResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	topIndexView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}
