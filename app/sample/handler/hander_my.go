package handler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
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
	profile *view
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
		profile: newView("my/profile.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.profile.addParams(viewError.toViewParams()).render(w, r, session)
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
	settingsFlow, kratosResponseHeader, _, err := kratos.CreateOrGetSettingsFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		views.profile.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	slog.DebugContext(ctx, "handleGetMyProfile", "settingsFlow", settingsFlow)

	// add cookies to the request header
	addCookies(w, kratosResponseHeader.Cookie)

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
	views.profile.addParams(map[string]any{
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

// Views
type getMyProfilePostViews struct {
	profileForm      *view
	loginIndex       *view
	loginCode        *view
	verificationCode *view
	topIndex         *view
}

// collect rendering data and validate request parameters.
func prepareGetMyProfilePost(w http.ResponseWriter, r *http.Request) (*postMyProfileRequestPostForm, getMyProfilePostViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
	}))
	reqParams := newMyProfileRequestParams(r)
	views := getMyProfilePostViews{
		profileForm:      newView("my/_profile_form.html").addParams(reqParams.toViewParams()),
		loginIndex:       newView("auth/login/index.html").addParams(reqParams.toViewParams()),
		loginCode:        newView("auth/login/code.html").addParams(reqParams.toViewParams()),
		verificationCode: newView("auth/verification/code.html").addParams(reqParams.toViewParams()),
		topIndex:         newView("top/index.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.profileForm.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

// Handler POST /my/profile
func (p *Provider) handlePostMyProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetMyProfilePost(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetMyProfilePost failed", "err", err)
		return
	}

	// update settings flow
	kratosResp, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: reqParams.FlowID,
		Header: kratosRequestHeader,
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken: reqParams.CsrfToken,
			Method:    "profile",
			Traits:    makeTraitsForUpdateSettings(session, reqParams),
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "handlePostMyProfile", "err", err)
		// render login form when session expired privileged_session_max_age, and re-render profile form.
		// redirect not use. htmx implementation policy.
		var errGeneric kratos.ErrorGeneric
		if errors.As(err, &errGeneric) && err.(kratos.ErrorGeneric).Err.ID == "session_refresh_required" {
			updateSettingsRequest := &kratos.UpdateSettingsFlowRequest{
				FlowID: reqParams.FlowID,
				Body: kratos.UpdateSettingsFlowRequestBody{
					CsrfToken: reqParams.CsrfToken,
					Method:    "profile",
					Traits:    makeTraitsForUpdateSettings(session, reqParams),
				},
			}

			if kratos.SessionRequiredAal == kratos.Aal1 {
				// create login flow
				createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosRequestHeader,
					Refresh: true,
					Aal:     kratos.Aal1,
				})
				if err != nil {
					views.profileForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// render login form
				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				views.loginIndex.addParams(map[string]any{
					"LoginFlowID":           createLoginFlowResp.LoginFlow.FlowID,
					"Information":           "プロフィール更新のために再度ログインをお願いします。",
					"CsrfToken":             createLoginFlowResp.LoginFlow.CsrfToken,
					"UpdateSettingsRequest": updateSettingsRequest.ToString(),
				}).render(w, r, session)

			} else if kratos.SessionRequiredAal == kratos.Aal2 {
				// create and update login flow for aal2, send authentication code
				createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosRequestHeader,
					Aal:     kratos.Aal2,
					Refresh: true,
				})
				if err != nil {
					slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
					views.profileForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// update login flow for aal2, send authentication code
				_, _, err = kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
					FlowID: createLoginFlowResp.LoginFlow.FlowID,
					Header: kratosRequestHeader,
					Aal:    kratos.Aal2,
					Body: kratos.UpdateLoginFlowRequestBody{
						Method:     "code",
						CsrfToken:  createLoginFlowResp.LoginFlow.CsrfToken,
						Identifier: createLoginFlowResp.LoginFlow.CodeAddress,
					},
				})
				if err != nil {
					slog.ErrorContext(ctx, "update login flow for aal2 error", "err", err)
					views.profileForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login/code?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				views.loginCode.addParams(map[string]any{
					"LoginFlowID":           createLoginFlowResp.LoginFlow.FlowID,
					"Information":           "プロフィール更新のために再度ログインをお願いします。",
					"CsrfToken":             createLoginFlowResp.LoginFlow.CsrfToken,
					"Identifier":            createLoginFlowResp.LoginFlow.CodeAddress,
					"UpdateSettingsRequest": updateSettingsRequest.ToString(),
				}).render(w, r, session)
			}
			return
		}

		// render form with error
		views.profileForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
		Header: kratosReqHeaderForNext,
	})
	session = whoamiResp.Session

	// verification required when modified email in traits
	if kratosResp.VerificationFlow != nil {
		// transition to verification flow from settings flow

		// get verification flow
		getVerificationFlowResp, _, err := kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
			FlowID: kratosResp.VerificationFlow.FlowID,
			Header: makeDefaultKratosRequestHeader(r),
		})
		if err != nil {
			slog.ErrorContext(ctx, "get verification error", "err", err.Error())
			views.profileForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}

		createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		if err != nil {
			views.profileForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}

		// for re-render profile form
		year, month, day := parseDate(reqParams.Birthdate)
		myProfileIndexView := newView("my/profile.html").addParams(map[string]any{
			"SettingsFlowID": createSettingsFlowResp.SettingsFlow.FlowID,
			"Information":    "プロフィールが更新されました。",
			"CsrfToken":      createSettingsFlowResp.SettingsFlow.CsrfToken,
			"Email":          session.Identity.Traits.Email,
			"Firstname":      session.Identity.Traits.Firstname,
			"Lastname":       session.Identity.Traits.Lastname,
			"Nickname":       session.Identity.Traits.Nickname,
			"BirthdateYear":  year,
			"BirthdateMonth": month,
			"BirthdateDay":   day,
		})

		// render verification code page (replace <body> tag and push url)
		addCookies(w, getVerificationFlowResp.Header.Cookie)
		setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", getVerificationFlowResp.VerificationFlow.FlowID))
		views.verificationCode.addParams(map[string]any{
			"VerificationFlowID": getVerificationFlowResp.VerificationFlow.FlowID,
			"CsrfToken":          getVerificationFlowResp.VerificationFlow.CsrfToken,
			"IsUsedFlow":         getVerificationFlowResp.VerificationFlow.IsUsedFlow(),
			"Render":             myProfileIndexView.toQueryParam(),
		}).render(w, r, session)
		return
	}

	// render top page
	addCookies(w, kratosResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	views.topIndex.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}

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

// Views
type getMyPasswordViews struct {
	password *view
}

// collect rendering data and validate request parameters.
func prepareGetMyPassword(w http.ResponseWriter, r *http.Request) (*getMyPasswordRequestParams, getMyPasswordViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
	}))
	reqParams := newGetMyPasswordRequestParams(r)
	views := getMyPasswordViews{
		password: newView("my/password.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.password.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handleGetMyPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetMyPassword(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetMyPassword failed", "err", err)
		return
	}

	// create or get settings Flow
	settingsFlow, kratosResponseHeader, _, err := kratos.CreateOrGetSettingsFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		views.password.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// add cookies to the request header
	addCookies(w, kratosResponseHeader.Cookie)

	// render page
	views.password.addParams(map[string]any{
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
		"SettingsFlowID":       p.FlowID,
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

// Views
type getMyPasswordPostViews struct {
	passwordForm *view
	loginIndex   *view
	loginCode    *view
}

// collect rendering data and validate request parameters.
func prepareGetMyPasswordPost(w http.ResponseWriter, r *http.Request) (*postMyPasswordRequestParams, getMyPasswordPostViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
	}))
	reqParams := newMyPasswordRequestParams(r)
	views := getMyPasswordPostViews{
		passwordForm: newView("my/_password_form.html").addParams(reqParams.toViewParams()),
		loginIndex:   newView("auth/login/index.html").addParams(reqParams.toViewParams()),
		loginCode:    newView("auth/login/code.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.passwordForm.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostMyPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)
	slog.Debug("", "session", session)
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetMyPasswordPost(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetMyPasswordPost failed", "err", err)
		return
	}

	// prepare views
	topIndexView := newView("top/index.html").addParams(reqParams.toViewParams())

	kratosResp, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: reqParams.FlowID,
		Header: kratosRequestHeader,
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken: reqParams.CsrfToken,
			Method:    "password",
			Password:  reqParams.Password,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "handlePostMyPassword", "err", err)
		// render login form when session expired privileged_session_max_age, and re-render profile form.
		// redirect not use. htmx implementation policy.
		var errGeneric kratos.ErrorGeneric
		if errors.As(err, &errGeneric) && err.(kratos.ErrorGeneric).Err.ID == "session_refresh_required" {
			updateSettingsRequest := &kratos.UpdateSettingsFlowRequest{
				FlowID: reqParams.FlowID,
				Body: kratos.UpdateSettingsFlowRequestBody{
					CsrfToken: reqParams.CsrfToken,
					Method:    "password",
					Password:  reqParams.Password,
				},
			}

			if kratos.SessionRequiredAal == kratos.Aal1 {
				// create login flow
				createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosReqHeaderForNext,
					Aal:     kratos.Aal1,
					Refresh: true,
				})
				if err != nil {
					views.passwordForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// render login form
				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				views.loginIndex.addParams(map[string]any{
					"LoginFlowID":           createLoginFlowResp.LoginFlow.FlowID,
					"Information":           "パスワード更新のために再度ログインをお願いします。",
					"CsrfToken":             createLoginFlowResp.LoginFlow.CsrfToken,
					"UpdateSettingsRequest": updateSettingsRequest.ToString(),
				}).render(w, r, session)

			} else if kratos.SessionRequiredAal == kratos.Aal2 {
				// create and update login flow for aal2, send authentication code
				createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosRequestHeader,
					Aal:     kratos.Aal2,
					Refresh: true,
				})
				if err != nil {
					slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
					views.passwordForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// update login flow for aal2, send authentication code
				_, _, err = kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
					FlowID: createLoginFlowResp.LoginFlow.FlowID,
					Header: kratosRequestHeader,
					Aal:    kratos.Aal2,
					Body: kratos.UpdateLoginFlowRequestBody{
						Method:     "code",
						CsrfToken:  createLoginFlowResp.LoginFlow.CsrfToken,
						Identifier: createLoginFlowResp.LoginFlow.CodeAddress,
					},
				})
				if err != nil {
					slog.ErrorContext(ctx, "update login flow for aal2 error", "err", err)
					views.passwordForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login/code?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				views.loginCode.addParams(map[string]any{
					"LoginFlowID":           createLoginFlowResp.LoginFlow.FlowID,
					"Information":           "パスワード更新のために再度ログインをお願いします。",
					"CsrfToken":             createLoginFlowResp.LoginFlow.CsrfToken,
					"Identifier":            createLoginFlowResp.LoginFlow.CodeAddress,
					"UpdateSettingsRequest": updateSettingsRequest.ToString(),
				}).render(w, r, session)
			}
			return
		}

		// render form with error
		views.passwordForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	addCookies(w, kratosResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	topIndexView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}

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

// --------------------------------------------------------------------------
// POST /my/totp
// --------------------------------------------------------------------------
type postMyTotpRequestPostForm struct {
	FlowID     string `validate:"required,uuid4"`
	CsrfToken  string `validate:"required"`
	TotpCode   string `validate:"omitempty" ja:"認証コード"`
	TotpUnlink string `validate:"omitempty"`
}

// Extract parameters from http request
func newMyTotpRequestParams(r *http.Request) *postMyTotpRequestPostForm {
	return &postMyTotpRequestPostForm{
		FlowID:     r.URL.Query().Get("flow"),
		CsrfToken:  r.PostFormValue("csrf_token"),
		TotpCode:   r.PostFormValue("totp_code"),
		TotpUnlink: r.PostFormValue("totp_unlink"),
	}
}

// Return parameters that can refer in view template
func (p *postMyTotpRequestPostForm) toViewParams() map[string]any {
	return map[string]any{
		"SettingsTotpID": p.FlowID,
		"CsrfToken":      p.CsrfToken,
		"TotpCode":       p.TotpCode,
		"TotpUnlink":     p.TotpUnlink,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postMyTotpRequestPostForm) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))
	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getMyTotpPostViews struct {
	totpForm   *view
	loginIndex *view
	loginCode  *view
}

// collect rendering data and validate request parameters.
func prepareGetMyTotpPost(w http.ResponseWriter, r *http.Request) (*postMyTotpRequestPostForm, getMyTotpPostViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
	}))
	reqParams := newMyTotpRequestParams(r)
	views := getMyTotpPostViews{
		totpForm:   newView("my/_totp_form.html").addParams(reqParams.toViewParams()),
		loginIndex: newView("auth/login/index.html").addParams(reqParams.toViewParams()),
		loginCode:  newView("auth/login/code.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.totpForm.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

// Handler POST /my/totp
func (p *Provider) handlePostMyTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetMyTotpPost(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetMyTotpPost failed", "err", err)
		return
	}

	// update settings flow
	_, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: reqParams.FlowID,
		Header: kratosRequestHeader,
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken:  reqParams.CsrfToken,
			Method:     "totp",
			TotpCode:   reqParams.TotpCode,
			TotpUnlink: reqParams.TotpUnlink,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "handlePostMyTotp", "err", err)
		// render login form when session expired privileged_session_max_age, and re-render totp form.
		// redirect not use. htmx implementation policy.
		var errGeneric kratos.ErrorGeneric
		if errors.As(err, &errGeneric) && err.(kratos.ErrorGeneric).Err.ID == "session_refresh_required" {
			updateSettingsRequest := &kratos.UpdateSettingsFlowRequest{
				FlowID: reqParams.FlowID,
				Body: kratos.UpdateSettingsFlowRequestBody{
					CsrfToken:  reqParams.CsrfToken,
					Method:     "totp",
					TotpCode:   reqParams.TotpCode,
					TotpUnlink: reqParams.TotpUnlink,
				},
			}

			if kratos.SessionRequiredAal == kratos.Aal1 {
				// create login flow
				createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosReqHeaderForNext,
					Aal:     kratos.Aal1,
					Refresh: true,
				})
				if err != nil {
					views.totpForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// render login form
				addCookies(w, kratosRequestHeader.Cookie)
				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				views.loginIndex.addParams(map[string]any{
					"LoginFlowID":           createLoginFlowResp.LoginFlow.FlowID,
					"Information":           "認証アプリ設定のために再度ログインをお願いします。",
					"CsrfToken":             createLoginFlowResp.LoginFlow.CsrfToken,
					"UpdateSettingsRequest": updateSettingsRequest.ToString(),
				}).render(w, r, session)

			} else if kratos.SessionRequiredAal == kratos.Aal2 {
				// create and update login flow for aal2, send authentication code
				createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosRequestHeader,
					Aal:     kratos.Aal2,
					Refresh: true,
				})
				if err != nil {
					slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
					views.totpForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				_, _, err = kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
					FlowID: createLoginFlowResp.LoginFlow.FlowID,
					Header: kratosRequestHeader,
					Aal:    kratos.Aal2,
					Body: kratos.UpdateLoginFlowRequestBody{
						Method:     "code",
						CsrfToken:  createLoginFlowResp.LoginFlow.CsrfToken,
						Identifier: createLoginFlowResp.LoginFlow.CodeAddress,
					},
				})
				if err != nil {
					slog.ErrorContext(ctx, "update login flow for aal2 error", "err", err)
					views.totpForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// addCookies(w, kratosRequestHeader.Cookie)
				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login/code?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				views.loginCode.addParams(map[string]any{
					"LoginFlowID":           createLoginFlowResp.LoginFlow.FlowID,
					"Information":           "認証アプリ更新のために再度ログインをお願いします。",
					"CsrfToken":             createLoginFlowResp.LoginFlow.CsrfToken,
					"Identifier":            createLoginFlowResp.LoginFlow.CodeAddress,
					"UpdateSettingsRequest": updateSettingsRequest.ToString(),
				}).render(w, r, session)
			}
			return
		}

		// render form with error
		views.totpForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	whoamiResp, whoamiReqheader := kratos.Whoami(ctx, kratos.WhoamiRequest{
		Header: kratosReqHeaderForNext,
	})
	session = whoamiResp.Session
	slog.DebugContext(ctx, "handlePostMyTotp", "whoamiResp", whoamiResp, "whoamiReqheader", whoamiReqheader)

	// create or get settings Flow
	createSettingsTotpResp, kratosReqHeader, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		views.totpForm.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	slog.DebugContext(ctx, "handlePostMyTotp", "createSettingsTotpResp", createSettingsTotpResp, "kratosReqHeader", kratosReqHeader)

	// render top page
	addCookies(w, kratosReqHeader.Cookie)
	views.totpForm.addParams(map[string]any{
		"SettingsFlowID": createSettingsTotpResp.SettingsFlow.FlowID,
		"CsrfToken":      createSettingsTotpResp.SettingsFlow.CsrfToken,
		"TotpQR":         "src=" + createSettingsTotpResp.SettingsFlow.TotpQR,
		"TotpRegisted":   createSettingsTotpResp.SettingsFlow.TotpUnlink,
	}).render(w, r, session)
}

type showSettingsAfterLoggedInParams struct {
	FlowID    string
	CsrfToken string
	Method    string
}

func (p *showSettingsAfterLoggedInParams) toString() string {
	jsonStr, err := json.Marshal(*p)
	if err != nil {
		slog.Error("showSettingsAfterLoggedInParams.toString", "json Marshal error", err)
	}
	return base64.URLEncoding.EncodeToString(jsonStr)
}

// func showSettingsAfterLoggedInParamsFromString(base64str string) showSettingsAfterLoggedInParams {
// 	var h showSettingsAfterLoggedInParams
// 	jsonStr, err := base64.URLEncoding.DecodeString(base64str)
// 	if err != nil {
// 		slog.Error("showSettingsAfterLoggedInParamsFromString", "json Marshal error", err)
// 	}
// 	json.Unmarshal([]byte(jsonStr), &h)
// 	return h
// }

// func showSettingsAfterLoggedIn(ctx context.Context, w http.ResponseWriter, r *http.Request, session *kratos.Session, kratosRequestHeader kratos.KratosRequestHeader, params showSettingsAfterLoggedInParams) {
// 	slog.InfoContext(ctx, "showSettingsPasswordAfterLoggedIn", "params", params)

// 	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
// 		MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
// 	}))
// 	getSettingsFlowResp, _, err := kratos.GetSettingsFlow(ctx, kratos.GetSettingsFlowRequest{
// 		FlowID: params.FlowID,
// 		Header: kratosRequestHeader,
// 	})
// 	if err != nil {
// 		slog.ErrorContext(ctx, "showSettingsAfterLoggedIn", "err", err)
// 		newView("auth/recovery/_code_form.html").addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
// 	}

// 	addCookies(w, getSettingsFlowResp.Header.Cookie)
// 	setHeadersForReplaceBody(w, fmt.Sprintf("/my/password?flow=%s", params.FlowID))
// 	newView("my/password.html").addParams(map[string]any{
// 		"SettingsFlowID": params.FlowID,
// 		"CsrfToken":      getSettingsFlowResp.SettingsFlow.CsrfToken,
// 	}).render(w, r, session)

// }

// type updateSettingsAfterLoggedInParams struct {
// 	FlowID     string
// 	CsrfToken  string
// 	Method     string
// 	Traits     kratos.Traits
// 	Password   string
// 	TotpCode   string
// 	TotpUnlink string
// }

// func (p *updateSettingsAfterLoggedInParams) toString() string {
// 	jsonStr, err := json.Marshal(*p)
// 	if err != nil {
// 		slog.Error("updateSettingsAfterLoggedInParams.toString", "json Marshal error", err)
// 	}
// 	return base64.URLEncoding.EncodeToString(jsonStr)
// }

// func updateSettingsAfterLoggedInParamsFromString(base64str string) updateSettingsAfterLoggedInParams {
// 	var h updateSettingsAfterLoggedInParams
// 	jsonStr, err := base64.URLEncoding.DecodeString(base64str)
// 	if err != nil {
// 		slog.Error("updateSettingsAfterLoggedInParamsFromString", "json Marshal error", err)
// 	}
// 	json.Unmarshal([]byte(jsonStr), &h)
// 	return h
// }

// func updateSettingsAfterLoggedIn(ctx context.Context, w http.ResponseWriter, r *http.Request, session *kratos.Session, kratosRequestHeaderAfterLoggedIn kratos.KratosRequestHeader, params updateSettingsAfterLoggedInParams) {
// 	if params.Method == "profile" {
// 		updateSettingsProfileAfterLoggedIn(ctx, w, r, session, kratosRequestHeaderAfterLoggedIn, params)
// 	} else if params.Method == "password" {
// 		updateSettingsPasswordAfterLoggedIn(ctx, w, r, session, kratosRequestHeaderAfterLoggedIn, params)
// 	} else if params.Method == "totp" {
// 		updateSettingsTotpAfterLoggedIn(ctx, w, r, session, kratosRequestHeaderAfterLoggedIn, params)
// 	}
// }

// func updateSettingsProfileAfterLoggedIn(ctx context.Context, w http.ResponseWriter, r *http.Request, session *kratos.Session, kratosRequestHeaderAfterLoggedIn kratos.KratosRequestHeader, params updateSettingsAfterLoggedInParams) {
// 	slog.InfoContext(ctx, "updateSettingsProfileAfterLoggedIn", "params", params)

// 	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
// 		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
// 	}))
// 	loginCodeView := newView("auth/login/code.html")

// 	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

// 	kratosResp, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
// 		FlowID: params.FlowID,
// 		Header: kratos.KratosRequestHeader{ // required both aal1 kratos session and csrf_token cookie
// 			Cookie: []string{
// 				kratos.ExtractCsrfTokenCookie(kratosRequestHeader),
// 				kratos.ExtractKratosSessionCookie(kratosRequestHeaderAfterLoggedIn),
// 			},
// 			ClientIP: kratosRequestHeaderAfterLoggedIn.ClientIP,
// 		},
// 		Body: kratos.UpdateSettingsFlowRequestBody{
// 			CsrfToken: params.CsrfToken,
// 			Method:    "profile",
// 			Traits:    params.Traits,
// 		},
// 	})
// 	if err != nil {
// 		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
// 		return
// 	}
// 	if kratosResp.VerificationFlow != nil {
// 		// get verification flow
// 		getVerificationFlowResp, _, err := kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
// 			FlowID: kratosResp.VerificationFlow.FlowID,
// 			Header: kratosReqHeaderForNext,
// 		})
// 		if err != nil {
// 			slog.ErrorContext(ctx, "get verification error", "err", err.Error())
// 			loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
// 			return
// 		}

// 		whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
// 			Header: kratosReqHeaderForNext,
// 		})

// 		createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
// 			Header: kratosRequestHeader,
// 		})
// 		if err != nil {
// 			loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
// 			return
// 		}

// 		// for re-render profile form
// 		year, month, day := parseDate(params.Traits.Birthdate)
// 		myProfileIndexView := newView("my/profile.html").addParams(map[string]any{
// 			"SettingsFlowID": createSettingsFlowResp.SettingsFlow.FlowID,
// 			"Information":    "プロフィールが更新されました。",
// 			"CsrfToken":      createSettingsFlowResp.SettingsFlow.CsrfToken,
// 			"Email":          whoamiResp.Session.Identity.Traits.Email,
// 			"Firstname":      whoamiResp.Session.Identity.Traits.Firstname,
// 			"Lastname":       whoamiResp.Session.Identity.Traits.Lastname,
// 			"Nickname":       whoamiResp.Session.Identity.Traits.Nickname,
// 			"BirthdateYear":  year,
// 			"BirthdateMonth": month,
// 			"BirthdateDay":   day,
// 		})

// 		// render verification code page (replace <body> tag and push url)
// 		addCookies(w, getVerificationFlowResp.Header.Cookie)
// 		setHeadersForReplaceBody(w, fmt.Sprintf("/auth/verification/code?flow=%s", getVerificationFlowResp.VerificationFlow.FlowID))
// 		newView("auth/verification/code.html").addParams(map[string]any{
// 			"VerificationFlowID": getVerificationFlowResp.VerificationFlow.FlowID,
// 			"CsrfToken":          getVerificationFlowResp.VerificationFlow.CsrfToken,
// 			"IsUsedFlow":         getVerificationFlowResp.VerificationFlow.IsUsedFlow(),
// 			"Render":             myProfileIndexView.toQueryParam(),
// 		}).render(w, r, session)
// 		return
// 	}
// 	whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
// 		Header: kratosReqHeaderForNext,
// 	})

// 	createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
// 		Header: makeDefaultKratosRequestHeader(r),
// 	})
// 	if err != nil {
// 		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
// 		return
// 	}
// 	year, month, day := parseDate(params.Traits.Birthdate)
// 	addCookies(w, createSettingsFlowResp.Header.Cookie)
// 	setHeadersForReplaceBody(w, "/my/profile")
// 	newView("my/profile.html").addParams(map[string]any{
// 		"SettingsFlowID": createSettingsFlowResp.SettingsFlow.FlowID,
// 		"Information":    "プロフィールが更新されました。",
// 		"CsrfToken":      createSettingsFlowResp.SettingsFlow.CsrfToken,
// 		"Email":          whoamiResp.Session.Identity.Traits.Email,
// 		"Firstname":      whoamiResp.Session.Identity.Traits.Firstname,
// 		"Lastname":       whoamiResp.Session.Identity.Traits.Lastname,
// 		"Nickname":       whoamiResp.Session.Identity.Traits.Nickname,
// 		"BirthdateYear":  year,
// 		"BirthdateMonth": month,
// 		"BirthdateDay":   day,
// 	}).render(w, r, whoamiResp.Session)
// }

// func updateSettingsPasswordAfterLoggedIn(ctx context.Context, w http.ResponseWriter, r *http.Request, session *kratos.Session, kratosRequestHeaderAfterLoggedIn kratos.KratosRequestHeader, params updateSettingsAfterLoggedInParams) {
// 	slog.InfoContext(ctx, "updateSettingsPasswordAfterLoggedIn", "params", params)

// 	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
// 		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
// 	}))
// 	loginCodeView := newView("auth/login/code.html")

// 	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

// 	_, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
// 		FlowID: params.FlowID,
// 		Header: kratos.KratosRequestHeader{ // required both aal1 kratos session and csrf_token cookie
// 			Cookie: []string{
// 				kratos.ExtractCsrfTokenCookie(kratosRequestHeader),
// 				kratos.ExtractKratosSessionCookie(kratosRequestHeaderAfterLoggedIn),
// 			},
// 			ClientIP: kratosRequestHeaderAfterLoggedIn.ClientIP,
// 		},
// 		Body: kratos.UpdateSettingsFlowRequestBody{
// 			CsrfToken: params.CsrfToken,
// 			Method:    "password",
// 			Password:  params.Password,
// 		},
// 	})
// 	if err != nil {
// 		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
// 		return
// 	}

// 	whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
// 		Header: kratosReqHeaderForNext,
// 	})

// 	createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
// 		Header: kratosRequestHeader,
// 	})
// 	if err != nil {
// 		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
// 		return
// 	}
// 	addCookies(w, createSettingsFlowResp.Header.Cookie)
// 	setHeadersForReplaceBody(w, "/my/password")
// 	newView("my/password.html").addParams(map[string]any{
// 		"SettingsTotpID": createSettingsFlowResp.SettingsFlow.FlowID,
// 		"Information":    "パスワードが設定されました。",
// 		"CsrfToken":      createSettingsFlowResp.SettingsFlow.CsrfToken,
// 	}).render(w, r, whoamiResp.Session)
// }

// func updateSettingsTotpAfterLoggedIn(ctx context.Context, w http.ResponseWriter, r *http.Request, session *kratos.Session, kratosRequestHeaderAfterLoggedIn kratos.KratosRequestHeader, params updateSettingsAfterLoggedInParams) {
// 	slog.InfoContext(ctx, "updateSettingsTotpAfterLoggedIn", "params", params)

// 	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
// 		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
// 	}))
// 	loginCodeView := newView("auth/login/code.html")

// 	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

// 	_, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
// 		FlowID: params.FlowID,
// 		Header: kratos.KratosRequestHeader{ // required both aal1 kratos session and csrf_token cookie
// 			Cookie: []string{
// 				kratos.ExtractCsrfTokenCookie(kratosRequestHeader),
// 				kratos.ExtractKratosSessionCookie(kratosRequestHeaderAfterLoggedIn),
// 			},
// 			ClientIP: kratosRequestHeaderAfterLoggedIn.ClientIP,
// 		},
// 		Body: kratos.UpdateSettingsFlowRequestBody{
// 			CsrfToken:  params.CsrfToken,
// 			Method:     "totp",
// 			TotpCode:   params.TotpCode,
// 			TotpUnlink: params.TotpUnlink,
// 		},
// 	})
// 	if err != nil {
// 		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
// 		return
// 	}
// 	whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
// 		Header: kratosReqHeaderForNext,
// 	})

// 	createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
// 		Header: kratosRequestHeader,
// 	})
// 	if err != nil {
// 		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
// 		return
// 	}
// 	addCookies(w, createSettingsFlowResp.Header.Cookie)
// 	setHeadersForReplaceBody(w, "/my/totp")
// 	newView("my/totp.html").addParams(map[string]any{
// 		"SettingsTotpID": createSettingsFlowResp.SettingsFlow.FlowID,
// 		"Information":    "認証アプリが設定されました。",
// 		"CsrfToken":      createSettingsFlowResp.SettingsFlow.CsrfToken,
// 		"TotpQR":         "src=" + createSettingsFlowResp.SettingsFlow.TotpQR,
// 		"TotpRegisted":   createSettingsFlowResp.SettingsFlow.TotpUnlink,
// 	}).render(w, r, whoamiResp.Session)
// }

func settingsView(method string, session *kratos.Session, settingsFlow kratos.SettingsFlow) *view {
	var settingsView *view
	if method == "profile" {
		year, month, day := parseDate(session.Identity.Traits.Birthdate)
		settingsView = newView("my/profile.html").addParams(map[string]any{
			"SettingsFlowID": settingsFlow.FlowID,
			"CsrfToken":      settingsFlow.CsrfToken,
			"Email":          session.Identity.Traits.Email,
			"Firstname":      session.Identity.Traits.Firstname,
			"Lastname":       session.Identity.Traits.Lastname,
			"Nickname":       session.Identity.Traits.Nickname,
			"BirthdateYear":  year,
			"BirthdateMonth": month,
			"BirthdateDay":   day,
			"Information":    "プロフィールが更新されました。",
		})
	} else if method == "password" {
		settingsView = newView("my/password.html").addParams(map[string]any{
			"SettingsTotpID": settingsFlow.FlowID,
			"Information":    "パスワードが設定されました。",
			"CsrfToken":      settingsFlow.CsrfToken,
		})
	} else if method == "totp" {
		settingsView = newView("my/totp.html").addParams(map[string]any{
			"SettingsTotpID": settingsFlow.FlowID,
			"Information":    "認証アプリが設定されました。",
			"CsrfToken":      settingsFlow.CsrfToken,
			"TotpQR":         "src=" + settingsFlow.TotpQR,
			"TotpRegisted":   settingsFlow.TotpUnlink,
		})
	}
	return settingsView
}
