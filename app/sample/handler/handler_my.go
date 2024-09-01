package handler

import (
	"fmt"
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
	FlowID string `validate:"omitempty,uuid4"`
}

// Extract parameters from http request
func newGetMyProfileRequestParams(r *http.Request) *getMyProfileRequestParams {
	return &getMyProfileRequestParams{
		FlowID: r.URL.Query().Get("flow"),
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
	myProfileIndexView.addParams(map[string]any{
		"SettingsFlowID": settingsFlow.FlowID,
		"CsrfToken":      settingsFlow.CsrfToken,
		"Email":          session.Identity.Traits.Email,
		"Firstname":      session.Identity.Traits.Firstname,
		"Lastname":       session.Identity.Traits.Lastname,
		"Nickname":       session.Identity.Traits.Nickname,
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
	Firstname string `validate:"omitempty,min=5,max=20" ja:"氏名(性)"`
	Lastname  string `validate:"omitempty,min=5,max=20" ja:"氏名(名)"`
	Nickname  string `validate:"omitempty,min=5,max=20" ja:"ニックネーム"`
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

	// deleteAfterLoginHook(w, AFTER_LOGIN_HOOK_COOKIE_KEY_SETTINGS_PROFILE_UPDATE)

	// // セッションが privileged_session_max_age を過ぎていた場合、ログイン画面へリダイレクト（再ログインの強制）
	// if session.NeedLoginWhenPrivilegedAccess() {
	// 	err := saveAfterLoginHook(w, afterLoginHook{
	// 		Operation: AFTER_LOGIN_HOOK_OPERATION_UPDATE_PROFILE,
	// 		Params:    params,
	// 	}, AFTER_LOGIN_HOOK_COOKIE_KEY_SETTINGS_PROFILE_UPDATE)
	// 	if err != nil {
	// 		tmplErr := pkgVars.tmpl.ExecuteTemplate(w, "my/profile/_form.html", viewParameters(session, r, map[string]any{
	// 			"SettingsFlowID": reqParams.flowID,
	// 			"CsrfToken":      reqParams.csrfToken,
	// 			"ErrorMessages":  []string{"Error"},
	// 			"Email":          params.Email,
	// 			"Firstname":      params.Firstname,
	// 			"Lastname":       params.Lastname,
	// 			"Nickname":       params.Nickname,
	// 			"Birthdate":      params.Birthdate,
	// 		}))
	// 		if tmplErr != nil {
	// 			slog.ErrorContext(ctx, tmplErr.Error())
	// 		}
	// 	} else {
	// 		returnTo := url.QueryEscape("/my/profile")
	// 		slog.InfoContext(ctx, returnTo)
	// 		redirect(w, r, fmt.Sprintf("/auth/login?return_to=%s", returnTo))
	// 	}
	// 	return
	// }

	kratosResp, err := p.d.Kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: params.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken: params.CsrfToken,
			Method:    "profile",
			Traits:    makeTraitsForUpdateSettings(session, params),
		},
	})
	if err != nil {
		myProfileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	setCookie(w, kratosResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	topIndexView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}
