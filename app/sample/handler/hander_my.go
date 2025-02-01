package handler

import (
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
// Handler GET /my
func (p *Provider) handleGetMy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// prepare views
	indexView := newView(TPL_MY_INDEX)

	// render page
	indexView.render(w, r, session)
}

// --------------------------------------------------------------------------
// GET /my/profile
// --------------------------------------------------------------------------
// Request parameters for handleGetMyProfile
type getMyProfileRequestParams struct {
	FlowID         string `validate:"omitempty,uuid4"`
	Information    string
	SavedEmail     string
	SavedFirstname string
	SavedLastname  string
	SavedNickname  string
	SavedBirthdate string
}

// Handler GET /my/profile
func (p *Provider) handleGetMyProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &getMyProfileRequestParams{
		FlowID:         r.URL.Query().Get("flow"),
		Information:    r.URL.Query().Get("information"),
		SavedEmail:     r.URL.Query().Get("email"),
		SavedFirstname: r.URL.Query().Get("firstname"),
		SavedLastname:  r.URL.Query().Get("lastname"),
		SavedNickname:  r.URL.Query().Get("nickname"),
		SavedBirthdate: r.URL.Query().Get("birthdate"),
	}

	// prepare views
	profileView := newView(TPL_MY_PROFILE)

	// create or get settings Flow
	settingsFlow, kratosResponseHeader, _, err := kratos.CreateOrGetSettingsFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
		}))
		profileView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// add cookies to the request header
	addCookies(w, kratosResponseHeader.Cookie)

	// render page
	year, month, day := parseDate(session.Identity.Traits.Birthdate)
	if reqParams.SavedBirthdate != "" {
		year, month, day = parseDate(reqParams.SavedBirthdate)
	}

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

	profileView.addParams(map[string]any{
		"SettingsFlowID": settingsFlow.FlowID,
		"CsrfToken":      settingsFlow.CsrfToken,
		"Information":    reqParams.Information,
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
type postMyProfileRequestParams struct {
	FlowID    string `validate:"required,uuid4"`
	CsrfToken string `validate:"required"`
	Email     string `validate:"omitempty,email" ja:"メールアドレス"`
	Firstname string `validate:"omitempty" ja:"氏名(性)"`
	Lastname  string `validate:"omitempty" ja:"氏名(名)"`
	Nickname  string `validate:"omitempty" ja:"ニックネーム"`
	Birthdate string `validate:"omitempty,date" ja:"生年月日"`
}

func makeTraitsForUpdateSettings(session *kratos.Session, params *postMyProfileRequestParams) kratos.Traits {
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
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

	// get request parameters
	reqParams := &postMyProfileRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Email:     r.PostFormValue("email"),
		Firstname: r.PostFormValue("firstname"),
		Lastname:  r.PostFormValue("lastname"),
		Nickname:  r.PostFormValue("nickname"),
		Birthdate: fmt.Sprintf("%s-%s-%s", r.PostFormValue("birthdate_year"), r.PostFormValue("birthdate_month"), r.PostFormValue("birthdate_day")),
	}

	// prepare views
	profileFormView := newView(TPL_MY_PROFILE_FORM)
	loginIndexView := newView(TPL_AUTH_LOGIN_INDEX)
	loginCodeView := newView(TPL_AUTH_LOGIN_CODE)
	verificationCodeView := newView(TPL_AUTH_VERIFICATION_CODE)
	topIndexView := newView(TPL_TOP_INDEX)

	// validate request parameters
	if err := pkgVars.validate.Struct(reqParams); err != nil {
		baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
		}))
		profileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
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
					baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
						MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
					}))
					profileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// render login form
				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				loginIndexView.addParams(map[string]any{
					"LoginFlowID":           createLoginFlowResp.LoginFlow.FlowID,
					"Information":           "プロフィール更新のために再度ログインをお願いします。",
					"CsrfToken":             createLoginFlowResp.LoginFlow.CsrfToken,
					"UpdateSettingsRequest": updateSettingsRequest.ToString(),
				}).render(w, r, session)
				return

			} else if kratos.SessionRequiredAal == kratos.Aal2 {
				// create and update login flow for aal2, send authentication code
				createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosRequestHeader,
					Aal:     kratos.Aal2,
					Refresh: true,
				})
				if err != nil {
					slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
					baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
						MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
					}))
					profileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
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
					baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
						MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
					}))
					profileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login/code?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				loginCodeView.addParams(map[string]any{
					"LoginFlowID":           createLoginFlowResp.LoginFlow.FlowID,
					"Information":           "プロフィール更新のために再度ログインをお願いします。",
					"CsrfToken":             createLoginFlowResp.LoginFlow.CsrfToken,
					"Identifier":            createLoginFlowResp.LoginFlow.CodeAddress,
					"UpdateSettingsRequest": updateSettingsRequest.ToString(),
				}).render(w, r, session)
				return
			}
		}

		// render form with error
		baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
		}))
		profileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
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
			baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
			}))
			profileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}

		createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		if err != nil {
			baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
			}))
			profileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}

		// for re-render profile form
		year, month, day := parseDate(reqParams.Birthdate)
		myProfileIndexView := newView(TPL_MY_PROFILE).addParams(map[string]any{
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
		verificationCodeView.addParams(map[string]any{
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
	topIndexView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// GET /my/password
// --------------------------------------------------------------------------
type getMyPasswordRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
}

// Handler GET /my/password
func (p *Provider) handleGetMyPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &getMyPasswordRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	passwordView := newView(TPL_MY_PASSWORD)

	// create or get settings Flow
	settingsFlow, kratosResponseHeader, _, err := kratos.CreateOrGetSettingsFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
		}))
		passwordView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// add cookies to the request header
	addCookies(w, kratosResponseHeader.Cookie)

	// render page
	passwordView.addParams(map[string]any{
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

// Handler POST /my/password
func (p *Provider) handlePostMyPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

	// get request parameters
	reqParams := &postMyPasswordRequestParams{
		FlowID:               r.URL.Query().Get("flow"),
		CsrfToken:            r.PostFormValue("csrf_token"),
		Password:             r.PostFormValue("password"),
		PasswordConfirmation: r.PostFormValue("password_confirmation"),
	}

	// prepare views
	passwordFormView := newView(TPL_MY_PASSWORD_FORM)
	loginIndexView := newView(TPL_AUTH_LOGIN_INDEX)
	loginCodeView := newView(TPL_AUTH_LOGIN_CODE)

	// validate request parameters
	if err := pkgVars.validate.Struct(reqParams); err != nil {
		baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
		}))
		passwordFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// validate password confirmation
	if reqParams.Password != reqParams.PasswordConfirmation {
		baseViewError := newViewError()
		baseViewError.validationFieldErrors["Password"] = validationFieldError{
			Tag:     "Password",
			Message: "パスワードとパスワード確認が一致しません",
		}
		passwordFormView.addParams(baseViewError.toViewParams()).render(w, r, session)
		return
	}

	// update settings flow
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
					baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
						MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
					}))
					passwordFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// render login form
				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				loginIndexView.addParams(map[string]any{
					"LoginFlowID":           createLoginFlowResp.LoginFlow.FlowID,
					"Information":           "パスワード更新のために再度ログインをお願いします。",
					"CsrfToken":             createLoginFlowResp.LoginFlow.CsrfToken,
					"UpdateSettingsRequest": updateSettingsRequest.ToString(),
				}).render(w, r, session)
				return

			} else if kratos.SessionRequiredAal == kratos.Aal2 {
				// create and update login flow for aal2, send authentication code
				createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosRequestHeader,
					Aal:     kratos.Aal2,
					Refresh: true,
				})
				if err != nil {
					slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
					baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
						MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
					}))
					passwordFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
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
					baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
						MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
					}))
					passwordFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login/code?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				loginCodeView.addParams(map[string]any{
					"LoginFlowID":           createLoginFlowResp.LoginFlow.FlowID,
					"Information":           "パスワード更新のために再度ログインをお願いします。",
					"CsrfToken":             createLoginFlowResp.LoginFlow.CsrfToken,
					"Identifier":            createLoginFlowResp.LoginFlow.CodeAddress,
					"UpdateSettingsRequest": updateSettingsRequest.ToString(),
				}).render(w, r, session)
				return
			}
		}

		// render form with error
		baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
		}))
		passwordFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
		Header: kratosReqHeaderForNext,
	})
	session = whoamiResp.Session

	// create new settings flow
	createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
		}))
		passwordFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render password page
	addCookies(w, kratosResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/my/password")
	passwordFormView.addParams(map[string]any{
		"SettingsFlowID": createSettingsFlowResp.SettingsFlow.FlowID,
		"Information":    "パスワードが設定されました。",
		"CsrfToken":      createSettingsFlowResp.SettingsFlow.CsrfToken,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// GET /my/totp
// --------------------------------------------------------------------------
type getMyTotpRequestParams struct {
	FlowID string `validate:"omitempty,uuid4"`
}

// Handler GET /my/totp
func (p *Provider) handleGetMyTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// get request parameters
	reqParams := &getMyTotpRequestParams{
		FlowID: r.URL.Query().Get("flow"),
	}

	// prepare views
	totpView := newView(TPL_MY_TOTP)

	// create or get settings Flow
	settingsFlow, kratosResponseHeader, _, err := kratos.CreateOrGetSettingsFlow(ctx, makeDefaultKratosRequestHeader(r), reqParams.FlowID)
	if err != nil {
		baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
		}))
		totpView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// add cookies to the request header
	addCookies(w, kratosResponseHeader.Cookie)

	// render page
	totpView.addParams(map[string]any{
		"SettingsFlowID": settingsFlow.FlowID,
		"CsrfToken":      settingsFlow.CsrfToken,
		"TotpQR":         "src=" + settingsFlow.TotpQR,
		"TotpRegisted":   settingsFlow.TotpUnlink,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /my/totp
// --------------------------------------------------------------------------
type postMyTotpRequestParams struct {
	FlowID     string `validate:"required,uuid4"`
	CsrfToken  string `validate:"required"`
	TotpCode   string `validate:"omitempty" ja:"認証コード"`
	TotpUnlink string `validate:"omitempty"`
}

// Handler POST /my/totp
func (p *Provider) handlePostMyTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

	// get request parameters
	reqParams := &postMyTotpRequestParams{
		FlowID:     r.URL.Query().Get("flow"),
		CsrfToken:  r.PostFormValue("csrf_token"),
		TotpCode:   r.PostFormValue("totp_code"),
		TotpUnlink: r.PostFormValue("totp_unlink"),
	}

	// prepare views
	totpFormView := newView(TPL_MY_TOTP_FORM)
	loginIndexView := newView(TPL_AUTH_LOGIN_INDEX)
	loginCodeView := newView(TPL_AUTH_LOGIN_CODE)

	// validate request parameters
	if err := pkgVars.validate.Struct(reqParams); err != nil {
		baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
		}))
		totpFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update settings flow
	kratosResp, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
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
					baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
						MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
					}))
					totpFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// render login form
				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				loginIndexView.addParams(map[string]any{
					"LoginFlowID":           createLoginFlowResp.LoginFlow.FlowID,
					"Information":           "認証アプリ設定のために再度ログインをお願いします。",
					"CsrfToken":             createLoginFlowResp.LoginFlow.CsrfToken,
					"UpdateSettingsRequest": updateSettingsRequest.ToString(),
				}).render(w, r, session)
				return

			} else if kratos.SessionRequiredAal == kratos.Aal2 {
				// create and update login flow for aal2, send authentication code
				createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
					Header:  kratosRequestHeader,
					Aal:     kratos.Aal2,
					Refresh: true,
				})
				if err != nil {
					slog.ErrorContext(ctx, "create login flow for aal2 error", "err", err)
					baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
						MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
					}))
					totpFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
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
					baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
						MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
					}))
					totpFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				addCookies(w, createLoginFlowResp.Header.Cookie)
				setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login/code?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
				loginCodeView.addParams(map[string]any{
					"LoginFlowID":           createLoginFlowResp.LoginFlow.FlowID,
					"Information":           "認証アプリ更新のために再度ログインをお願いします。",
					"CsrfToken":             createLoginFlowResp.LoginFlow.CsrfToken,
					"Identifier":            createLoginFlowResp.LoginFlow.CodeAddress,
					"UpdateSettingsRequest": updateSettingsRequest.ToString(),
				}).render(w, r, session)
				return
			}
		}

		// render form with error
		baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
		}))
		totpFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
		Header: kratosReqHeaderForNext,
	})
	session = whoamiResp.Session

	// create new settings flow
	createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
		}))
		totpFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render totp page
	addCookies(w, kratosResp.Header.Cookie)
	totpFormView.addParams(map[string]any{
		"SettingsFlowID": createSettingsFlowResp.SettingsFlow.FlowID,
		"CsrfToken":      createSettingsFlowResp.SettingsFlow.CsrfToken,
		"TotpQR":         "src=" + createSettingsFlowResp.SettingsFlow.TotpQR,
		"TotpRegisted":   createSettingsFlowResp.SettingsFlow.TotpUnlink,
	}).render(w, r, session)
}

func settingsView(method string, session *kratos.Session, settingsFlow kratos.SettingsFlow) *view {
	var settingsView *view
	if method == "profile" {
		year, month, day := parseDate(session.Identity.Traits.Birthdate)
		settingsView = newView(TPL_MY_PROFILE).addParams(map[string]any{
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
		settingsView = newView(TPL_MY_PASSWORD).addParams(map[string]any{
			"SettingsTotpID": settingsFlow.FlowID,
			"Information":    "パスワードが設定されました。",
			"CsrfToken":      settingsFlow.CsrfToken,
		})
	} else if method == "totp" {
		settingsView = newView(TPL_MY_TOTP).addParams(map[string]any{
			"SettingsTotpID": settingsFlow.FlowID,
			"Information":    "認証アプリが設定されました。",
			"CsrfToken":      settingsFlow.CsrfToken,
			"TotpQR":         "src=" + settingsFlow.TotpQR,
			"TotpRegisted":   settingsFlow.TotpUnlink,
		})
	}
	return settingsView
}
