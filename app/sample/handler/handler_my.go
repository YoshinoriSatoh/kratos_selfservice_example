package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
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
	FlowID         string `form:"flow" validate:"omitempty,uuid4"`
	Information    string `form:"information" validate:"omitempty"`
	SavedEmail     string `form:"email" validate:"omitempty"`
	SavedFirstname string `form:"firstname" validate:"omitempty"`
	SavedLastname  string `form:"lastname" validate:"omitempty"`
	SavedNickname  string `form:"nickname" validate:"omitempty"`
	SavedBirthdate string `form:"birthdate" validate:"omitempty"`
}

// Handler GET /my/profile
func (p *Provider) handleGetMyProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// prepare views
	profileView := newView(TPL_MY_PROFILE)

	// bind and validate request parameters
	var reqParams getMyProfileRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handleGetMyProfile bind request error", "err", err)
		profileView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// create or get settings Flow
	response, kratosResponseHeader, _, err := kratos.CreateOrGetSettingsFlow(ctx, kratos.CreateOrGetSettingsFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		slog.ErrorContext(ctx, "create or get settings flow error", "err", err)
		profileView.setKratosMsg(err).render(w, r, session)
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
		"SettingsFlowID": response.SettingsFlow.FlowID,
		"CsrfToken":      response.SettingsFlow.CsrfToken,
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
	FlowID    string `form:"flow" validate:"required,uuid4"`
	CsrfToken string `form:"csrf_token" validate:"required"`
	Email     string `form:"email" validate:"omitempty,email" ja:"メールアドレス"`
	Firstname string `form:"firstname" validate:"omitempty" ja:"氏名(性)"`
	Lastname  string `form:"lastname" validate:"omitempty" ja:"氏名(名)"`
	Nickname  string `form:"nickname" validate:"omitempty" ja:"ニックネーム"`
	Birthdate string `form:"birthdate" validate:"omitempty,date" ja:"生年月日"`
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

	// prepare views
	profileFormView := newView(TPL_MY_PROFILE_FORM)
	loginIndexView := newView(TPL_AUTH_LOGIN_INDEX)
	loginCodeView := newView(TPL_AUTH_LOGIN_CODE)
	verificationCodeView := newView(TPL_AUTH_VERIFICATION_CODE)
	topIndexView := newView(TPL_TOP_INDEX)

	// bind and validate request parameters
	var reqParams postMyProfileRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostMyProfile bind request error", "err", err)
		profileFormView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// update settings flow
	kratosResp, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: reqParams.FlowID,
		Header: kratosRequestHeader,
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken: reqParams.CsrfToken,
			Method:    "profile",
			Traits:    makeTraitsForUpdateSettings(session, &reqParams),
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
					Traits:    makeTraitsForUpdateSettings(session, &reqParams),
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
					slog.ErrorContext(ctx, "create login flow error", "err", err)
					profileFormView.setKratosMsg(err).render(w, r, session)
					return
				}

				// render login form
				addCookies(w, createLoginFlowResp.Header.Cookie)
				redirect(w, r, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID), []string{})
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
					profileFormView.setKratosMsg(err).render(w, r, session)
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
					profileFormView.setKratosMsg(err).render(w, r, session)
					return
				}

				addCookies(w, createLoginFlowResp.Header.Cookie)
				redirect(w, r, fmt.Sprintf("/auth/login/code?flow=%s", createLoginFlowResp.LoginFlow.FlowID), []string{})
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
		profileFormView.setKratosMsg(err).render(w, r, session)
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
			profileFormView.setKratosMsg(err).render(w, r, session)
			return
		}

		createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		if err != nil {
			profileFormView.setKratosMsg(err).render(w, r, session)
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
		redirect(w, r, fmt.Sprintf("/auth/verification/code?flow=%s", getVerificationFlowResp.VerificationFlow.FlowID), []string{})
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
	redirect(w, r, "/", []string{})
	topIndexView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// GET /my/password
// --------------------------------------------------------------------------
type getMyPasswordRequestParams struct {
	FlowID string `form:"flow" validate:"omitempty,uuid4"`
}

// Handler GET /my/password
func (p *Provider) handleGetMyPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// prepare views
	passwordView := newView(TPL_MY_PASSWORD)

	// bind and validate request parameters
	var reqParams getMyPasswordRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handleGetMyPassword bind request error", "err", err)
		passwordView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// create or get settings Flow
	response, kratosResponseHeader, _, err := kratos.CreateOrGetSettingsFlow(ctx, kratos.CreateOrGetSettingsFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		slog.ErrorContext(ctx, "create or get settings flow error", "err", err)
		passwordView.setKratosMsg(err).render(w, r, session)
		return
	}

	// add cookies to the request header
	addCookies(w, kratosResponseHeader.Cookie)

	// render page
	passwordView.addParams(map[string]any{
		"SettingsFlowID": response.SettingsFlow.FlowID,
		"CsrfToken":      response.SettingsFlow.CsrfToken,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /my/password
// --------------------------------------------------------------------------
type postMyPasswordRequestParams struct {
	FlowID               string `form:"flow" validate:"uuid4"`
	CsrfToken            string `form:"csrf_token" validate:"required"`
	Password             string `form:"password" validate:"required" ja:"パスワード"`
	PasswordConfirmation string `form:"password_confirmation" validate:"required" ja:"パスワード確認"`
}

// Handler POST /my/password
func (p *Provider) handlePostMyPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

	// prepare views
	passwordFormView := newView(TPL_MY_PASSWORD_FORM)
	loginIndexView := newView(TPL_AUTH_LOGIN_INDEX)
	loginCodeView := newView(TPL_AUTH_LOGIN_CODE)

	// bind and validate request parameters
	var reqParams postMyPasswordRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostMyPassword bind request error", "err", err)
		passwordFormView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// validate password confirmation
	if reqParams.Password != reqParams.PasswordConfirmation {
		passwordFormView.setValidationFieldError(fmt.Errorf("パスワードとパスワード確認が一致しません")).render(w, r, session)
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
					slog.ErrorContext(ctx, "create login flow error", "err", err)
					passwordFormView.setKratosMsg(err).render(w, r, session)
					return
				}

				// render login form
				addCookies(w, createLoginFlowResp.Header.Cookie)
				redirect(w, r, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID), []string{})
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
					passwordFormView.setKratosMsg(err).render(w, r, session)
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
					passwordFormView.setKratosMsg(err).render(w, r, session)
					return
				}

				addCookies(w, createLoginFlowResp.Header.Cookie)
				redirect(w, r, fmt.Sprintf("/auth/login/code?flow=%s", createLoginFlowResp.LoginFlow.FlowID), []string{})
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
		passwordFormView.setKratosMsg(err).render(w, r, session)
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
		passwordFormView.setKratosMsg(err).render(w, r, session)
		return
	}

	// render password page
	addCookies(w, kratosResp.Header.Cookie)
	redirect(w, r, "/my/password", []string{})
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
	FlowID string `form:"flow" validate:"omitempty,uuid4"`
}

// Handler GET /my/totp
func (p *Provider) handleGetMyTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// prepare views
	totpView := newView(TPL_MY_TOTP)

	// bind and validate request parameters
	var reqParams getMyTotpRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handleGetMyTotp bind request error", "err", err)
		totpView.setValidationFieldError(err).render(w, r, session)
		return
	}

	// create or get settings Flow
	response, kratosResponseHeader, _, err := kratos.CreateOrGetSettingsFlow(ctx, kratos.CreateOrGetSettingsFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		slog.ErrorContext(ctx, "create or get settings flow error", "err", err)
		totpView.setKratosMsg(err).render(w, r, session)
		return
	}

	// add cookies to the request header
	addCookies(w, kratosResponseHeader.Cookie)

	// render page
	totpView.addParams(map[string]any{
		"SettingsFlowID": response.SettingsFlow.FlowID,
		"CsrfToken":      response.SettingsFlow.CsrfToken,
		"TotpQR":         "src=" + response.SettingsFlow.TotpQR,
		"TotpRegisted":   response.SettingsFlow.TotpUnlink,
	}).render(w, r, session)
}

// --------------------------------------------------------------------------
// POST /my/totp
// --------------------------------------------------------------------------
type postMyTotpRequestParams struct {
	FlowID     string `form:"flow" validate:"required,uuid4"`
	CsrfToken  string `form:"csrf_token" validate:"required"`
	TotpCode   string `form:"totp_code" validate:"omitempty" ja:"認証コード"`
	TotpUnlink string `form:"totp_unlink" validate:"omitempty"`
}

// Handler POST /my/totp
func (p *Provider) handlePostMyTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)

	// prepare views
	totpFormView := newView(TPL_MY_TOTP_FORM)
	loginIndexView := newView(TPL_AUTH_LOGIN_INDEX)
	loginCodeView := newView(TPL_AUTH_LOGIN_CODE)

	// bind and validate request parameters
	var reqParams postMyTotpRequestParams
	if err := bindAndValidateRequest(r, &reqParams); err != nil {
		slog.Error("handlePostMyTotp bind request error", "err", err)
		totpFormView.setValidationFieldError(err).render(w, r, session)
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
					slog.ErrorContext(ctx, "create login flow error", "err", err)
					totpFormView.setKratosMsg(err).render(w, r, session)
					return
				}

				// render login form
				addCookies(w, createLoginFlowResp.Header.Cookie)
				redirect(w, r, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID), []string{})
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
					totpFormView.setKratosMsg(err).render(w, r, session)
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
					totpFormView.setKratosMsg(err).render(w, r, session)
					return
				}

				addCookies(w, createLoginFlowResp.Header.Cookie)
				redirect(w, r, fmt.Sprintf("/auth/login/code?flow=%s", createLoginFlowResp.LoginFlow.FlowID), []string{})
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
		totpFormView.setKratosMsg(err).render(w, r, session)
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
		totpFormView.setKratosMsg(err).render(w, r, session)
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
