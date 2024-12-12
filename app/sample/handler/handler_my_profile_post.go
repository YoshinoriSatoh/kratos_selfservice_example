package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

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
	form *view
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
		form: newView("my/profile/_form.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.form.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

// Handler POST /my/profile
func (p *Provider) handlePostMyProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetMyProfilePost(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetMyProfilePost failed", "err", err)
		return
	}

	// prepare views
	myProfileFormView := newView("my/profile/_form.html").addParams(reqParams.toViewParams())
	loginIndexView := newView("auth/login/index.html").addParams(reqParams.toViewParams())
	verificationCodeView := newView("auth/verification/code.html").addParams(reqParams.toViewParams())
	topIndexView := newView("top/index.html").addParams(reqParams.toViewParams())

	// update settings flow
	kratosRequestHeader := makeDefaultKratosRequestHeader(r)
	kratosResp, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: reqParams.FlowID,
		Header: kratosRequestHeader,
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken: reqParams.CsrfToken,
			Method:    "profile",
			Traits:    makeTraitsForUpdateSettings(session, reqParams),
		},
	})
	if err != nil {
		// render login form when session expired privileged_session_max_age, and re-render profile form.
		// redirect not use. htmx implementation policy.
		var errGeneric kratos.ErrorGeneric
		if errors.As(err, &errGeneric) && err.(kratos.ErrorGeneric).Err.ID == "session_refresh_required" {
			// create login flow
			// kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, kratosResp.Header.Cookie)
			kratosRequestHeader.Cookie = strings.Join(kratosResp.Header.Cookie, " ")
			createLoginFlowResp, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
				Header:  kratosRequestHeader,
				Refresh: true,
			})
			if err != nil {
				myProfileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
				return
			}

			// for re-render profile form
				year, month, day := parseDate(reqParams.Birthdate)
				myProfileIndexView := newView("my/profile/index.html").addParams(map[string]any{
					"SettingsFlowID": reqParams.FlowID,
					"Information":    "ログインされました。プロフィールを更新できます。",
					"CsrfToken":      reqParams.CsrfToken,
					"Email":          reqParams.Email,
					"Firstname":      reqParams.Firstname,
					"Lastname":       reqParams.Lastname,
					"Nickname":       reqParams.Nickname,
					"BirthdateYear":  year,
					"BirthdateMonth": month,
					"BirthdateDay":   day,
				})

			hook := &hook{
				HookID: HookIDUpdateSettingsProfile,
				UpdateSettingsProfileParams: HookParamsUpdateSettingsProfile{
					FlowID:    reqParams.FlowID,
					CsrfToken: reqParams.CsrfToken,
					Traits:    makeTraitsForUpdateSettings(session, reqParams),
				},
			}

			// render login form
			addCookies(w, createLoginFlowResp.Header.Cookie)
			setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
			loginIndexView.addParams(map[string]any{
				"LoginFlowID": createLoginFlowResp.LoginFlow.FlowID,
				"Information": "プロフィール更新のために再度ログインをお願いします。",
				"CsrfToken":   createLoginFlowResp.LoginFlow.CsrfToken,
				"Render":      myProfileIndexView.toQueryParam(),
				"Hook":        hook.toQueryParam(),
			}).render(w, r, session)
			return
		}

		// render form with error
		myProfileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	if kratosResp.VerificationFlowID != "" {
		// transition to verification flow from settings flow
		// kratosRequestHeader := makeDefaultKratosRequestHeader(r)
		kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, kratosResp.Header.Cookie)
		slog.DebugContext(ctx, "handlePostMyProfile", "kratosRequestHeader.Cookie", kratosRequestHeader.Cookie)
		// get verification flow
		getVerificationFlowResp, err := kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
			FlowID: kratosResp.VerificationFlowID,
			Header: kratosRequestHeader,
		})
		if err != nil {
			slog.DebugContext(ctx, "get verification error", "err", err.Error())
			myProfileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}

		whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
			Header: kratosRequestHeader,
		})

		createSettingsFlowResp, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		if err != nil {
			myProfileFormView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}

		// for re-render profile form
		year, month, day := parseDate(reqParams.Birthdate)
		myProfileIndexView := newView("my/profile/index.html").addParams(map[string]any{
			"SettingsFlowID": createSettingsFlowResp.SettingsFlow.FlowID,
			"Information":    "プロフィールが更新されました。",
			"CsrfToken":      createSettingsFlowResp.SettingsFlow.CsrfToken,
			"Email":          whoamiResp.Session.Identity.Traits.Email,
			"Firstname":      whoamiResp.Session.Identity.Traits.Firstname,
			"Lastname":       whoamiResp.Session.Identity.Traits.Lastname,
			"Nickname":       whoamiResp.Session.Identity.Traits.Nickname,
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
