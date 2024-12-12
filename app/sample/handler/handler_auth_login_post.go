package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /auth/login
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthLogin
type postAuthLoginRequestParams struct {
	FlowID     string `validate:"uuid4"`
	CsrfToken  string `validate:"required"`
	Identifier string `validate:"required,email" ja:"メールアドレス"`
	Password   string `validate:"required" ja:"パスワード"`
	Render     string
	Hook       string
}

// Extract parameters from http request
func newPostAuthLoginRequestParams(r *http.Request) *postAuthLoginRequestParams {
	return &postAuthLoginRequestParams{
		FlowID:     r.URL.Query().Get("flow"),
		Render:     r.PostFormValue("render"),
		Hook:       r.PostFormValue("hook"),
		CsrfToken:  r.PostFormValue("csrf_token"),
		Identifier: r.PostFormValue("identifier"),
		Password:   r.PostFormValue("password"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthLoginRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"LoginFlowID": p.FlowID,
		"Render":      p.Render,
		"Hook":        p.Hook,
		"CsrfToken":   p.CsrfToken,
		"Identifier":  p.Identifier,
		"Password":    p.Password,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthLoginRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type getAuthLoginPostViews struct {
	index *view
}

// collect rendering data and validate request parameters.
func prepareGetAuthLoginPost(w http.ResponseWriter, r *http.Request) (*postAuthLoginRequestParams, getAuthLoginPostViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_LOGIN_DEFAULT",
	}))
	reqParams := newPostAuthLoginRequestParams(r)
	views := getAuthLoginPostViews{
		index: newView("auth/login/_form.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.index.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := prepareGetAuthLoginPost(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "prepareGetAuthLoginPost failed", "err", err)
		return
	}

	// prepare views
	topIndexView := newView("top/index.html").addParams(reqParams.toViewParams())

	// update login flow
	updateLoginFlowResp, err := kratos.UpdateLoginFlow(ctx, kratos.UpdateLoginFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateLoginFlowRequestBody{
			Method:     "password",
			CsrfToken:  reqParams.CsrfToken,
			Identifier: reqParams.Identifier,
			Password:   reqParams.Password,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update login flow error", "err", err)
		views.index.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// update session
	session = &updateLoginFlowResp.Session

	if reqParams.Hook != "" {
		h := hookFromQueryParam(reqParams.Hook)
		if h.HookID == HookIDUpdateSettingsProfile {
			kratosRequestHeader := makeDefaultKratosRequestHeader(r)
			kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, updateLoginFlowResp.Header.Cookie)
			kratosResp, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
				FlowID: h.UpdateSettingsProfileParams.FlowID,
				Header: kratosRequestHeader,
				Body: kratos.UpdateSettingsFlowRequestBody{
					CsrfToken: reqParams.CsrfToken,
					Method:    "profile",
					Traits:    h.UpdateSettingsProfileParams.Traits,
				},
			})
			if err != nil {
				views.index.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
				return
			}
			if kratosResp.VerificationFlowID != "" {
				// transition to verification flow from settings flow
				// Transferring cookies from update registration flow response
				kratosRequestHeader := makeDefaultKratosRequestHeader(r)
				kratosRequestHeader.Cookie = mergeProxyResponseCookies(kratosRequestHeader.Cookie, kratosResp.Header.Cookie)
				// get verification flow
				getVerificationFlowResp, err := kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
					FlowID: kratosResp.VerificationFlowID,
					Header: kratosRequestHeader,
				})
				if err != nil {
					slog.DebugContext(ctx, "get verification error", "err", err.Error())
					views.index.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
					Header: kratosRequestHeader,
				})

				createSettingsFlowResp, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
					Header: makeDefaultKratosRequestHeader(r),
				})
				if err != nil {
					views.index.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
					return
				}

				// for re-render profile form
				year, month, day := parseDate(h.UpdateSettingsProfileParams.Traits.Birthdate)
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
				newView("auth/verification/code.html").addParams(reqParams.toViewParams()).addParams(map[string]any{
					"VerificationFlowID": getVerificationFlowResp.VerificationFlow.FlowID,
					"CsrfToken":          getVerificationFlowResp.VerificationFlow.CsrfToken,
					"IsUsedFlow":         getVerificationFlowResp.VerificationFlow.IsUsedFlow(),
					"Render":             myProfileIndexView.toQueryParam(),
				}).render(w, r, session)
				return
			}
			whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
				Header: kratosRequestHeader,
			})

			createSettingsFlowResp, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
				Header: makeDefaultKratosRequestHeader(r),
			})
			if err != nil {
				views.index.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
				return
			}
			year, month, day := parseDate(h.UpdateSettingsProfileParams.Traits.Birthdate)
			addCookies(w, updateLoginFlowResp.Header.Cookie)
			setHeadersForReplaceBody(w, "/my/profile")
			newView("my/profile/index.html").addParams(map[string]any{
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
			}).render(w, r, whoamiResp.Session)
		}
		return
	}

	if reqParams.Render != "" {
		v := viewFromQueryParam(reqParams.Render)
		setHeadersForReplaceBody(w, v.Path)
		viewFromQueryParam(reqParams.Render).render(w, r, session)
		return
	}

	addCookies(w, updateLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/")
	topIndexView.addParams(map[string]any{
		"Items": items,
	}).render(w, r, session)
}
