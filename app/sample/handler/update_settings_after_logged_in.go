package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

type updateSettingsAfterLoggedInParams struct {
	FlowID   string
	Method   string
	Traits   kratos.Traits
	Password string
	TotpCode string
}

func (p *updateSettingsAfterLoggedInParams) toString() string {
	jsonStr, err := json.Marshal(*p)
	if err != nil {
		slog.Error("updateSettingsAfterLoggedInParams.toString", "json Marshal error", err)
	}
	return base64.URLEncoding.EncodeToString(jsonStr)
}

func updateSettingsAfterLoggedInParamsFromString(base64str string) updateSettingsAfterLoggedInParams {
	var h updateSettingsAfterLoggedInParams
	jsonStr, err := base64.URLEncoding.DecodeString(base64str)
	if err != nil {
		slog.Error("updateSettingsAfterLoggedInParamsFromString", "json Marshal error", err)
	}
	json.Unmarshal([]byte(jsonStr), &h)
	return h
}

func updateSettingsAfterLoggedIn(ctx context.Context, w http.ResponseWriter, r *http.Request, session *kratos.Session, kratosRequestHeaderAfterLoggedIn kratos.KratosRequestHeader, params updateSettingsAfterLoggedInParams) {
	if params.Method == "profile" {
		updateSettingsProfileAfterLoggedIn(ctx, w, r, session, kratosRequestHeaderAfterLoggedIn, params)
	} else if params.Method == "password" {
		updateSettingsPasswordAfterLoggedIn(ctx, w, r, session, kratosRequestHeaderAfterLoggedIn, params)
	} else if params.Method == "totp" {
		updateSettingsTotpAfterLoggedIn(ctx, w, r, session, kratosRequestHeaderAfterLoggedIn, params)
	}
}

func updateSettingsProfileAfterLoggedIn(ctx context.Context, w http.ResponseWriter, r *http.Request, session *kratos.Session, kratosRequestHeaderAfterLoggedIn kratos.KratosRequestHeader, params updateSettingsAfterLoggedInParams) {
	slog.InfoContext(ctx, "updateSettingsProfileAfterLoggedIn", "params", params)

	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
	}))
	loginCodeView := newView("auth/login/code.html")

	getSettingsFlowResp, kratosRequestHeaderSettingsFlow, err := kratos.GetSettingsFlow(ctx, kratos.GetSettingsFlowRequest{
		FlowID: params.FlowID,
		Header: kratosRequestHeaderAfterLoggedIn,
	})
	if err != nil {
		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	kratosResp, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: params.FlowID,
		Header: kratos.MergeHeaderForRequests(kratosRequestHeaderAfterLoggedIn, kratosRequestHeaderSettingsFlow),
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken: getSettingsFlowResp.SettingsFlow.CsrfToken,
			Method:    "profile",
			Traits:    params.Traits,
		},
	})
	if err != nil {
		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	if kratosResp.VerificationFlowID != "" {
		// get verification flow
		getVerificationFlowResp, _, err := kratos.GetVerificationFlow(ctx, kratos.GetVerificationFlowRequest{
			FlowID: kratosResp.VerificationFlowID,
			Header: kratosReqHeaderForNext,
		})
		if err != nil {
			slog.ErrorContext(ctx, "get verification error", "err", err.Error())
			loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}

		whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
			Header: kratosReqHeaderForNext,
		})

		createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
			Header: makeDefaultKratosRequestHeader(r),
		})
		if err != nil {
			loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
			return
		}

		// for re-render profile form
		year, month, day := parseDate(params.Traits.Birthdate)
		myProfileIndexView := newView("my/profile.html").addParams(map[string]any{
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
		newView("auth/verification/code.html").addParams(map[string]any{
			"VerificationFlowID": getVerificationFlowResp.VerificationFlow.FlowID,
			"CsrfToken":          getVerificationFlowResp.VerificationFlow.CsrfToken,
			"IsUsedFlow":         getVerificationFlowResp.VerificationFlow.IsUsedFlow(),
			"Render":             myProfileIndexView.toQueryParam(),
		}).render(w, r, session)
		return
	}
	whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
		Header: kratosReqHeaderForNext,
	})

	createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	year, month, day := parseDate(params.Traits.Birthdate)
	addCookies(w, createSettingsFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/my/profile")
	newView("my/profile.html").addParams(map[string]any{
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

func updateSettingsPasswordAfterLoggedIn(ctx context.Context, w http.ResponseWriter, r *http.Request, session *kratos.Session, kratosRequestHeaderAfterLoggedIn kratos.KratosRequestHeader, params updateSettingsAfterLoggedInParams) {
	slog.InfoContext(ctx, "updateSettingsPasswordAfterLoggedIn", "params", params)

	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
	}))
	loginCodeView := newView("auth/login/code.html")

	getSettingsFlowResp, kratosRequestHeaderSettingsFlow, err := kratos.GetSettingsFlow(ctx, kratos.GetSettingsFlowRequest{
		FlowID: params.FlowID,
		Header: kratosRequestHeaderAfterLoggedIn,
	})
	if err != nil {
		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	_, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: params.FlowID,
		Header: kratos.MergeHeaderForRequests(kratosRequestHeaderAfterLoggedIn, kratosRequestHeaderSettingsFlow),
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken: getSettingsFlowResp.SettingsFlow.CsrfToken,
			Method:    "password",
			Password:  params.Password,
		},
	})
	if err != nil {
		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
		Header: kratosReqHeaderForNext,
	})

	createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	addCookies(w, createSettingsFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/my/password")
	newView("my/password.html").addParams(map[string]any{
		"SettingsTotpID": createSettingsFlowResp.SettingsFlow.FlowID,
		"Information":    "パスワードが設定されました。",
		"CsrfToken":      createSettingsFlowResp.SettingsFlow.CsrfToken,
	}).render(w, r, whoamiResp.Session)
}

func updateSettingsTotpAfterLoggedIn(ctx context.Context, w http.ResponseWriter, r *http.Request, session *kratos.Session, kratosRequestHeaderAfterLoggedIn kratos.KratosRequestHeader, params updateSettingsAfterLoggedInParams) {
	slog.InfoContext(ctx, "updateSettingsTotpAfterLoggedIn", "params", params)

	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PROFILE_DEFAULT",
	}))
	loginCodeView := newView("auth/login/code.html")

	getSettingsFlowResp, kratosRequestHeaderSettingsFlow, err := kratos.GetSettingsFlow(ctx, kratos.GetSettingsFlowRequest{
		FlowID: params.FlowID,
		Header: kratosRequestHeaderAfterLoggedIn,
	})
	if err != nil {
		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	_, kratosReqHeaderForNext, err := kratos.UpdateSettingsFlow(ctx, kratos.UpdateSettingsFlowRequest{
		FlowID: params.FlowID,
		Header: kratos.MergeHeaderForRequests(kratosRequestHeaderAfterLoggedIn, kratosRequestHeaderSettingsFlow),
		Body: kratos.UpdateSettingsFlowRequestBody{
			CsrfToken: getSettingsFlowResp.SettingsFlow.CsrfToken,
			Method:    "totp",
			TotpCode:  params.TotpCode,
		},
	})
	if err != nil {
		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	whoamiResp, _ := kratos.Whoami(ctx, kratos.WhoamiRequest{
		Header: kratosReqHeaderForNext,
	})

	createSettingsFlowResp, _, err := kratos.CreateSettingsFlow(ctx, kratos.CreateSettingsFlowRequest{
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		loginCodeView.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}
	addCookies(w, createSettingsFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, "/my/totp")
	newView("my/totp.html").addParams(map[string]any{
		"SettingsTotpID": createSettingsFlowResp.SettingsFlow.FlowID,
		"Information":    "認証アプリが設定されました。",
		"CsrfToken":      createSettingsFlowResp.SettingsFlow.CsrfToken,
		"TotpQR":         "src=" + createSettingsFlowResp.SettingsFlow.TotpQR,
		"TotpRegisted":   createSettingsFlowResp.SettingsFlow.TotpUnlink,
	}).render(w, r, whoamiResp.Session)
}
