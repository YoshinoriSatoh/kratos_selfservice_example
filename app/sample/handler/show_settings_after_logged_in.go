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

type showSettingsAfterLoggedInParams struct {
	FlowID string
	Method string
}

func (p *showSettingsAfterLoggedInParams) toString() string {
	jsonStr, err := json.Marshal(*p)
	if err != nil {
		slog.Error("showSettingsAfterLoggedInParams.toString", "json Marshal error", err)
	}
	return base64.URLEncoding.EncodeToString(jsonStr)
}

func showSettingsAfterLoggedInParamsFromString(base64str string) showSettingsAfterLoggedInParams {
	var h showSettingsAfterLoggedInParams
	jsonStr, err := base64.URLEncoding.DecodeString(base64str)
	if err != nil {
		slog.Error("showSettingsAfterLoggedInParamsFromString", "json Marshal error", err)
	}
	json.Unmarshal([]byte(jsonStr), &h)
	return h
}

func showSettingsAfterLoggedIn(ctx context.Context, w http.ResponseWriter, r *http.Request, session *kratos.Session, kratosRequestHeader kratos.KratosRequestHeader, params showSettingsAfterLoggedInParams) {
	slog.InfoContext(ctx, "showSettingsPasswordAfterLoggedIn", "params", params)

	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_SETTINGS_PASSWORD_DEFAULT",
	}))
	getSettingsFlowResp, _, err := kratos.GetSettingsFlow(ctx, kratos.GetSettingsFlowRequest{
		FlowID: params.FlowID,
		Header: kratosRequestHeader,
	})
	if err != nil {
		slog.ErrorContext(ctx, "showSettingsAfterLoggedIn", "err", err)
		newView("auth/recovery/_code_form.html").addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
	}

	addCookies(w, getSettingsFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/my/password?flow=%s", params.FlowID))
	newView("my/password.html").addParams(map[string]any{
		"SettingsFlowID": params.FlowID,
		"CsrfToken":      getSettingsFlowResp.SettingsFlow.CsrfToken,
	}).render(w, r, session)

}
