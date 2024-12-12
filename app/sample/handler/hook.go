package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
)

type HookID string

const (
	HookIDUpdateSettingsProfile = HookID("update_settings_profile")
)

type hook struct {
	HookID                      HookID
	UpdateSettingsProfileParams HookParamsUpdateSettingsProfile
}

// func newHook(hookId HookID, params any) *hook {
// 	h := &hook{
// 		HookID: hookId,
// 		Params: params,
// 	}
// 	return h
// }

func (h *hook) toQueryParam() string {
	jsonStr, err := json.Marshal(*h)
	if err != nil {
		slog.Error("json Marshal error in view", err)
	}
	fmt.Println(string(jsonStr))
	return base64.URLEncoding.EncodeToString(jsonStr)
}

func hookFromQueryParam(base64str string) *hook {
	var h hook
	jsonStr, err := base64.URLEncoding.DecodeString(base64str)
	if err != nil {
		slog.Error("json Marshal error in hook", err)
	}
	json.Unmarshal([]byte(jsonStr), &h)
	return &h
}

type HookParamsUpdateSettingsProfile struct {
	FlowID    string
	CsrfToken string
	Traits    kratos.Traits
}
