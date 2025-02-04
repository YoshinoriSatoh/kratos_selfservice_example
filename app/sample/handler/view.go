package handler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
	"github.com/go-playground/validator/v10"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

const (
	// Auth login
	TPL_AUTH_LOGIN_INDEX         = "auth/login/index.html"
	TPL_AUTH_LOGIN_PASSWORD_FORM = "auth/login/_password_form.html"
	TPL_AUTH_LOGIN_PASSKEY_FORM  = "auth/login/_passkey_form.html"
	TPL_AUTH_LOGIN_TOTP_FORM     = "auth/login/_totp_form.html"
	TPL_AUTH_LOGIN_CODE          = "auth/login/code.html"
	TPL_AUTH_LOGIN_CODE_FORM     = "auth/login/_code_form.html"
	TPL_AUTH_LOGIN_MFA           = "auth/login/mfa.html"
	TPL_AUTH_LOGIN_TOTP          = "auth/login/totp.html"

	// Auth recovery
	TPL_AUTH_RECOVERY_INDEX     = "auth/recovery/index.html"
	TPL_AUTH_RECOVERY_CODE      = "auth/recovery/code.html"
	TPL_AUTH_RECOVERY_FORM      = "auth/recovery/_form.html"
	TPL_AUTH_RECOVERY_CODE_FORM = "auth/recovery/_code_form.html"

	// Auth registration
	TPL_AUTH_REGISTRATION_INDEX                    = "auth/registration/index.html"
	TPL_AUTH_REGISTRATION_PROFILE_FORM             = "auth/registration/_profile_form.html"
	TPL_AUTH_REGISTRATION_CREDENTIAL               = "auth/registration/credential.html"
	TPL_AUTH_REGISTRATION_CREDENTIAL_PASSWORD_FORM = "auth/registration/_credential_password_form.html"
	TPL_AUTH_REGISTRATION_CREDENTIAL_PASSKEY_FORM  = "auth/registration/_credential_passkey_form.html"

	// Auth verification
	TPL_AUTH_VERIFICATION_INDEX     = "auth/verification/index.html"
	TPL_AUTH_VERIFICATION_FORM      = "auth/verification/_form.html"
	TPL_AUTH_VERIFICATION_CODE      = "auth/verification/code.html"
	TPL_AUTH_VERIFICATION_CODE_FORM = "auth/verification/_code_form.html"

	// My pages
	TPL_MY_INDEX         = "my/index.html"
	TPL_MY_PROFILE       = "my/profile.html"
	TPL_MY_PROFILE_FORM  = "my/_profile_form.html"
	TPL_MY_PASSWORD      = "my/password.html"
	TPL_MY_PASSWORD_FORM = "my/_password_form.html"
	TPL_MY_TOTP          = "my/totp.html"
	TPL_MY_TOTP_FORM     = "my/_totp_form.html"

	// Top pages
	TPL_TOP_INDEX = "top/index.html"

	// Item
	TPL_ITEM_DETAIL                = "item/detail.html"
	TPL_ITEM_PURCHASE              = "item/purchase.html"
	TPL_ITEM_PURCHASE_CONFIRM      = "item/_purchase_confirm.html"
	TPL_ITEM_PURCHASE_COMPLETE     = "item/_purchase_complete.html"
	TPL_ITEM_PURCHASE_WITHOUT_AUTH = "item/_purchase_without_auth.html"
)

// ---------------------- msg ----------------------

type MsgType string

const (
	MSG_TYPE_SUCCESS = MsgType("success")
	MSG_TYPE_INFO    = MsgType("info")
	MSG_TYPE_WARNING = MsgType("warning")
	MSG_TYPE_ERROR   = MsgType("error")
)

type msg struct {
	MsgType MsgType
	Message string
}

// ---------------------- view ----------------------
type view struct {
	Path   string         `json:"path"`
	Params map[string]any `json:"params"`
	// viewError
}

func newView(path string) *view {
	v := &view{
		Path:   path,
		Params: map[string]any{},
	}
	return v
}

func (v *view) render(w http.ResponseWriter, r *http.Request, session *kratos.Session) error {
	v.Params["CurrentPath"] = r.URL.Path
	if isAuthenticated(session) {
		v.Params["IsAuthenticated"] = true
		v.Params["Navbar"] = session.Identity.Traits.ToMap()
	} else {
		v.Params["IsAuthenticated"] = false
	}
	err := pkgVars.tmpl.ExecuteTemplate(w, v.Path, v.Params)
	if err != nil {
		slog.Error(err.Error())
	}
	return err
}

func (v *view) addParams(p map[string]any) *view {
	maps.Copy(v.Params, p)
	return v
}

func (v *view) addMessage(msg string) *view {
	messages := v.Params["Messages"]
	messages = append(messages.([]string), msg)
	maps.Copy(v.Params, map[string]any{
		"Messages": messages,
	})
	return v
}

func (v *view) toQueryParam() string {
	jsonStr, err := json.Marshal(*v)
	if err != nil {
		slog.Error("json Marshal error in view", "err", err)
	}
	return base64.URLEncoding.EncodeToString(jsonStr)
}

func viewFromQueryParam(base64str string) *view {
	var v view
	jsonStr, err := base64.URLEncoding.DecodeString(base64str)
	if err != nil {
		slog.Error("json Marshal error in view", "err", err)
	}
	json.Unmarshal([]byte(jsonStr), &v)
	return &v
}

func addCookies(w http.ResponseWriter, cookie []string) {
	for _, v := range cookie {
		w.Header().Add("Set-Cookie", v)
	}
}

// func setHeadersForReplaceBody(w http.ResponseWriter, pushUrl string) {
// 	w.Header().Set("HX-Push-Url", pushUrl)
// 	w.Header().Set("HX-Retarget", "body")
// 	w.Header().Set("HX-Reswap", "innerHTML")
// }

type validationFieldError struct {
	Tag     string
	Message string
}

func (v *view) setValidationFieldError(err error) *view {
	var validastionErrors validator.ValidationErrors
	if errors.As(err, &validastionErrors) {
		fieldsErrors := make(map[string]any)
		for _, err := range err.(validator.ValidationErrors) {
			var msg string
			if err.ActualTag() == "date" {
				msg = "正しい日付を入力してください"
			} else {
				msg = err.Translate(pkgVars.trans)
			}
			fieldsErrors[err.StructField()] = validationFieldError{
				Tag:     err.ActualTag(),
				Message: msg,
			}
		}
		v.addParams(map[string]any{
			"ValidationFieldError": fieldsErrors,
		})
	}
	return v
}

func (v *view) setKratosMsg(err error) *view {
	var genericError kratos.GenericError
	var messages []msg

	if errors.As(err, &genericError) {
		messages = []msg{kratosGenericErrorMessage(err.(kratos.ErrorGeneric).Err)}
	}

	var errorGeneric kratos.ErrorGeneric
	if errors.As(err, &errorGeneric) {
		messages = []msg{kratosGenericErrorMessage(err.(kratos.ErrorGeneric).Err)}
	}

	var errorBrowserLocationChangeRequired kratos.ErrorBrowserLocationChangeRequired
	if errors.As(err, &errorBrowserLocationChangeRequired) {
		messages = []msg{kratosGenericErrorMessage(err.(kratos.ErrorBrowserLocationChangeRequired).Err)}
	}

	var kratosErrorUiMessages kratos.ErrorUiMessages
	if errors.As(err, &kratosErrorUiMessages) {
		messages = kratosUiMessages(err.(kratos.ErrorUiMessages))
	}

	v.addParams(map[string]any{
		"Messages": messages,
	})

	return v
}

func kratosGenericErrorMessage(genericError kratos.GenericError) msg {
	message, err := pkgVars.loc.Localize(&i18n.LocalizeConfig{
		MessageID: fmt.Sprintf("ERR_KRATOS_%s", strings.ToUpper(genericError.ID)),
	})
	if err != nil {
		slog.Error("kratosGenericErrorToViewError", "LocalizeError", err)
		message, _ = pkgVars.loc.Localize(&i18n.LocalizeConfig{
			MessageID: "ERR_FALLBACK",
		})
	}
	return msg{
		MsgType: MSG_TYPE_ERROR,
		Message: message,
	}
}

func kratosUiMessages(uiMessages kratos.ErrorUiMessages) []msg {
	var messages []msg
	for _, v := range uiMessages {
		message, err := pkgVars.loc.Localize(&i18n.LocalizeConfig{
			MessageID:    fmt.Sprintf("ERR_KRATOS_UI_%s", strconv.Itoa(int(v.ID))),
			TemplateData: v.Context,
		})
		if err != nil {
			slog.Error("kratosUiMessagesToViewError", "LocalizeError", err)
			message, _ := pkgVars.loc.Localize(&i18n.LocalizeConfig{
				MessageID:    "ERR_FALLBACK",
				TemplateData: v.Context,
			})
			messages = append(messages, msg{
				MsgType: MSG_TYPE_ERROR,
				Message: message,
			})
			continue
		}
		messages = append(messages, msg{
			MsgType: MSG_TYPE_ERROR,
			Message: message,
		})
	}

	return messages
}

func redirect(w http.ResponseWriter, r *http.Request, redirectUrl string, excludeQueriesInPushUrl []string) {
	// Parse the redirect URL
	parsedURL, err := url.Parse(redirectUrl)
	if err != nil {
		slog.Error("Failed to parse redirect URL", "error", err)
		return
	}

	// Get query parameters
	queryParams := parsedURL.Query()
	pushUrl := parsedURL.Path

	// Build push URL without excluded queries
	if len(queryParams) > 0 {
		filteredQuery := make(url.Values)
		for key, values := range queryParams {
			// Check if the query parameter should be excluded
			shouldExclude := false
			for _, excludeKey := range excludeQueriesInPushUrl {
				if key == excludeKey {
					shouldExclude = true
					break
				}
			}
			if !shouldExclude {
				filteredQuery[key] = values
			}
		}

		// Add filtered query parameters to push URL if any exist
		if len(filteredQuery) > 0 {
			pushUrl = fmt.Sprintf("%s?%s", pushUrl, filteredQuery.Encode())
		}
	}

	w.Header().Set("HX-Push-Url", pushUrl)
	w.Header().Set("HX-Redirect", redirectUrl)
}
