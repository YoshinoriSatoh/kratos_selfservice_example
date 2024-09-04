package handler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"kratos_example/kratos"
	"log/slog"
	"maps"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// ---------------------- view ----------------------
type view struct {
	Path   string         `json:"path"`
	Params map[string]any `json:"params"`
	viewError
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

	if session != nil {
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

func (v *view) toQueryParam() string {
	jsonStr, err := json.Marshal(*v)
	if err != nil {
		slog.Error("json Marshal error in view", err)
	}
	return base64.URLEncoding.EncodeToString(jsonStr)
}

func viewFromQueryParam(base64str string) *view {
	var v view
	jsonStr, err := base64.URLEncoding.DecodeString(base64str)
	if err != nil {
		slog.Error("json Marshal error in view", err)
	}
	json.Unmarshal([]byte(jsonStr), &v)
	return &v
}

func setCookie(w http.ResponseWriter, cookie []string) {
	for _, v := range cookie {
		w.Header().Add("Set-Cookie", v)
	}
}

func setHeadersForReplaceBody(w http.ResponseWriter, pushUrl string) {
	w.Header().Set("HX-Push-Url", pushUrl)
	w.Header().Set("HX-Retarget", "body")
	w.Header().Set("HX-Reswap", "innerHTML")
}

func mergeProxyResponseCookies(reqCookie string, proxyResCookies []string) string {
	reqCookies := strings.Split(reqCookie, " ")
	slog.Debug("mergeProxyResponseCookies", "reqCookies", reqCookies)
	// for reqci, reqcv := range reqCookies {
	// 	slog.Debug("mergeProxyResponseCookies", "reqcv", reqcv)
	// reqcKey := strings.SplitN(reqcv, "=", 1)[0]
	// for _, prescv := range proxyResCookies {
	// slog.Debug("mergeProxyResponseCookies", "prescv", prescv)
	// prescKey := strings.SplitN(prescv, "=", 1)[0]
	// slog.Debug("mergeProxyResponseCookies", "prescKey", prescKey, "reqcKey", reqcKey)
	reqCookies = append(reqCookies, proxyResCookies...)
	// if prescKey == reqcKey {
	// 	fmt.Println("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
	// 	slog.Debug("mergeProxyResponseCookies", "reqci", reqci, "prescv", prescv)
	// 	reqCookies[reqci] = prescv
	// 	break
	// }
	// 	}
	// }

	return strings.Join(reqCookies, " ")
}

// ---------------------- viewError ----------------------
type viewError struct {
	validationFieldErrors map[string]validationFieldError
	messages              []msg
}

func (ve *viewError) hasError() bool {
	return len(ve.validationFieldErrors) > 0 || len(ve.messages) > 0
}

func (ve *viewError) toViewParams() map[string]any {
	return map[string]any{
		"ValidationFieldError": ve.validationFieldErrors,
		"Messages":             ve.messages,
	}
}

func newViewError() *viewError {
	return &viewError{
		validationFieldErrors: map[string]validationFieldError{},
		messages:              []msg{},
	}
}

func (ve *viewError) addMessage(message string) *viewError {
	ve.messages = append(ve.messages, msg{
		MsgType: MSG_TYPE_ERROR,
		Message: message,
	})
	return ve
}

func (ve *viewError) setMessages(messages []string) *viewError {
	for _, v := range messages {
		ve.messages = append(ve.messages, msg{
			MsgType: MSG_TYPE_ERROR,
			Message: v,
		})
	}
	return ve
}

func (ve *viewError) extract(err error) *viewError {
	var validastionErrors validator.ValidationErrors
	if errors.As(err, &validastionErrors) {
		fieldsErrors := make(map[string]validationFieldError)
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
		return &viewError{
			validationFieldErrors: fieldsErrors,
			messages:              []msg{},
		}
	}

	var genericError kratos.GenericError
	if errors.As(err, &genericError) {
		return kratosGenericErrorToViewError(err.(kratos.GenericError))
	}

	var errorGeneric kratos.ErrorGeneric
	if errors.As(err, &errorGeneric) {
		return kratosGenericErrorToViewError(err.(kratos.ErrorGeneric).Err)
	}

	var errorBrowserLocationChangeRequired kratos.ErrorBrowserLocationChangeRequired
	if errors.As(err, &errorBrowserLocationChangeRequired) {
		return kratosGenericErrorToViewError(err.(kratos.ErrorBrowserLocationChangeRequired).Err)
	}

	var kratosErrorUiMessages kratos.ErrorUiMessages
	if errors.As(err, &kratosErrorUiMessages) {
		return kratosUiMessagesToViewError(err.(kratos.ErrorUiMessages))
	}

	return &viewError{}
}

func kratosGenericErrorToViewError(genericError kratos.GenericError) *viewError {
	message, err := pkgVars.loc.Localize(&i18n.LocalizeConfig{
		MessageID: fmt.Sprintf("ERR_KRATOS_%s", strings.ToUpper(genericError.ID)),
	})
	if err != nil {
		slog.Error("kratosGenericErrorToViewError", "LocalizeError", err)
		message, _ := pkgVars.loc.Localize(&i18n.LocalizeConfig{
			MessageID: "ERR_FALLBACK",
		})
		return &viewError{
			validationFieldErrors: map[string]validationFieldError{},
			messages:              []msg{newErrorMsg(message)},
		}
	}
	return &viewError{
		validationFieldErrors: map[string]validationFieldError{},
		messages:              []msg{newErrorMsg(message)},
	}
}

func kratosUiMessagesToViewError(uiMessages kratos.ErrorUiMessages) *viewError {
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
			messages = append(messages, newErrorMsg(message))
			continue
		}
		messages = append(messages, newErrorMsg(message))
	}

	return &viewError{
		validationFieldErrors: map[string]validationFieldError{},
		messages:              messages,
	}
}

// ---------------------- validationFieldError(s) ----------------------
type validationFieldError struct {
	Tag     string
	Message string
}

type validationFieldErrors map[string]validationFieldError

func (e *validationFieldErrors) toViewParams() map[string]any {
	return map[string]any{
		"ValidationFieldError": e,
	}
}

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

func newErrorSuccess(message string) msg {
	return msg{
		MsgType: MSG_TYPE_SUCCESS,
		Message: "",
	}
}

func newErrorInfo(message string) msg {
	return msg{
		MsgType: MSG_TYPE_INFO,
		Message: "",
	}
}

func newErrorWarning(message string) msg {
	return msg{
		MsgType: MSG_TYPE_WARNING,
		Message: "",
	}
}

func newErrorMsg(message string) msg {
	return msg{
		MsgType: MSG_TYPE_ERROR,
		Message: message,
		// Message: pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		// 	MessageID: "ERR_FALLBACK",
		// }),
	}
}

func redirect(w http.ResponseWriter, r *http.Request, redirectTo string) {
	if r.Header.Get("HX-Request") == "true" {
		slog.Info("HX-Redirect")
		w.Header().Set("HX-Redirect", redirectTo)
		// w.Header().Set("HX-Location", redirectTo)
		// w.WriteHeader(http.StatusSeeOther)
	} else {
		slog.Info("Redirect")
		http.Redirect(w, r, redirectTo, http.StatusSeeOther)
	}
}
