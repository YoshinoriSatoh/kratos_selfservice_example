package handler

import (
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
	path   string
	params map[string]any
	viewError
}

func newView(path string) *view {
	v := &view{
		path: path,
	}
	return v
}

func (v *view) render(w http.ResponseWriter, r *http.Request, session *kratos.Session) error {
	v.params["CurrentPath"] = r.URL.Path

	if session != nil {
		v.params["IsAuthenticated"] = true
		v.params["Navbar"] = session.Identity.Traits.ToMap()
	} else {
		v.params["IsAuthenticated"] = false
	}

	err := pkgVars.tmpl.ExecuteTemplate(w, v.path, v.params)
	if err != nil {
		slog.Error(err.Error())
	}
	return err
}

func (v *view) addParams(p map[string]any) *view {
	maps.Copy(v.params, p)
	return v
}

func setHeadersForReplaceBody(w http.ResponseWriter, pushUrl string) {
	w.Header().Set("HX-Push-Url", pushUrl)
	w.Header().Set("HX-Retarget", "body")
	w.Header().Set("HX-Reswap", "innerHTML")
}

// ---------------------- viewError ----------------------
type viewError struct {
	validationFieldErrors map[string]validationFieldError
	messages              []msg
}

func (ve *viewError) hasError() bool {
	return len(ve.validationFieldErrors) > 0 || len(ve.messages) > 0
}

// func (ve *viewError) addSuccessMessage(message string) *viewError {
// 	ve.messages = append(ve.messages, msg{
// 		MsgType: MSG_TYPE_SUCCESS,
// 		message: message,
// 	})
// 	return ve
// }

// func (ve *viewError) addInfoMessage(message string) *viewError {
// 	ve.messages = append(ve.messages, msg{
// 		MsgType: MSG_TYPE_INFO,
// 		message: message,
// 	})
// 	return ve
// }

// func (ve *viewError) addWarningMessage(message string) *viewError {
// 	ve.messages = append(ve.messages, msg{
// 		MsgType: MSG_TYPE_WARNING,
// 		message: message,
// 	})
// 	return ve
// }

// func (ve *viewError) addErrorMessage(message string) *viewError {
// 	ve.messages = append(ve.messages, msg{
// 		MsgType: MSG_TYPE_ERROR,
// 		message: message,
// 	})
// 	return ve
// }

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
			// if err.StructField() == "CsrfToken" || err.StructField() == "FlowID" {
			// 	errorMessages = []string{"申し訳ございませんが、画面をリロードして再度お試しください。"}
			// }
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
	message := pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: fmt.Sprintf("ERR_KRATOS_%s", strings.ToUpper(genericError.ID)),
	})
	return &viewError{
		validationFieldErrors: map[string]validationFieldError{},
		messages:              []msg{newErrorMsg(message)},
	}
}

func kratosUiMessagesToViewError(uiMessages kratos.ErrorUiMessages) *viewError {
	var messages []msg
	for _, v := range uiMessages {
		message := pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID:    fmt.Sprintf("ERR_KRATOS_UI_%s", strconv.Itoa(int(v.ID))),
			TemplateData: v.Context,
		})
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

// // 削除対象
// func extractValidationFieldErrors(err error) validationFieldErrors {
// 	if err == nil {
// 		return validationFieldErrors{}
// 	}

// 	fieldsErrors := make(validationFieldErrors)
// 	for _, err := range err.(validator.ValidationErrors) {
// 		var msg string
// 		if err.ActualTag() == "date" {
// 			msg = "正しい日付を入力してください"
// 		} else {
// 			msg = err.Translate(pkgVars.trans)
// 		}
// 		fieldsErrors[err.StructField()] = validationFieldError{
// 			Tag:     err.ActualTag(),
// 			Message: msg,
// 		}
// 	}
// 	return fieldsErrors
// }

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

// func newMsg(MsgType MsgType) *msg {
// 	var lc i18n.LocalizeConfig
// 	if MsgType == MSG_TYPE_ERROR {
// 		lc = i18n.LocalizeConfig{
// 			MessageID: "ERR_FALLBACK",
// 		}
// 	}

// 	m := msg{
// 		MsgType: MsgType,
// 		message: pkgVars.loc.MustLocalize(&lc),
// 	}

// 	for _, opt := range opts {
// 		opt(&m)
// 	}

// 	return &m
// }

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

// // ---------------------- errorMessages ----------------------
// type errorMessages []string

// type errorMessagesOption func(*errorMessages)

// func newErrorMessages(options ...errorMessagesOption) *errorMessages {
// 	e := errorMessagesMap[ERROR_MESSAGES_ID_FALLBACK]
// 	for _, option := range options {
// 		option(&e)
// 	}
// 	return &e
// }

// func withErrorMessagesDefault(em errorMessages) errorMessagesOption {
// 	return func(e *errorMessages) {
// 		e = &em
// 	}
// }

// func (e *errorMessages) extract(err error) *errorMessages {
// 	var kratosErr kratos.Error
// 	if errors.As(err, &kratosErr) {
// 		emsgs := errorMessages(kratosErr.Messages)
// 		return &emsgs
// 	} else {
// 		return e
// 	}
// }

// func (e *errorMessages) toViewParams() map[string]any {
// 	return map[string]any{
// 		"ErrorMessages": e,
// 	}
// }

// ---------------------- message ----------------------
// type viewMsgType string

// const (
// 	MSG_TYPE_SUCCESS = viewMsgType("success")
// 	MSG_TYPE_INFO    = viewMsgType("info")
// 	MSG_TYPE_WARNING = viewMsgType("warning")
// 	MSG_TYPE_ERROR   = viewMsgType("error")
// )

// type viewMsg struct {
// 	MsgType viewMsgType
// 	msgList []string
// }

// type viewMsgOption func(*viewMsg)

// func newViewMsg(opts ...viewMsgOption) *viewMsg {
// 	e := errorMessagesMap[ERROR_MESSAGES_ID_FALLBACK]
// 	for _, option := range options {
// 		option(&e)
// 	}
// 	return &e
// }

// ---------------------------------------------------

func viewParameters(session *kratos.Session, r *http.Request, p map[string]any) map[string]any {
	params := p
	params["IsAuthenticated"] = isAuthenticated(session)
	params["Navbar"] = getNavbarviewParameters(session)
	params["CurrentPath"] = r.URL.Path
	return params
}
func getNavbarviewParameters(session *kratos.Session) map[string]any {
	var nickname string

	if session != nil {
		nickname = session.Identity.Traits.Nickname
	}
	return map[string]any{
		"Nickname": nickname,
	}
}
func setCookieToResponseHeader(w http.ResponseWriter, cookies []string) {
	for _, cookie := range cookies {
		w.Header().Add("Set-Cookie", cookie)
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

func swapBody(w http.ResponseWriter, url string) {
	w.Header().Set("HX-Push-Url", url)
	w.Header().Set("HX-Retarget", "body")
	w.Header().Set("HX-Reswap", "innerHTML")
}
