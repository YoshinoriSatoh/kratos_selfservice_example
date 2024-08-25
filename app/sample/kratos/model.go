package kratos

import (
	"log/slog"
	"time"
)

// Traitsはjsonb型なので要素はstring型
type Traits struct {
	Email     string `json:"email" validate:"required,email" ja:"メールアドレス"`
	Firstname string `json:"firstname" validate:"required" ja:"名"`
	Lastname  string `json:"lastname" validate:"required" ja:"性"`
	Nickname  string `json:"nickname" validate:"required" ja:"ニックネーム"`
	Birthdate string `json:"birthdate" validate:"date" ja:"生年月日"`
}

func (t *Traits) ToMap() map[string]any {
	return map[string]any{
		"Email":     t.Email,
		"Firstname": t.Firstname,
		"Lastname":  t.Lastname,
		"Nickname":  t.Nickname,
		"Birthdate": t.Birthdate,
	}
}

func setTraitsFromUiNodes(traits *Traits, nodes []uiNode) error {
	for _, node := range nodes {
		if node.Attributes.Name == "traits.email" {
			traits.Email, _ = node.Attributes.Value.(string)
		}
		if node.Attributes.Name == "traits.firstname" {
			traits.Firstname, _ = node.Attributes.Value.(string)
		}
		if node.Attributes.Name == "traits.lastname" {
			traits.Lastname, _ = node.Attributes.Value.(string)
		}
		if node.Attributes.Name == "traits.nickname" {
			traits.Nickname, _ = node.Attributes.Value.(string)
		}
		if node.Attributes.Name == "traits.birthdate" {
			if birthdate, ok := node.Attributes.Value.(string); ok {
				// parseのlayoutがこれでいいかはOIDCプロバイダーによるとおもう
				t, err := time.Parse(time.DateOnly, birthdate)
				if err != nil {
					slog.Error(err.Error())
					return err
				}
				traits.Birthdate = t.Format(time.DateOnly)
			}
		}
	}
	return nil
}

func getPasskeyCreateData(nodes []uiNode) string {
	for _, node := range nodes {
		if node.Attributes.Name == "passkey_create_data" {
			return node.Attributes.Value.(string)
		}
	}
	return ""
}

type Identity struct {
	ID     string `json:"id" validate:"required"`
	Traits Traits `json:"traits" validate:"required"`
}

func (i Identity) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", i.ID),
	)
}

// session
type Session struct {
	ID              string    `json:"id"`
	Identity        Identity  `json:"identity,omitempty"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
}

func (s *Session) NeedLoginWhenPrivilegedAccess() bool {
	authenticateAt := s.AuthenticatedAt.In(pkgVars.locationJst)
	if authenticateAt.Before(time.Now().Add(-time.Second * pkgVars.privilegedAccessLimitMinutes)) {
		return true
	} else {
		return false
	}
}

type RegistrationFlow struct {
	FlowID             string
	CredentialType     CredentialsType
	Traits             Traits
	PasskeyCreateData  string
	CsrfToken          string
	VerificationFlowID string
}

type VerificationFlow struct {
	FlowID    string
	State     string
	CsrfToken string
}

type LoginFlow struct {
	FlowID              string
	PasskeyChallenge    string
	CsrfToken           string
	DuplicateIdentifier string
}

type UpdateLoginFlowResponse struct {
	RedirectBrowserTo string
}

type RecoveryFlow struct {
	FlowID    string
	CsrfToken string
}

type UpdateRecoveryFlowResponse struct {
	Flow              RecoveryFlow
	RedirectBrowserTo string
}

type SettingsFlow struct {
	FlowID    string
	CsrfToken string
}

type UpdateSettingsFlowResponse struct {
	Flow              SettingsFlow
	RedirectBrowserTo string
}

// kratosからのレスポンスのうち、必要なもののみを定義
type kratosSuccessResponse struct {
	Ui *uiContainer `json:"ui,omitempty"`
}

type uiText struct {
	Context map[string]interface{} `json:"context,omitempty"`
	ID      int64                  `json:"id"`
	Text    string                 `json:"text"`
	Type    string                 `json:"type"`
}

type uiNodeMeta struct {
	Label uiText `json:"label,omitempty"`
}

type uiNodeAttributes struct {
	Disabled bool        `json:"disabled"`
	Label    uiText      `json:"label,omitempty"`
	Name     string      `json:"name"`
	NodeType string      `json:"node_type"`
	Onclick  string      `json:"onclick,omitempty"`
	Pattern  string      `json:"pattern,omitempty"`
	Required bool        `json:"required,omitempty"`
	Type     string      `json:"type"`
	Value    interface{} `json:"value,omitempty"`
}

type uiNode struct {
	Attributes uiNodeAttributes `json:"attributes"`
	Group      string           `json:"group"`
	Messages   []uiText         `json:"messages"`
	Meta       uiNodeMeta       `json:"meta"`
	Type       string           `json:"type"`
}

type uiContainer struct {
	Action   string   `json:"action"`
	Messages []uiText `json:"messages,omitempty"`
	Method   string   `json:"method"`
	Nodes    []uiNode `json:"nodes"`
}

type verificationFlow struct {
	Ui uiContainer `json:"ui"`
}

type loginFlow struct {
	Ui uiContainer `json:"ui"`
}

type recoveryFlow struct {
	Ui uiContainer `json:"ui"`
}

type settingsFlow struct {
	Ui uiContainer `json:"ui"`
}

type ErrorUiMessages []ErrorUiMessage

type ErrorUiMessage struct {
	ID      int64
	Type    string
	Text    string
	Context map[string]interface{}
}

func (e ErrorUiMessages) Error() string {
	return ""
}

type GenericError struct {
	Code    int64                  `json:"code,omitempty"`
	Debug   string                 `json:"debug,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
	ID      string                 `json:"id,omitempty"`
	Message string                 `json:"message"`
	Reason  string                 `json:"reason,omitempty"`
	Request string                 `json:"request,omitempty"`
	Status  string                 `json:"status,omitempty"`
	// err     error                  `json:"-"`
}

func (e GenericError) Error() string {
	return e.Message
}

type ErrorGeneric struct {
	Err GenericError `json:"error,omitempty"`
}

func (e ErrorGeneric) Error() string {
	return e.Err.Error()
}

type ErrorBrowserLocationChangeRequired struct {
	Err               GenericError `json:"error"`
	RedirectBrowserTo string       `json:"redirect_browser_to,omitempty"`
}

func (e ErrorBrowserLocationChangeRequired) Error() string {
	return e.Err.Error()
}

type continueWithFlow struct {
	ID string `json:"id"`
}

type continueWith struct {
	Action string           `json:"action"`
	Flow   continueWithFlow `json:"flow"`
}

type CredentialsType string

const (
	CredentialsTypePassword = CredentialsType("password")
	CredentialsTypeOIDC     = CredentialsType("oidc")
	CredentialsTypePasskey  = CredentialsType("passkey")
)

// Registration flow
// type kratosCreateRegisrationFlowRespnse struct {
// 	ID     string          `json:"id"`
// 	Ui     uiContainer     `json:"ui"`
// 	Active CredentialsType `json:"active"`
// }

// type kratosGetRegisrationFlowRespnse struct {
// 	ID     string          `json:"id"`
// 	Ui     uiContainer     `json:"ui"`
// 	Active CredentialsType `json:"active"`
// }

// type kratosUpdateRegistrationFlowRequest struct {
// 	CsrfToken       string  `json:"csrf_token"`
// 	Method          string  `json:"method"`
// 	Traits          Traits  `json:"traits"`
// 	Password        *string `json:"password"`
// 	Provider        *string `json:"provider"`
// 	PasskeyRegister *string `json:"passkey_register"`
// }

// type kratosUpdateRegistrationFlowPasswordMethodRequest struct {
// 	CsrfToken string `json:"csrf_token"`
// 	Method    string `json:"method"`
// 	Traits    Traits `json:"traits"`
// 	Password  string `json:"password"`
// }

// type kratosUpdateRegistrationFlowOidcMethodRequest struct {
// 	CsrfToken string `json:"csrf_token"`
// 	Method    string `json:"method"`
// 	Provider  string `json:"provider"`
// 	Traits    Traits `json:"traits"`
// }

// type kratosUpdateRegistrationFlowPasskeyMethodRequest struct {
// 	CsrfToken       string `json:"csrf_token"`
// 	Method          string `json:"method"`
// 	Traits          Traits `json:"traits"`
// 	PasskeyRegister string `json:"passkey_register"`
// }

// type kratosUpdateRegisrationFlowPasswordRespnse struct {
// 	RedirectBrowserTo string         `json:"redirect_browser_to"`
// 	ContinueWith      []continueWith `json:"continue_with"`
// }

// status code 400 の場合のレスポンスボディのフォーマット
// ドキュメントではregistration flowが返却される記載しかないが、GenericErrorが返却される場合もある
// どちらの場合にも対応するため、必要なフィールドを全て定義している
type kratosBadRequestErrorResponse struct {
	Ui    *uiContainer  `json:"ui,omitempty"`
	Error *GenericError `json:"error,omitempty"`
}

// type kratosUpdateRegistrationFlowBadRequestErrorResponse struct {
// 	Ui    *uiContainer  `json:"ui,omitempty"`
// 	Error *GenericError `json:"error,omitempty"`
// }

// Verification flow

// status code 400 の場合のレスポンスボディのフォーマット
// ドキュメントではverification flowが返却される記載しかないが、GenericErrorが返却される場合もある
// どちらの場合にも対応するため、必要なフィールドを全て定義している
// type kratosUpdateVerificationFlowBadRequestErrorResponse struct {
// 	Ui    *uiContainer  `json:"ui,omitempty"`
// 	Error *GenericError `json:"error,omitempty"`
// }

// Login flow

type kratosUpdateLoginFlowPasswordRequest struct {
	Method     string `json:"method"`
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
	CsrfToken  string `json:"csrf_token"`
}

type kratosUpdateLoginFlowOidcRequest struct {
	Method    string `json:"method"`
	Provider  string `json:"provider"`
	CsrfToken string `json:"csrf_token"`
}

// status code 400 の場合のレスポンスボディのフォーマット
// ドキュメントではverification flowが返却される記載しかないが、GenericErrorが返却される場合もある
// どちらの場合にも対応するため、必要なフィールドを全て定義している
type kratosUpdateLoginFlowBadRequestErrorResponse struct {
	Ui    *uiContainer  `json:"ui,omitempty"`
	Error *GenericError `json:"error,omitempty"`
}

// Logout flow
type kratosCreateLogoutFlowRespnse struct {
	ID          string `json:"id"`
	LogoutToken string `json:"logout_token"`
}

type kratosUpdateLogoutFlowRequest struct {
	CsrfToken string `json:"csrf_token"`
}

// Recovery flow
type kratosCreateRecoveryFlowRespnse struct {
	ID string      `json:"id"`
	Ui uiContainer `json:"ui"`
}

type kratosGetRecoveryFlowRespnse struct {
	ID string      `json:"id"`
	Ui uiContainer `json:"ui"`
}

type kratosUpdateRecoveryFlowRequest struct {
	Method    string `json:"method"`
	Email     string `json:"email"`
	Code      string `json:"code"`
	CsrfToken string `json:"csrf_token"`
}

// Settings flow
type kratosCreateSettingsFlowRespnse struct {
	ID string      `json:"id"`
	Ui uiContainer `json:"ui"`
}

type kratosGetSettingsFlowRespnse struct {
	ID    string      `json:"id"`
	Ui    uiContainer `json:"ui"`
	State string      `json:"state"`
}

type kratosUpdateSettingsFlowRequest struct {
	Method    string `json:"method"`
	Password  string `json:"password"`
	Traits    Traits `json:"traits"`
	Code      string `json:"code"`
	CsrfToken string `json:"csrf_token"`
}

// status code 400 の場合のレスポンスボディのフォーマット
// ドキュメントではverification flowが返却される記載しかないが、GenericErrorが返却される場合もある
// どちらの場合にも対応するため、必要なフィールドを全て定義している
type kratosUpdateSettingsFlowBadRequestErrorResponse struct {
	Ui    *uiContainer  `json:"ui,omitempty"`
	Error *GenericError `json:"error,omitempty"`
}
