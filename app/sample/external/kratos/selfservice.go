package kratos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

const (
	PATH_SELF_SERVICE_CREATE_REGISTRATION_FLOW = "/self-service/registration/browser"
	PATH_SELF_SERVICE_UPDATE_REGISTRATION_FLOW = "/self-service/registration"
	PATH_SELF_SERVICE_GET_REGISTRATION_FLOW    = "/self-service/registration/flows"
	PATH_SELF_SERVICE_CREATE_VERIFICATION_FLOW = "/self-service/verification/browser"
	PATH_SELF_SERVICE_UPDATE_VERIFICATION_FLOW = "/self-service/verification"
	PATH_SELF_SERVICE_GET_VERIFICATION_FLOW    = "/self-service/verification/flows"
	PATH_SELF_SERVICE_CREATE_LOGIN_FLOW        = "/self-service/login/browser"
	PATH_SELF_SERVICE_UPDATE_LOGIN_FLOW        = "/self-service/login"
	PATH_SELF_SERVICE_GET_LOGIN_FLOW           = "/self-service/login/flows"
	PATH_SELF_SERVICE_GET_LOGOUT_FLOW          = "/self-service/logout/browser"
	PATH_SELF_SERVICE_UPDATE_LOGOUT_FLOW       = "/self-service/logout"
	PATH_SELF_SERVICE_CREATE_SETTINGS_FLOW     = "/self-service/settings/browser"
	PATH_SELF_SERVICE_UPDATE_SETTINGS_FLOW     = "/self-service/settings"
	PATH_SELF_SERVICE_GET_SETTINGS_FLOW        = "/self-service/settings/flows"
	PATH_SELF_SERVICE_CREATE_RECOVERY_FLOW     = "/self-service/recovery/browser"
	PATH_SELF_SERVICE_UPDATE_RECOVERY_FLOW     = "/self-service/recovery"
	PATH_SELF_SERVICE_GET_RECOVERY_FLOW        = "/self-service/recovery/flows"
	PATH_SELF_SERVICE_CALLBACK_OIDC            = "/self-service/methods/oidc/callback"
)

// --------------------------------------------------------------------------
// Create or Get Registration Flow
// --------------------------------------------------------------------------
func (p *Provider) CreateOrGetRegistrationFlow(ctx context.Context, h KratosRequestHeader, flowID string) (RegistrationFlow, KratosResponseHeader, error) {
	var (
		err                  error
		registrationFlow     RegistrationFlow
		kratosResponseHeader KratosResponseHeader
	)
	if flowID == "" {
		var createRegistrationFlowResp CreateRegistrationFlowResponse
		createRegistrationFlowResp, err = p.CreateRegistrationFlow(ctx, CreateRegistrationFlowRequest{
			Header: h,
		})
		kratosResponseHeader = createRegistrationFlowResp.Header
		registrationFlow = createRegistrationFlowResp.RegistrationFlow
	} else {
		var getRegistrationFlowResp GetRegistrationFlowResponse
		getRegistrationFlowResp, err = p.GetRegistrationFlow(ctx, GetRegistrationFlowRequest{
			FlowID: flowID,
			Header: h,
		})
		kratosResponseHeader = getRegistrationFlowResp.Header
		registrationFlow = getRegistrationFlowResp.RegistrationFlow
	}
	return registrationFlow, kratosResponseHeader, err
}

// --------------------------------------------------------------------------
// Get Registration Flow
// --------------------------------------------------------------------------
type GetRegistrationFlowRequest struct {
	FlowID string
	Header KratosRequestHeader
}

type GetRegistrationFlowResponse struct {
	Header           KratosResponseHeader
	RegistrationFlow RegistrationFlow
}

type kratosGetRegisrationFlowRespnseBody struct {
	ID string      `json:"id"`
	Ui uiContainer `json:"ui"`
	// Active CredentialsType `json:"active"` // Activeはflow完了後でないと取得できない
	RequestUrl string `json:"request_url"` // flow完了前はrequest_urlから判定する
}

func (p *Provider) GetRegistrationFlow(ctx context.Context, r GetRegistrationFlowRequest) (GetRegistrationFlowResponse, error) {
	// Request to kratos
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s?id=%s", PATH_SELF_SERVICE_GET_REGISTRATION_FLOW, r.FlowID),
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "GetRegistrationFlow", "requestKratosPublic error", err)
		return GetRegistrationFlowResponse{}, err
	}

	// Parse response body
	var kratosRespBody kratosGetRegisrationFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetRegistrationFlow", "json unmarshal error", err)
		return GetRegistrationFlowResponse{}, err
	}

	// create response
	var credentialsType CredentialsType
	var oidcProvider OidcProvider
	if strings.Contains(kratosRespBody.RequestUrl, "self-service/methods/oidc/callback") {
		credentialsType = CredentialsTypeOidc
		if strings.Contains(kratosRespBody.RequestUrl, "self-service/methods/oidc/callback/google") {
			oidcProvider = OidcProviderGoogle
		} else if strings.Contains(kratosRespBody.RequestUrl, "self-service/methods/oidc/callback/github") {
			oidcProvider = OidcProviderGithub
		}
	} else {
		credentialsType = CredentialsTypePassword
	}
	response := GetRegistrationFlowResponse{
		Header: kratosResp.Header,
		RegistrationFlow: RegistrationFlow{
			FlowID:         kratosRespBody.ID,
			CsrfToken:      getCsrfTokenFromFlowUi(kratosRespBody.Ui),
			CredentialType: credentialsType,
			OidcProvider:   oidcProvider,
		},
	}
	if credentialsType == CredentialsTypeOidc {
		// Set to response the traits that was got from OIDC provider if OIDC callback
		setTraitsFromUiNodes(&response.RegistrationFlow.Traits, kratosRespBody.Ui.Nodes)
	} else if credentialsType == CredentialsTypePasskey {
		response.RegistrationFlow.PasskeyCreateData = getPasskeyCreateData(kratosRespBody.Ui.Nodes)
	}

	return response, nil
}

// --------------------------------------------------------------------------
// Create Registration Flow
// --------------------------------------------------------------------------
type CreateRegistrationFlowRequest struct {
	Header KratosRequestHeader
	// ReturnTo は application/json では機能しない
	// https://github.com/ory/kratos/blob/v1.2.0/x/http_secure_redirect.go#L185-L199
}

type CreateRegistrationFlowResponse struct {
	Header           KratosResponseHeader
	RegistrationFlow RegistrationFlow
}

type kratosCreateRegisrationFlowRespnseBody struct {
	ID string      `json:"id"`
	Ui uiContainer `json:"ui"`
	// Active CredentialsType `json:"active"` // Activeはflow完了後でないと取得できない
	RequestUrl string `json:"request_url"` // flow完了前はrequest_urlから判定する
}

func (p *Provider) CreateRegistrationFlow(ctx context.Context, r CreateRegistrationFlowRequest) (CreateRegistrationFlowResponse, error) {
	// Request to kratos
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_CREATE_REGISTRATION_FLOW,
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "CreateRegistrationFlow", "requestKratosPublic error", err)
		return CreateRegistrationFlowResponse{}, err
	}

	// Parse response body
	var kratosRespBody kratosCreateRegisrationFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, err.Error())
		return CreateRegistrationFlowResponse{}, err
	}

	// create response
	var credentialsType CredentialsType
	var oidcProvider OidcProvider
	if strings.Contains(kratosRespBody.RequestUrl, "self-service/methods/oidc/callback") {
		credentialsType = CredentialsTypeOidc
		if strings.Contains(kratosRespBody.RequestUrl, "self-service/methods/oidc/callback/google") {
			oidcProvider = OidcProviderGoogle
		} else if strings.Contains(kratosRespBody.RequestUrl, "self-service/methods/oidc/callback/github") {
			oidcProvider = OidcProviderGithub
		}
	} else {
		credentialsType = CredentialsTypePassword
	}
	response := CreateRegistrationFlowResponse{
		Header: kratosResp.Header,
		RegistrationFlow: RegistrationFlow{
			FlowID:         kratosRespBody.ID,
			CsrfToken:      getCsrfTokenFromFlowUi(kratosRespBody.Ui),
			CredentialType: credentialsType,
			OidcProvider:   oidcProvider,
		},
	}
	// if credentialsType == CredentialsTypePasskey {
	response.RegistrationFlow.PasskeyCreateData = getPasskeyCreateData(kratosRespBody.Ui.Nodes)
	// }

	return response, nil
}

// --------------------------------------------------------------------------
// Update Registration Flow
// --------------------------------------------------------------------------
type UpdateRegistrationFlowRequest struct {
	FlowID string
	Header KratosRequestHeader
	Body   UpdateRegistrationFlowRequestBody
}

type UpdateRegistrationFlowRequestBody struct {
	CsrfToken       string `json:"csrf_token"`
	Method          string `json:"method"`
	Traits          Traits `json:"traits,omitempty"`
	Password        string `json:"password,omitempty"`
	Provider        string `json:"provider,omitempty"`
	PasskeyRegister string `json:"passkey_register,omitempty"`
}

type UpdateRegistrationFlowResponse struct {
	Header              KratosResponseHeader
	VerificationFlowID  string
	RedirectBrowserTo   string
	DuplicateIdentifier string
}

type kratosUpdateRegisrationFlowPasswordRespnseBody struct {
	ContinueWith []continueWith `json:"continue_with"`
	// Identity     Identity
	// Session      Session
	// SessionToken string
}

type kratosUpdateRegisrationFlowBadRequestRespnseBody struct {
	Ui uiContainer `json:"ui"`
}

func (p *Provider) UpdateRegistrationFlow(ctx context.Context, r UpdateRegistrationFlowRequest) (UpdateRegistrationFlowResponse, error) {
	// valiate parameter
	if r.Body.Method == "password" {
		if r.Body.Password == "" {
			return UpdateRegistrationFlowResponse{}, errors.New("missing password in body")
		}
	} else if r.Body.Method == "oidc" {
		if r.Body.Provider == "" {
			return UpdateRegistrationFlowResponse{}, errors.New("missing provider in body")
		}
	} else if r.Body.Method == "passkey" {
		if r.Body.PasskeyRegister == "" {
			return UpdateRegistrationFlowResponse{}, errors.New("missing passkey register in body")
		}
	} else {
		slog.ErrorContext(ctx, "UpdateRegistrationFlow", "Method", r.Body.Method)
		return UpdateRegistrationFlowResponse{}, fmt.Errorf("invalid method: %s", r.Body.Method)
	}

	// Request to kratos
	bodyBytes, err := json.Marshal(r.Body)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateRegistrationFlow", "json unmarshal error", err)
		return UpdateRegistrationFlowResponse{}, err
	}
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method:    http.MethodPost,
		Path:      fmt.Sprintf("%s?flow=%s", PATH_SELF_SERVICE_UPDATE_REGISTRATION_FLOW, r.FlowID),
		BodyBytes: bodyBytes,
		Header:    r.Header,
	})
	var redirectBrowserTo string
	var duplicateIdentifier string
	if err != nil {
		if kratosResp.StatusCode == http.StatusUnprocessableEntity {
			redirectBrowserTo = err.(ErrorBrowserLocationChangeRequired).RedirectBrowserTo
		} else if kratosResp.StatusCode == http.StatusBadRequest {
			// Parse response body (bad request)
			var kratosRespBadRequestBody kratosUpdateRegisrationFlowBadRequestRespnseBody
			if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBadRequestBody); err != nil {
				slog.ErrorContext(ctx, "UpdateRegistrationFlow", "json unmarshal error", err)
				return UpdateRegistrationFlowResponse{}, err
			}
			duplicateIdentifier = getDuplicateIdentifierFromUi(kratosRespBadRequestBody.Ui)
		} else {
			slog.ErrorContext(ctx, "UpdateRegistrationFlow", "requestKratosPublic error", err)
			return UpdateRegistrationFlowResponse{}, err
		}
	}

	// Parse response body
	var kratosRespBody kratosUpdateRegisrationFlowPasswordRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "UpdateRegistrationFlow", "json unmarshal error", err)
		return UpdateRegistrationFlowResponse{}, err
	}

	// Create response
	response := UpdateRegistrationFlowResponse{
		Header:              kratosResp.Header,
		RedirectBrowserTo:   redirectBrowserTo,
		DuplicateIdentifier: duplicateIdentifier,
	}
	for _, c := range kratosRespBody.ContinueWith {
		if c.Action == "show_verification_ui" {
			response.VerificationFlowID = c.Flow.ID
		}
	}

	return response, nil
}

// --------------------------------------------------------------------------
// Get Verification Flow
// --------------------------------------------------------------------------
type GetVerificationFlowRequest struct {
	FlowID string
	Header KratosRequestHeader
}

type GetVerificationFlowResponse struct {
	Header           KratosResponseHeader
	VerificationFlow VerificationFlow
}

type kratosGetVerificationFlowRespnseBody struct {
	ID    string      `json:"id"`
	Ui    uiContainer `json:"ui"`
	State string      `json:"state"`
}

func (p *Provider) GetVerificationFlow(ctx context.Context, r GetVerificationFlowRequest) (GetVerificationFlowResponse, error) {
	// Request to kratos
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s?id=%s", PATH_SELF_SERVICE_GET_VERIFICATION_FLOW, r.FlowID),
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "GetVerificationFlow", "requestKratosPublic error", err)
		return GetVerificationFlowResponse{}, err
	}

	// Parse response body
	var kratosRespBody kratosGetVerificationFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetVerificationFlow", "json unmarshal error", err)
		return GetVerificationFlowResponse{}, err
	}

	// create response
	response := GetVerificationFlowResponse{
		Header: kratosResp.Header,
		VerificationFlow: VerificationFlow{
			FlowID:    kratosRespBody.ID,
			CsrfToken: getCsrfTokenFromFlowUi(kratosRespBody.Ui),
			State:     kratosRespBody.State,
		},
	}
	// if kratosRespBody.State == "passed_challenge" {
	// 	verificationFlow.IsUsedFlow = true
	// }

	return response, nil
}

// --------------------------------------------------------------------------
// Create Verification Flow
// --------------------------------------------------------------------------
type CreateVerificationFlowRequest struct {
	Header KratosRequestHeader
	// ReturnTo は application/json では機能しない
	// https://github.com/ory/kratos/blob/v1.2.0/x/http_secure_redirect.go#L185-L199
}

type CreateVerificationFlowResponse struct {
	Header           KratosResponseHeader
	VerificationFlow VerificationFlow
}

type kratosCreateVerificationFlowRespnseBody struct {
	ID string      `json:"id"`
	Ui uiContainer `json:"ui"`
}

func (p *Provider) CreateVerificationFlow(ctx context.Context, r CreateVerificationFlowRequest) (CreateVerificationFlowResponse, error) {
	// Request to kratos
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_CREATE_VERIFICATION_FLOW,
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "CreateVerificationFlow", "requestKratosPublic error", err)
		return CreateVerificationFlowResponse{}, err
	}

	// Parse response body
	var kratosRespBody kratosCreateVerificationFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetVerificationFlow", "json unmarshal error", err)
		return CreateVerificationFlowResponse{}, err
	}

	response := CreateVerificationFlowResponse{
		Header: kratosResp.Header,
		VerificationFlow: VerificationFlow{
			FlowID:    kratosRespBody.ID,
			CsrfToken: getCsrfTokenFromFlowUi(kratosRespBody.Ui),
		},
	}

	return response, nil
}

// --------------------------------------------------------------------------
// Update Verification Flow
// --------------------------------------------------------------------------
type UpdateVerificationFlowRequest struct {
	FlowID string
	Header KratosRequestHeader
	Body   UpdateVerificationFlowRequestBody
}

type UpdateVerificationFlowRequestBody struct {
	Method    string `json:"method"`
	CsrfToken string `json:"csrf_token"`
	Email     string `json:"email,omitempty"`
	Code      string `json:"code,omitempty"`
}

type UpdateVerificationFlowResponse struct {
	Header KratosResponseHeader
	Flow   VerificationFlow
}

type kratosUpdateVerificationFlowResponseBody struct {
	ID    string      `json:"id"`
	Ui    uiContainer `json:"ui,omitempty"`
	State string      `json:"state"`
}

func (p *Provider) UpdateVerificationFlow(ctx context.Context, r UpdateVerificationFlowRequest) (UpdateVerificationFlowResponse, error) {
	// valiate parameter
	//   email設定時は、Verification Flowを更新して、アカウント検証メールを送信
	//   code設定時は、Verification Flowを完了
	if (r.Body.Email != "" && r.Body.Code != "") || (r.Body.Email == "" && r.Body.Code == "") {
		return UpdateVerificationFlowResponse{}, fmt.Errorf("parameter convination error. email: %s, code: %s", r.Body.Email, "code", r.Body.Code)
	}

	// Request to kratos
	r.Body.Method = "code" // supported code only
	kratosInputBytes, err := json.Marshal(r.Body)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateVerificationFlow", "json unmarshal error", err)
		return UpdateVerificationFlowResponse{}, err
	}
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method:    http.MethodPost,
		Path:      fmt.Sprintf("%s?flow=%s", PATH_SELF_SERVICE_UPDATE_VERIFICATION_FLOW, r.FlowID),
		BodyBytes: kratosInputBytes,
		Header:    r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "UpdateVerificationFlow", "requestKratosPublic error", err)
		return UpdateVerificationFlowResponse{}, err
	}

	// Parse response body
	var kratosRespBody kratosUpdateVerificationFlowResponseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetVerificationFlow", "json unmarshal error", err)
		return UpdateVerificationFlowResponse{}, err
	}

	// create response
	response := UpdateVerificationFlowResponse{
		Header: kratosResp.Header,
		Flow: VerificationFlow{
			FlowID:    kratosRespBody.ID,
			CsrfToken: getCsrfTokenFromFlowUi(kratosRespBody.Ui),
			State:     kratosRespBody.State,
		},
	}
	// if kratosRespBody.State == "passed_challenge" {
	// 	response.Flow.IsUsedFlow = true
	// }

	return response, nil
}

// --------------------------------------------------------------------------
// Get Login Flow
// --------------------------------------------------------------------------
type GetLoginFlowRequest struct {
	FlowID string
	Header KratosRequestHeader
}

type GetLoginFlowResponse struct {
	Header    KratosResponseHeader
	LoginFlow LoginFlow
}

type kratosGetLoginFlowRespnseBody struct {
	ID    string      `json:"id"`
	Ui    uiContainer `json:"ui"`
	State string      `json:"state"`
}

func (p *Provider) GetLoginFlow(ctx context.Context, r GetLoginFlowRequest) (GetLoginFlowResponse, error) {
	// Request to kratos
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s?id=%s", PATH_SELF_SERVICE_GET_LOGIN_FLOW, r.FlowID),
		Header: r.Header,
	})
	if err != nil {
		if !hasUiError(err, 4000007) {
			slog.ErrorContext(ctx, "GeLoginFlow", "requestKratosPublic error", err)
			return GetLoginFlowResponse{}, err
		}
	}

	// Parse response body
	var FlowkratosRespBody kratosGetLoginFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &FlowkratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GeLoginFlow", "json unmarshal error", err)
		return GetLoginFlowResponse{}, err
	}

	// create response
	response := GetLoginFlowResponse{
		Header: kratosResp.Header,
		LoginFlow: LoginFlow{
			DuplicateIdentifier: getDuplicateIdentifierFromUi(FlowkratosRespBody.Ui),
			FlowID:              FlowkratosRespBody.ID,
			CsrfToken:           getCsrfTokenFromFlowUi(FlowkratosRespBody.Ui),
		},
	}
	for _, node := range FlowkratosRespBody.Ui.Nodes {
		if node.Attributes.Name == "passkey_challenge" {
			response.LoginFlow.PasskeyChallenge = node.Attributes.Value.(string)
		}
	}

	return response, nil
}

// --------------------------------------------------------------------------
// Create Login Flow
// --------------------------------------------------------------------------
type CreateLoginFlowRequest struct {
	Header  KratosRequestHeader
	Refresh bool
	// ReturnTo は application/json では機能しない
	// https://github.com/ory/kratos/blob/v1.2.0/x/http_secure_redirect.go#L185-L199
}

type CreateLoginFlowResponse struct {
	Header    KratosResponseHeader
	LoginFlow LoginFlow
}

type kratosCreateLoginFlowRespnseBody struct {
	ID string      `json:"id"`
	Ui uiContainer `json:"ui"`
}

func (p *Provider) CreateLoginFlow(ctx context.Context, r CreateLoginFlowRequest) (CreateLoginFlowResponse, error) {
	// Request to kratos
	path := PATH_SELF_SERVICE_CREATE_LOGIN_FLOW
	// path = fmt.Sprintf("%s?aal=aal2", path)
	if r.Refresh {
		path = fmt.Sprintf("%s?refresh=true", path)
	}

	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   path,
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "GetLoginFlow", "requestKratosPublic error", err)
		return CreateLoginFlowResponse{}, err
	}

	// Parse response body
	var createLoginFlowResp kratosCreateLoginFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &createLoginFlowResp); err != nil {
		slog.ErrorContext(ctx, err.Error())
		return CreateLoginFlowResponse{}, err
	}

	// create response
	response := CreateLoginFlowResponse{
		Header: kratosResp.Header,
		LoginFlow: LoginFlow{
			FlowID:    createLoginFlowResp.ID,
			CsrfToken: getCsrfTokenFromFlowUi(createLoginFlowResp.Ui),
		},
	}
	for _, node := range createLoginFlowResp.Ui.Nodes {
		if node.Attributes.Name == "passkey_challenge" {
			response.LoginFlow.PasskeyChallenge = node.Attributes.Value.(string)
		}
	}

	return response, nil
}

// --------------------------------------------------------------------------
// Update Login Flow
// --------------------------------------------------------------------------
type UpdateLoginFlowRequest struct {
	FlowID string
	Header KratosRequestHeader
	Body   UpdateLoginFlowRequestBody
}

type UpdateLoginFlowRequestBody struct {
	CsrfToken    string `json:"csrf_token"`
	Method       string `json:"method"`
	Identifier   string `json:"identifier,omitempty"`
	Password     string `json:"password,omitempty"`
	Provider     string `json:"provider,omitempty"`
	PasskeyLogin string `json:"passkey_login,omitempty"`
}

type UpdateLoginFlowResponse struct {
	Header            KratosResponseHeader
	Session           Session
	RedirectBrowserTo string
}

type kratosUpdateLoginFlowResponseBody struct {
	Session Session `json:"session"`
}

// Login Flow の送信(完了)
func (p *Provider) UpdateLoginFlow(ctx context.Context, r UpdateLoginFlowRequest) (UpdateLoginFlowResponse, error) {
	// valiate parameter
	if r.Body.Method == "password" {
		if r.Body.Password == "" || r.Body.Identifier == "" {
			return UpdateLoginFlowResponse{}, fmt.Errorf("parameter convination error. password: %s, identifier: %s", r.Body.Password, r.Body.Identifier)
		}
	} else if r.Body.Method == "oidc" {
		if r.Body.Provider == "" {
			return UpdateLoginFlowResponse{}, fmt.Errorf("parameter convination error. provider: %s", r.Body.Provider)
		}
	} else if r.Body.Method == "passkey" {
		if r.Body.PasskeyLogin == "" {
			return UpdateLoginFlowResponse{}, fmt.Errorf("parameter convination error. passkey: %s", r.Body.PasskeyLogin)
		}
	} else {
		slog.ErrorContext(ctx, "UpdateLoginFlow", "Method", r.Body.Method)
		return UpdateLoginFlowResponse{}, fmt.Errorf("invalid method: %s", r.Body.Method)
	}

	// Request to kratos
	kratosInputBytes, err := json.Marshal(r.Body)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateLoginFlow", "json unmarshal error", err)
		return UpdateLoginFlowResponse{}, err
	}
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method:    http.MethodPost,
		Path:      fmt.Sprintf("%s?flow=%s", PATH_SELF_SERVICE_UPDATE_LOGIN_FLOW, r.FlowID),
		BodyBytes: kratosInputBytes,
		Header:    r.Header,
	})
	var redirectBrowserTo string
	if err != nil {
		if kratosResp.StatusCode == http.StatusUnprocessableEntity {
			redirectBrowserTo = err.(ErrorBrowserLocationChangeRequired).RedirectBrowserTo
		} else {
			slog.ErrorContext(ctx, "UpdateLoginFlow", "requestKratosPublic error", err)
			return UpdateLoginFlowResponse{}, err
		}
	}

	// Parse response body
	var kratosRespBody kratosUpdateLoginFlowResponseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "UpdateLoginFlow", "json unmarshal error", err)
		return UpdateLoginFlowResponse{}, err
	}

	// Create response
	response := UpdateLoginFlowResponse{
		Header:            kratosResp.Header,
		Session:           kratosRespBody.Session,
		RedirectBrowserTo: redirectBrowserTo,
	}

	return response, nil
}

// --------------------------------------------------------------------------
// Logout
// --------------------------------------------------------------------------
type LogoutRequest struct {
	Header KratosRequestHeader
}

type LogoutResponse struct {
	Header KratosResponseHeader
}

type kratosCreateLogoutFlowRespnseBody struct {
	ID          string `json:"id"`
	LogoutToken string `json:"logout_token"`
}

type kratosUpdateLogoutFlowRequestBody struct {
	CsrfToken string `json:"csrf_token"`
}

func (p *Provider) Logout(ctx context.Context, r LogoutRequest) (LogoutResponse, error) {
	// Request to kratos for create logout flow
	kratosRespCreateLogoutFlow, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_GET_LOGOUT_FLOW,
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "Logout", "requestKratosPublic error", err)
		return LogoutResponse{}, err
	}

	// Parse response body for create logout flow
	var kratosRespBodyCreateLogoutFlow kratosCreateLogoutFlowRespnseBody
	if err := json.Unmarshal(kratosRespCreateLogoutFlow.BodyBytes, &kratosRespBodyCreateLogoutFlow); err != nil {
		slog.ErrorContext(ctx, "Logout", "json unmarshal error", err)
		return LogoutResponse{}, err
	}

	// Request to kratos for update logout flow
	kratosRespUpdateLogoutFlow, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s?flow=%s&token=%s", PATH_SELF_SERVICE_UPDATE_LOGOUT_FLOW, kratosRespBodyCreateLogoutFlow.ID, kratosRespBodyCreateLogoutFlow.LogoutToken),
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "Logout", "requestKratosPublic error", err)
		return LogoutResponse{}, err
	}

	// Parse response body for update logout flow
	if len(kratosRespUpdateLogoutFlow.BodyBytes) > 0 {
		var kratosRespBodyUpdateLogoutFlow kratosUpdateLogoutFlowRequestBody
		if err := json.Unmarshal(kratosRespUpdateLogoutFlow.BodyBytes, &kratosRespBodyUpdateLogoutFlow); err != nil {
			slog.ErrorContext(ctx, "Logout", "json unmarshal error", err)
			return LogoutResponse{}, err
		}
	}

	// Create response
	response := LogoutResponse{
		Header: kratosRespUpdateLogoutFlow.Header,
	}

	return response, nil
}

// --------------------------------------------------------------------------
// Get Recovery Flow
// --------------------------------------------------------------------------
type GetRecoveryFlowRequest struct {
	FlowID string
	Header KratosRequestHeader
}

type GetRecoveryFlowResponse struct {
	Header       KratosResponseHeader
	RecoveryFlow RecoveryFlow
}

type kratosGetRecoveryFlowRespnseBody struct {
	ID string      `json:"id"`
	Ui uiContainer `json:"ui"`
}

func (p *Provider) GetRecoveryFlow(ctx context.Context, r GetRecoveryFlowRequest) (GetRecoveryFlowResponse, error) {
	// Request to kratos
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s?id=%s", PATH_SELF_SERVICE_GET_RECOVERY_FLOW, r.FlowID),
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "GetRecoveryFlow", "requestKratosPublic error", err)
		return GetRecoveryFlowResponse{}, err
	}

	// Parse response body
	var kratosRespBody kratosGetRecoveryFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetRecoveryFlow", "json unmarshal error", err)
		return GetRecoveryFlowResponse{}, err
	}

	// create response
	response := GetRecoveryFlowResponse{
		Header: kratosResp.Header,
		RecoveryFlow: RecoveryFlow{
			FlowID:    kratosRespBody.ID,
			CsrfToken: getCsrfTokenFromFlowUi(kratosRespBody.Ui),
		},
	}

	return response, nil
}

// --------------------------------------------------------------------------
// Create Recovery Flow
// --------------------------------------------------------------------------
type CreateRecoveryFlowRequest struct {
	Header KratosRequestHeader
}

type CreateRecoveryFlowResponse struct {
	Header       KratosResponseHeader
	RecoveryFlow RecoveryFlow
}

type kratosCreateRecoveryFlowRespnseBody struct {
	ID string      `json:"id"`
	Ui uiContainer `json:"ui"`
}

func (p *Provider) CreateRecoveryFlow(ctx context.Context, r CreateRecoveryFlowRequest) (CreateRecoveryFlowResponse, error) {
	// Request to kratos
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_CREATE_RECOVERY_FLOW,
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "CreateRecoveryFlow", "requestKratosPublic error", err)
		return CreateRecoveryFlowResponse{}, err
	}

	// Parse response body
	var kratosRespBody kratosCreateRecoveryFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "CreateRecoveryFlow", "json unmarshal error", err)
		return CreateRecoveryFlowResponse{}, err
	}

	// create response
	response := CreateRecoveryFlowResponse{
		Header: kratosResp.Header,
		RecoveryFlow: RecoveryFlow{
			FlowID:    kratosRespBody.ID,
			CsrfToken: getCsrfTokenFromFlowUi(kratosRespBody.Ui),
		},
	}

	return response, nil
}

// --------------------------------------------------------------------------
// Update Recovery Flow
// --------------------------------------------------------------------------
type UpdateRecoveryFlowRequest struct {
	FlowID string
	Body   UpdateRecoveryFlowRequestBody
	Header KratosRequestHeader
}

type UpdateRecoveryFlowRequestBody struct {
	CsrfToken string `json:"csrf_token"`
	Method    string `json:"method"`
	Email     string `json:"email,omitempty"`
	Code      string `json:"code,omitempty"`
}

type UpdateRecoveryFlowResponse struct {
	Header            KratosResponseHeader
	Flow              RecoveryFlow
	RecoveryFlowID    string
	SettingsFlowID    string
	RedirectBrowserTo string
}

type kratosUpdateRecoveryFlowResponseBody struct {
	ContinueWith []continueWith `json:"continue_with"`
}

func (p *Provider) UpdateRecoveryFlow(ctx context.Context, r UpdateRecoveryFlowRequest) (UpdateRecoveryFlowResponse, error) {
	// valiate parameter
	if (r.Body.Email != "" && r.Body.Code != "") || (r.Body.Email == "" && r.Body.Code == "") {
		return UpdateRecoveryFlowResponse{}, fmt.Errorf("parameter convination error. email: %s, code: %s", r.Body.Email, "code", r.Body.Code)
	}

	// Request to kratos
	kratosInputBytes, err := json.Marshal(r.Body)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateRecoveryFlow", "json unmarshal error", err)
		return UpdateRecoveryFlowResponse{}, err
	}
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method:    http.MethodPost,
		Path:      fmt.Sprintf("%s?flow=%s", PATH_SELF_SERVICE_UPDATE_RECOVERY_FLOW, r.FlowID),
		BodyBytes: kratosInputBytes,
		Header:    r.Header,
	})
	var redirectBrowserTo string
	if err != nil {
		if kratosResp.StatusCode == http.StatusUnprocessableEntity {
			redirectBrowserTo = err.(ErrorBrowserLocationChangeRequired).RedirectBrowserTo
		} else {
			slog.ErrorContext(ctx, "UpdateRecoveryFlow", "requestKratosPublic error", err)
			return UpdateRecoveryFlowResponse{}, err
		}
	}

	// Parse response body
	var kratosRespBody kratosUpdateRecoveryFlowResponseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "UpdateRecoveryFlow", "json unmarshal error", err)
		return UpdateRecoveryFlowResponse{}, err
	}

	// create response
	response := UpdateRecoveryFlowResponse{
		Header:            kratosResp.Header,
		RedirectBrowserTo: redirectBrowserTo,
	}
	for _, c := range kratosRespBody.ContinueWith {
		if c.Action == "show_settings_ui" {
			response.SettingsFlowID = c.Flow.ID
		}
		if c.Action == "show_recovery_ui" {
			response.RecoveryFlowID = c.Flow.ID
		}
	}
	return response, nil
}

// --------------------------------------------------------------------------
// Get Settings Flow
// --------------------------------------------------------------------------
type GetSettingsFlowRequest struct {
	FlowID string
	Header KratosRequestHeader
}

type GetSettingsFlowResponse struct {
	Header       KratosResponseHeader
	SettingsFlow SettingsFlow
}

type kratosGetSettingsFlowRespnseBody struct {
	ID    string      `json:"id"`
	Ui    uiContainer `json:"ui"`
	State string      `json:"state"`
}

func (p *Provider) GetSettingsFlow(ctx context.Context, r GetSettingsFlowRequest) (GetSettingsFlowResponse, error) {
	// Request to kratos
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s?id=%s", PATH_SELF_SERVICE_GET_SETTINGS_FLOW, r.FlowID),
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "GetSettingsFlow", "requestKratosPublic error", err)
		return GetSettingsFlowResponse{}, err
	}

	// Parse response body
	var kratosRespBody kratosGetSettingsFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetSettingsFlow", "json unmarshal error", err)
		return GetSettingsFlowResponse{}, err
	}

	// create response
	response := GetSettingsFlowResponse{
		Header: kratosResp.Header,
		SettingsFlow: SettingsFlow{
			FlowID:    kratosRespBody.ID,
			CsrfToken: getCsrfTokenFromFlowUi(kratosRespBody.Ui),
		},
	}

	return response, nil
}

// --------------------------------------------------------------------------
// Create Settings Flow
// --------------------------------------------------------------------------
type CreateSettingsFlowRequest struct {
	Header KratosRequestHeader
}

type CreateSettingsFlowResponse struct {
	Header       KratosResponseHeader
	SettingsFlow SettingsFlow
}

type kratosCreateSettingsFlowRespnseBody struct {
	ID string      `json:"id"`
	Ui uiContainer `json:"ui"`
}

func (p *Provider) CreateSettingsFlow(ctx context.Context, r CreateSettingsFlowRequest) (CreateSettingsFlowResponse, error) {
	// Request to kratos
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_CREATE_SETTINGS_FLOW,
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "CreateSettingsFlow", "requestKratosPublic error", err)
		return CreateSettingsFlowResponse{}, err
	}

	// Parse response body
	var kratosRespBody kratosCreateSettingsFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetSettingsFlow", "json unmarshal error", err)
		return CreateSettingsFlowResponse{}, err
	}

	// create response
	response := CreateSettingsFlowResponse{
		Header: kratosResp.Header,
		SettingsFlow: SettingsFlow{
			FlowID:    kratosRespBody.ID,
			CsrfToken: getCsrfTokenFromFlowUi(kratosRespBody.Ui),
		},
	}

	return response, nil
}

// --------------------------------------------------------------------------
// Update Settings Flow
// --------------------------------------------------------------------------
type UpdateSettingsFlowRequest struct {
	FlowID string
	Header KratosRequestHeader
	Body   UpdateSettingsFlowRequestBody
}

type UpdateSettingsFlowResponse struct {
	Header             KratosResponseHeader
	SettingsFlowID     string
	VerificationFlowID string
	RedirectBrowserTo  string
}

type UpdateSettingsFlowRequestBody struct {
	Method    string `json:"method"`
	CsrfToken string `json:"csrf_token"`
	Password  string `json:"password,omitempty"`
	Traits    Traits `json:"traits,omitempty"`
}

type kratosUpdateSettingsFlowRespnseBody struct {
	ContinueWith []continueWith `json:"continue_with"`
}

func (p *Provider) UpdateSettingsFlow(ctx context.Context, r UpdateSettingsFlowRequest) (UpdateSettingsFlowResponse, error) {
	// valiate parameter
	if r.Body.Method == "password" {
		if r.Body.Password == "" {
			return UpdateSettingsFlowResponse{}, errors.New("missing password in body")
		}
	} else if r.Body.Method == "profile" {
		if r.Body.Traits == (Traits{}) {
			return UpdateSettingsFlowResponse{}, errors.New("missing traits in body")
		}
	} else {
		slog.ErrorContext(ctx, "UpdateSettingsFlow", "Method", r.Body.Method)
		return UpdateSettingsFlowResponse{}, fmt.Errorf("invalid method: %s", r.Body.Method)
	}

	// Request to kratos
	kratosInputBytes, err := json.Marshal(r.Body)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateSettingsFlow", "json unmarshal error", err)
		return UpdateSettingsFlowResponse{}, err
	}
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method:    http.MethodPost,
		Path:      fmt.Sprintf("%s?flow=%s", PATH_SELF_SERVICE_UPDATE_SETTINGS_FLOW, r.FlowID),
		BodyBytes: kratosInputBytes,
		Header:    r.Header,
	})
	response := UpdateSettingsFlowResponse{
		Header: kratosResp.Header,
	}
	if err != nil {
		if kratosResp.StatusCode == http.StatusUnprocessableEntity {
			response.RedirectBrowserTo = err.(ErrorBrowserLocationChangeRequired).RedirectBrowserTo
		} else {
			slog.ErrorContext(ctx, "UpdateSettingsFlow", "requestKratosPublic error", err)
			return response, err
		}
	}

	// Parse response body
	var kratosRespBody kratosUpdateSettingsFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "UpdateSettingsFlow", "json unmarshal error", err)
		return response, err
	}

	// Create response
	for _, c := range kratosRespBody.ContinueWith {
		if c.Action == "show_verification_ui" {
			response.VerificationFlowID = c.Flow.ID
		}
		if c.Action == "show_settings_ui" {
			response.SettingsFlowID = c.Flow.ID
		}
	}

	return response, nil
}
