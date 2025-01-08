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
func KratosCreateOrGetRegistrationFlow(ctx context.Context, h KratosRequestHeader, flowID string) (RegistrationFlow, KratosResponseHeader, KratosRequestHeader, error) {
	var (
		err              error
		registrationFlow RegistrationFlow
		kratosReqHeader  KratosRequestHeader
		kratosRespHeader KratosResponseHeader
	)
	if flowID == "" {
		var createRegistrationFlowResp CreateRegistrationFlowResponse
		createRegistrationFlowResp, kratosReqHeader, err = CreateRegistrationFlow(ctx, CreateRegistrationFlowRequest{
			Header: h,
		})
		kratosRespHeader = createRegistrationFlowResp.Header
		registrationFlow = createRegistrationFlowResp.RegistrationFlow
	} else {
		var getRegistrationFlowResp GetRegistrationFlowResponse
		getRegistrationFlowResp, kratosReqHeader, err = GetRegistrationFlow(ctx, GetRegistrationFlowRequest{
			FlowID: flowID,
			Header: h,
		})
		kratosRespHeader = getRegistrationFlowResp.Header
		registrationFlow = getRegistrationFlowResp.RegistrationFlow
	}
	return registrationFlow, kratosRespHeader, kratosReqHeader, err
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

func GetRegistrationFlow(ctx context.Context, r GetRegistrationFlowRequest) (GetRegistrationFlowResponse, KratosRequestHeader, error) {
	// Request to kratos
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_GET_REGISTRATION_FLOW,
		Query:  map[string]string{"id": r.FlowID},
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "GetRegistrationFlow", "requestKratosPublic error", err)
		return GetRegistrationFlowResponse{}, kratosReqHeaderForNext, err
	}

	// Parse response body
	var kratosRespBody kratosGetRegisrationFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetRegistrationFlow", "json unmarshal error", err)
		return GetRegistrationFlowResponse{}, kratosReqHeaderForNext, err
	}

	// create response
	var oidcProvider OidcProvider
	if strings.Contains(kratosRespBody.RequestUrl, "self-service/methods/oidc/callback") {
		if strings.Contains(kratosRespBody.RequestUrl, "self-service/methods/oidc/callback/google") {
			oidcProvider = OidcProviderGoogle
		} else if strings.Contains(kratosRespBody.RequestUrl, "self-service/methods/oidc/callback/github") {
			oidcProvider = OidcProviderGithub
		}
	}
	response := GetRegistrationFlowResponse{
		Header: kratosResp.Header,
		RegistrationFlow: RegistrationFlow{
			FlowID:       kratosRespBody.ID,
			CsrfToken:    getCsrfTokenFromFlowUi(kratosRespBody.Ui),
			OidcProvider: oidcProvider,
		},
	}
	if oidcProvider.Provided() {
		// Set to response the traits that was got from OIDC provider if OIDC callback
		setTraitsFromUiNodes(&response.RegistrationFlow.Traits, kratosRespBody.Ui.Nodes)
	} else {
		response.RegistrationFlow.PasskeyCreateData = getPasskeyCreateData(kratosRespBody.Ui.Nodes)
	}

	return response, kratosReqHeaderForNext, nil
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

func CreateRegistrationFlow(ctx context.Context, r CreateRegistrationFlowRequest) (CreateRegistrationFlowResponse, KratosRequestHeader, error) {
	// Request to kratos
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_CREATE_REGISTRATION_FLOW,
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "CreateRegistrationFlow", "requestKratosPublic error", err)
		return CreateRegistrationFlowResponse{}, kratosReqHeaderForNext, err
	}

	// Parse response body
	var kratosRespBody kratosCreateRegisrationFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, err.Error())
		return CreateRegistrationFlowResponse{}, kratosReqHeaderForNext, err
	}

	// create response
	// var credentialsType CredentialsType
	// var oidcProvider OidcProvider
	// if strings.Contains(kratosRespBody.RequestUrl, "self-service/methods/oidc/callback") {
	// 	credentialsType = CredentialsTypeOidc
	// 	if strings.Contains(kratosRespBody.RequestUrl, "self-service/methods/oidc/callback/google") {
	// 		oidcProvider = OidcProviderGoogle
	// 	} else if strings.Contains(kratosRespBody.RequestUrl, "self-service/methods/oidc/callback/github") {
	// 		oidcProvider = OidcProviderGithub
	// 	}
	// } else {
	// 	credentialsType = CredentialsTypePassword
	// }
	response := CreateRegistrationFlowResponse{
		Header: kratosResp.Header,
		RegistrationFlow: RegistrationFlow{
			FlowID:       kratosRespBody.ID,
			CsrfToken:    getCsrfTokenFromFlowUi(kratosRespBody.Ui),
			OidcProvider: OidcProvider(""),
		},
	}
	// if credentialsType == CredentialsTypePasskey {
	// response.RegistrationFlow.PasskeyCreateData = getPasskeyCreateData(kratosRespBody.Ui.Nodes)
	// }

	return response, kratosReqHeaderForNext, nil
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
	Screen          string `json:"screen"`
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

func UpdateRegistrationFlow(ctx context.Context, r UpdateRegistrationFlowRequest) (UpdateRegistrationFlowResponse, KratosRequestHeader, error) {
	// valiate parameter
	if r.Body.Method == "password" {
		if r.Body.Password == "" {
			slog.ErrorContext(ctx, "missing password in body", "method", r.Body.Method)
			return UpdateRegistrationFlowResponse{}, r.Header, errors.New("missing password in body")
		}
	} else if r.Body.Method == "profile" {
		if r.Body.Screen != "credential-selection" {
			slog.ErrorContext(ctx, "invalid screen in body", "method", r.Body.Method, "screen", r.Body.Screen)
			return UpdateRegistrationFlowResponse{}, r.Header, errors.New("invalid screen in body")
		}
	} else if r.Body.Method == "oidc" {
		if r.Body.Provider == "" {
			slog.ErrorContext(ctx, "missing provider in body", "method", r.Body.Method)
			return UpdateRegistrationFlowResponse{}, r.Header, errors.New("missing provider in body")
		}
	} else if r.Body.Method == "passkey" {
		if r.Body.PasskeyRegister == "" {
			slog.ErrorContext(ctx, "missing passkey register in body", "method", r.Body.Method)
			return UpdateRegistrationFlowResponse{}, r.Header, errors.New("missing passkey register in body")
		}
	} else {
		slog.ErrorContext(ctx, "UpdateRegistrationFlow", "Method", r.Body.Method)
		return UpdateRegistrationFlowResponse{}, r.Header, fmt.Errorf("invalid method: %s", r.Body.Method)
	}

	// Request to kratos
	bodyBytes, err := json.Marshal(r.Body)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateRegistrationFlow", "json unmarshal error", err)
		return UpdateRegistrationFlowResponse{}, r.Header, err
	}
	kratosResp, kratosReqHeaderForNext, kratosErr := requestKratosPublic(ctx, kratosRequest{
		Method:    http.MethodPost,
		Path:      PATH_SELF_SERVICE_UPDATE_REGISTRATION_FLOW,
		Query:     map[string]string{"flow": r.FlowID},
		BodyBytes: bodyBytes,
		Header:    r.Header,
	})

	var redirectBrowserTo string
	var duplicateIdentifier string
	if kratosErr != nil {
		if kratosResp.StatusCode == http.StatusUnprocessableEntity {
			redirectBrowserTo = kratosErr.(ErrorBrowserLocationChangeRequired).RedirectBrowserTo
		} else if kratosResp.StatusCode == http.StatusBadRequest {
			// Parse response body (bad request)
			var kratosRespBadRequestBody kratosUpdateRegisrationFlowBadRequestRespnseBody
			if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBadRequestBody); err != nil {
				slog.ErrorContext(ctx, "UpdateRegistrationFlow", "json unmarshal error", err)
				return UpdateRegistrationFlowResponse{}, kratosReqHeaderForNext, err
			}
			duplicateIdentifier = getDuplicateIdentifierFromUi(kratosRespBadRequestBody.Ui)
		} else {
			slog.ErrorContext(ctx, "UpdateRegistrationFlow", "requestKratosPublic error", err)
			return UpdateRegistrationFlowResponse{}, kratosReqHeaderForNext, kratosErr
		}
	}

	// Parse response body
	var kratosRespBody kratosUpdateRegisrationFlowPasswordRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "UpdateRegistrationFlow", "json unmarshal error", err)
		return UpdateRegistrationFlowResponse{}, kratosReqHeaderForNext, err
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

	return response, kratosReqHeaderForNext, kratosErr
}

// --------------------------------------------------------------------------
// Create or Get Verification Flow
// --------------------------------------------------------------------------
// CreateOrGetVerificationFlow handles the logic for creating or getting a verification flow
func CreateOrGetVerificationFlow(ctx context.Context, h KratosRequestHeader, flowID string) (VerificationFlow, KratosResponseHeader, KratosRequestHeader, error) {
	var (
		err              error
		verificationFlow VerificationFlow
		kratosReqHeader  KratosRequestHeader
		kratosRespHeader KratosResponseHeader
	)
	if flowID == "" {
		var createVerificationFlowResp CreateVerificationFlowResponse
		createVerificationFlowResp, kratosReqHeader, err = CreateVerificationFlow(ctx, CreateVerificationFlowRequest{
			Header: h,
		})
		kratosRespHeader = createVerificationFlowResp.Header
		verificationFlow = createVerificationFlowResp.VerificationFlow
	} else {
		var getVerificationFlowResp GetVerificationFlowResponse
		getVerificationFlowResp, kratosReqHeader, err = GetVerificationFlow(ctx, GetVerificationFlowRequest{
			Header: h,
			FlowID: flowID,
		})
		kratosRespHeader = getVerificationFlowResp.Header
		verificationFlow = getVerificationFlowResp.VerificationFlow
	}
	return verificationFlow, kratosRespHeader, kratosReqHeader, err
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

func GetVerificationFlow(ctx context.Context, r GetVerificationFlowRequest) (GetVerificationFlowResponse, KratosRequestHeader, error) {
	// Request to kratos
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_GET_VERIFICATION_FLOW,
		Query:  map[string]string{"id": r.FlowID},
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "GetVerificationFlow", "requestKratosPublic error", err)
		return GetVerificationFlowResponse{}, kratosReqHeaderForNext, err
	}

	// Parse response body
	var kratosRespBody kratosGetVerificationFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetVerificationFlow", "json unmarshal error", err)
		return GetVerificationFlowResponse{}, kratosReqHeaderForNext, err
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

	return response, kratosReqHeaderForNext, nil
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

func CreateVerificationFlow(ctx context.Context, r CreateVerificationFlowRequest) (CreateVerificationFlowResponse, KratosRequestHeader, error) {
	// Request to kratos
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_CREATE_VERIFICATION_FLOW,
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "CreateVerificationFlow", "requestKratosPublic error", err)
		return CreateVerificationFlowResponse{}, kratosReqHeaderForNext, err
	}

	// Parse response body
	var kratosRespBody kratosCreateVerificationFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetVerificationFlow", "json unmarshal error", err)
		return CreateVerificationFlowResponse{}, kratosReqHeaderForNext, err
	}

	response := CreateVerificationFlowResponse{
		Header: kratosResp.Header,
		VerificationFlow: VerificationFlow{
			FlowID:    kratosRespBody.ID,
			CsrfToken: getCsrfTokenFromFlowUi(kratosRespBody.Ui),
		},
	}

	return response, kratosReqHeaderForNext, nil
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

func UpdateVerificationFlow(ctx context.Context, r UpdateVerificationFlowRequest) (UpdateVerificationFlowResponse, KratosRequestHeader, error) {
	// valiate parameter
	//   email設定時は、Verification Flowを更新して、アカウント検証メールを送信
	//   code設定時は、Verification Flowを完了
	if (r.Body.Email != "" && r.Body.Code != "") || (r.Body.Email == "" && r.Body.Code == "") {
		return UpdateVerificationFlowResponse{}, r.Header, fmt.Errorf("parameter convination error. email: %s, code: %s", r.Body.Email, "code", r.Body.Code)
	}

	// Request to kratos
	r.Body.Method = "code" // supported code only
	kratosInputBytes, err := json.Marshal(r.Body)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateVerificationFlow", "json unmarshal error", err)
		return UpdateVerificationFlowResponse{}, r.Header, err
	}
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method:    http.MethodPost,
		Path:      PATH_SELF_SERVICE_UPDATE_VERIFICATION_FLOW,
		Query:     map[string]string{"flow": r.FlowID},
		BodyBytes: kratosInputBytes,
		Header:    r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "UpdateVerificationFlow", "requestKratosPublic error", err)
		return UpdateVerificationFlowResponse{}, kratosReqHeaderForNext, err
	}

	// Parse response body
	var kratosRespBody kratosUpdateVerificationFlowResponseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetVerificationFlow", "json unmarshal error", err)
		return UpdateVerificationFlowResponse{}, kratosReqHeaderForNext, err
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

	return response, kratosReqHeaderForNext, nil
}

// --------------------------------------------------------------------------
// Create or Get Login Flow
// --------------------------------------------------------------------------
type CreateOrGetLoginFlowRequest struct {
	FlowID  string
	Header  KratosRequestHeader
	Refresh bool
	Aal     Aal
}

// CreateOrGetLoginFlow handles the logic for creating or getting a login flow
func CreateOrGetLoginFlow(ctx context.Context, r CreateOrGetLoginFlowRequest) (LoginFlow, KratosResponseHeader, KratosRequestHeader, error) {
	var (
		err              error
		loginFlow        LoginFlow
		kratosReqHeader  KratosRequestHeader
		kratosRespHeader KratosResponseHeader
	)
	if r.FlowID == "" {
		var createLoginFlowResp CreateLoginFlowResponse
		createLoginFlowResp, kratosReqHeader, err = CreateLoginFlow(ctx, CreateLoginFlowRequest{
			Header:  r.Header,
			Refresh: r.Refresh,
			Aal:     r.Aal,
		})
		kratosRespHeader = createLoginFlowResp.Header
		loginFlow = createLoginFlowResp.LoginFlow
	} else {
		var getLoginFlowResp GetLoginFlowResponse
		getLoginFlowResp, kratosReqHeader, err = GetLoginFlow(ctx, GetLoginFlowRequest{
			Header: r.Header,
			FlowID: r.FlowID,
		})
		kratosRespHeader = getLoginFlowResp.Header
		loginFlow = getLoginFlowResp.LoginFlow
	}
	return loginFlow, kratosRespHeader, kratosReqHeader, err
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

func GetLoginFlow(ctx context.Context, r GetLoginFlowRequest) (GetLoginFlowResponse, KratosRequestHeader, error) {
	// Request to kratos
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_GET_LOGIN_FLOW,
		Query:  map[string]string{"id": r.FlowID},
		Header: r.Header,
	})
	if err != nil {
		if !hasUiError(err, 4000007) {
			slog.ErrorContext(ctx, "GeLoginFlow", "requestKratosPublic error", err)
			return GetLoginFlowResponse{}, kratosReqHeaderForNext, err
		}
	}

	// Parse response body
	var FlowkratosRespBody kratosGetLoginFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &FlowkratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GeLoginFlow", "json unmarshal error", err)
		return GetLoginFlowResponse{}, kratosReqHeaderForNext, err
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

	return response, kratosReqHeaderForNext, nil
}

// --------------------------------------------------------------------------
// Create Login Flow
// --------------------------------------------------------------------------
type CreateLoginFlowRequest struct {
	Header  KratosRequestHeader
	Refresh bool
	Aal     Aal
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

func CreateLoginFlow(ctx context.Context, r CreateLoginFlowRequest) (CreateLoginFlowResponse, KratosRequestHeader, error) {
	// Request to kratos
	path := PATH_SELF_SERVICE_CREATE_LOGIN_FLOW
	query := map[string]string{}
	if r.Refresh {
		query["refresh"] = "true"
	}
	query["aal"] = string(r.Aal)

	slog.DebugContext(ctx, "CreateLoginFlow", "kratos query", query, "request", r)
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   path,
		Query:  query,
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "GetLoginFlow", "requestKratosPublic error", err)
		return CreateLoginFlowResponse{}, kratosReqHeaderForNext, err
	}

	// Parse response body
	var createLoginFlowResp kratosCreateLoginFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &createLoginFlowResp); err != nil {
		slog.ErrorContext(ctx, err.Error())
		return CreateLoginFlowResponse{}, kratosReqHeaderForNext, err
	}

	// create response
	var codeAddress string
	for _, node := range createLoginFlowResp.Ui.Nodes {
		if node.Group == "code" && node.Attributes.Name == "address" {
			codeAddress = node.Attributes.Value.(string)
		}
	}
	response := CreateLoginFlowResponse{
		Header: kratosResp.Header,
		LoginFlow: LoginFlow{
			FlowID:      createLoginFlowResp.ID,
			CsrfToken:   getCsrfTokenFromFlowUi(createLoginFlowResp.Ui),
			CodeAddress: codeAddress,
		},
	}
	for _, node := range createLoginFlowResp.Ui.Nodes {
		if node.Attributes.Name == "passkey_challenge" {
			response.LoginFlow.PasskeyChallenge = node.Attributes.Value.(string)
		}
	}

	return response, kratosReqHeaderForNext, nil
}

// --------------------------------------------------------------------------
// Update Login Flow
// --------------------------------------------------------------------------
type UpdateLoginFlowRequest struct {
	FlowID string
	Header KratosRequestHeader
	Aal    Aal
	Body   UpdateLoginFlowRequestBody
}

type UpdateLoginFlowRequestBody struct {
	CsrfToken    string `json:"csrf_token"`
	Method       string `json:"method"`
	Identifier   string `json:"identifier,omitempty"`
	Password     string `json:"password,omitempty"`
	Code         string `json:"code,omitempty"`
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
func UpdateLoginFlow(ctx context.Context, r UpdateLoginFlowRequest) (UpdateLoginFlowResponse, KratosRequestHeader, error) {
	// valiate parameter
	if r.Body.Method == "password" {
		if r.Body.Password == "" || r.Body.Identifier == "" {
			return UpdateLoginFlowResponse{}, r.Header, fmt.Errorf("parameter convination error. password: %s, identifier: %s", r.Body.Password, r.Body.Identifier)
		}
	} else if r.Body.Method == "code" {
		// if r.Body.Identifier == "" {
		// 	return UpdateLoginFlowResponse{}, r.Header, fmt.Errorf("parameter convination error. identifier: %s", r.Body.Identifier)
		// }
	} else if r.Body.Method == "oidc" {
		if r.Body.Provider == "" {
			return UpdateLoginFlowResponse{}, r.Header, fmt.Errorf("parameter convination error. provider: %s", r.Body.Provider)
		}
	} else if r.Body.Method == "passkey" {
		if r.Body.PasskeyLogin == "" {
			return UpdateLoginFlowResponse{}, r.Header, fmt.Errorf("parameter convination error. passkey: %s", r.Body.PasskeyLogin)
		}
	} else {
		slog.ErrorContext(ctx, "UpdateLoginFlow", "Method", r.Body.Method)
		return UpdateLoginFlowResponse{}, r.Header, fmt.Errorf("invalid method: %s", r.Body.Method)
	}

	// Request to kratos
	kratosInputBytes, err := json.Marshal(r.Body)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateLoginFlow", "json unmarshal error", err)
		return UpdateLoginFlowResponse{}, r.Header, err
	}
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method:    http.MethodPost,
		Path:      PATH_SELF_SERVICE_UPDATE_LOGIN_FLOW,
		Query:     map[string]string{"flow": r.FlowID, "aal": string(r.Aal)},
		BodyBytes: kratosInputBytes,
		Header:    r.Header,
	})
	slog.DebugContext(ctx, "UpdateLoginFlow", "kratosResp", string(kratosResp.BodyBytes), "err", err)
	if err != nil {
		if kratosResp.StatusCode == http.StatusUnprocessableEntity {
			return UpdateLoginFlowResponse{
				Header:            kratosResp.Header,
				RedirectBrowserTo: err.(ErrorBrowserLocationChangeRequired).RedirectBrowserTo,
			}, kratosReqHeaderForNext, nil
		} else {
			slog.ErrorContext(ctx, "UpdateLoginFlow", "requestKratosPublic error", err)
			return UpdateLoginFlowResponse{}, kratosReqHeaderForNext, err
		}
	}

	// Parse response body
	var kratosRespBody kratosUpdateLoginFlowResponseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "UpdateLoginFlow", "json unmarshal error", err)
		return UpdateLoginFlowResponse{}, kratosReqHeaderForNext, err
	}
	slog.DebugContext(ctx, "UpdateLoginFlow", "raw", string(kratosResp.BodyBytes))

	// Create response
	response := UpdateLoginFlowResponse{
		Header:  kratosResp.Header,
		Session: kratosRespBody.Session,
	}

	return response, kratosReqHeaderForNext, nil
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

func Logout(ctx context.Context, r LogoutRequest) (LogoutResponse, KratosRequestHeader, error) {
	// Request to kratos for create logout flow
	kratosRespCreateLogoutFlow, KratosRequestHeader, err := requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_GET_LOGOUT_FLOW,
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "Logout", "requestKratosPublic error", err)
		return LogoutResponse{}, KratosRequestHeader, err
	}

	// Parse response body for create logout flow
	var kratosRespBodyCreateLogoutFlow kratosCreateLogoutFlowRespnseBody
	if err := json.Unmarshal(kratosRespCreateLogoutFlow.BodyBytes, &kratosRespBodyCreateLogoutFlow); err != nil {
		slog.ErrorContext(ctx, "Logout", "json unmarshal error", err)
		return LogoutResponse{}, KratosRequestHeader, err
	}

	// Request to kratos for update logout flow
	kratosRespUpdateLogoutFlow, KratosRequestHeader, err := requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_UPDATE_LOGOUT_FLOW,
		Query:  map[string]string{"flow": kratosRespBodyCreateLogoutFlow.ID, "token": kratosRespBodyCreateLogoutFlow.LogoutToken},
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "Logout", "requestKratosPublic error", err)
		return LogoutResponse{}, KratosRequestHeader, err
	}

	// Parse response body for update logout flow
	if len(kratosRespUpdateLogoutFlow.BodyBytes) > 0 {
		var kratosRespBodyUpdateLogoutFlow kratosUpdateLogoutFlowRequestBody
		if err := json.Unmarshal(kratosRespUpdateLogoutFlow.BodyBytes, &kratosRespBodyUpdateLogoutFlow); err != nil {
			slog.ErrorContext(ctx, "Logout", "json unmarshal error", err)
			return LogoutResponse{}, KratosRequestHeader, err
		}
	}

	// Create response
	response := LogoutResponse{
		Header: kratosRespUpdateLogoutFlow.Header,
	}

	return response, KratosRequestHeader, nil
}

// --------------------------------------------------------------------------
// Create or Get Recovery Flow
// --------------------------------------------------------------------------
// CreateOrGetRecoveryFlow handles the logic for creating or getting a recovery flow
func CreateOrGetRecoveryFlow(ctx context.Context, h KratosRequestHeader, flowID string) (RecoveryFlow, KratosResponseHeader, KratosRequestHeader, error) {
	var (
		err              error
		recoveryFlow     RecoveryFlow
		kratosReqHeader  KratosRequestHeader
		kratosRespHeader KratosResponseHeader
	)
	if flowID == "" {
		var createRecoveryFlowResp CreateRecoveryFlowResponse
		createRecoveryFlowResp, kratosReqHeader, err = CreateRecoveryFlow(ctx, CreateRecoveryFlowRequest{
			Header: h,
		})
		kratosRespHeader = createRecoveryFlowResp.Header
		recoveryFlow = createRecoveryFlowResp.RecoveryFlow
	} else {
		var getRecoveryFlowResp GetRecoveryFlowResponse
		getRecoveryFlowResp, kratosReqHeader, err = GetRecoveryFlow(ctx, GetRecoveryFlowRequest{
			Header: h,
			FlowID: flowID,
		})
		kratosRespHeader = getRecoveryFlowResp.Header
		recoveryFlow = getRecoveryFlowResp.RecoveryFlow
	}
	return recoveryFlow, kratosRespHeader, kratosReqHeader, err
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

func GetRecoveryFlow(ctx context.Context, r GetRecoveryFlowRequest) (GetRecoveryFlowResponse, KratosRequestHeader, error) {
	// Request to kratos
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_GET_RECOVERY_FLOW,
		Query:  map[string]string{"id": r.FlowID},
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "GetRecoveryFlow", "requestKratosPublic error", err)
		return GetRecoveryFlowResponse{}, kratosReqHeaderForNext, err
	}

	// Parse response body
	var kratosRespBody kratosGetRecoveryFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetRecoveryFlow", "json unmarshal error", err)
		return GetRecoveryFlowResponse{}, kratosReqHeaderForNext, err
	}

	// create response
	response := GetRecoveryFlowResponse{
		Header: kratosResp.Header,
		RecoveryFlow: RecoveryFlow{
			FlowID:    kratosRespBody.ID,
			CsrfToken: getCsrfTokenFromFlowUi(kratosRespBody.Ui),
		},
	}

	return response, kratosReqHeaderForNext, nil
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

func CreateRecoveryFlow(ctx context.Context, r CreateRecoveryFlowRequest) (CreateRecoveryFlowResponse, KratosRequestHeader, error) {
	// Request to kratos
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_CREATE_RECOVERY_FLOW,
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "CreateRecoveryFlow", "requestKratosPublic error", err)
		return CreateRecoveryFlowResponse{}, kratosReqHeaderForNext, err
	}

	// Parse response body
	var kratosRespBody kratosCreateRecoveryFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "CreateRecoveryFlow", "json unmarshal error", err)
		return CreateRecoveryFlowResponse{}, kratosReqHeaderForNext, err
	}

	// create response
	response := CreateRecoveryFlowResponse{
		Header: kratosResp.Header,
		RecoveryFlow: RecoveryFlow{
			FlowID:    kratosRespBody.ID,
			CsrfToken: getCsrfTokenFromFlowUi(kratosRespBody.Ui),
		},
	}

	return response, kratosReqHeaderForNext, nil
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

func UpdateRecoveryFlow(ctx context.Context, r UpdateRecoveryFlowRequest) (UpdateRecoveryFlowResponse, KratosRequestHeader, error) {
	// valiate parameter
	if (r.Body.Email != "" && r.Body.Code != "") || (r.Body.Email == "" && r.Body.Code == "") {
		return UpdateRecoveryFlowResponse{}, r.Header, fmt.Errorf("parameter convination error. email: %s, code: %s", r.Body.Email, "code", r.Body.Code)
	}

	// Request to kratos
	kratosInputBytes, err := json.Marshal(r.Body)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateRecoveryFlow", "json unmarshal error", err)
		return UpdateRecoveryFlowResponse{}, r.Header, err
	}
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method:    http.MethodPost,
		Path:      PATH_SELF_SERVICE_UPDATE_RECOVERY_FLOW,
		Query:     map[string]string{"flow": r.FlowID},
		BodyBytes: kratosInputBytes,
		Header:    r.Header,
	})
	var redirectBrowserTo string
	if err != nil {
		if kratosResp.StatusCode == http.StatusUnprocessableEntity {
			redirectBrowserTo = err.(ErrorBrowserLocationChangeRequired).RedirectBrowserTo
		} else {
			slog.ErrorContext(ctx, "UpdateRecoveryFlow", "requestKratosPublic error", err)
			return UpdateRecoveryFlowResponse{}, kratosReqHeaderForNext, err
		}
	}

	// Parse response body
	var kratosRespBody kratosUpdateRecoveryFlowResponseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "UpdateRecoveryFlow", "json unmarshal error", err)
		return UpdateRecoveryFlowResponse{}, kratosReqHeaderForNext, err
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
	return response, kratosReqHeaderForNext, nil
}

// --------------------------------------------------------------------------
// Create or Get Settings Flow
// --------------------------------------------------------------------------
// CreateOrGetSettingsFlow handles the logic for creating or getting a settings flow
func CreateOrGetSettingsFlow(ctx context.Context, h KratosRequestHeader, flowID string) (SettingsFlow, KratosResponseHeader, KratosRequestHeader, error) {
	var (
		err              error
		settingsFlow     SettingsFlow
		kratosReqHeader  KratosRequestHeader
		kratosRespHeader KratosResponseHeader
	)
	if flowID == "" {
		var createSettingsFlowResp CreateSettingsFlowResponse
		createSettingsFlowResp, kratosReqHeader, err = CreateSettingsFlow(ctx, CreateSettingsFlowRequest{
			Header: h,
		})
		kratosRespHeader = createSettingsFlowResp.Header
		settingsFlow = createSettingsFlowResp.SettingsFlow
	} else {
		var getSettingsFlowResp GetSettingsFlowResponse
		getSettingsFlowResp, kratosReqHeader, err = GetSettingsFlow(ctx, GetSettingsFlowRequest{
			Header: h,
			FlowID: flowID,
		})
		kratosRespHeader = getSettingsFlowResp.Header
		settingsFlow = getSettingsFlowResp.SettingsFlow
	}
	return settingsFlow, kratosRespHeader, kratosReqHeader, err
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

func GetSettingsFlow(ctx context.Context, r GetSettingsFlowRequest) (GetSettingsFlowResponse, KratosRequestHeader, error) {
	// Request to kratos
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_GET_SETTINGS_FLOW,
		Query:  map[string]string{"id": r.FlowID},
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "GetSettingsFlow", "requestKratosPublic error", err)
		return GetSettingsFlowResponse{}, kratosReqHeaderForNext, err
	}

	// Parse response body
	var kratosRespBody kratosGetSettingsFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetSettingsFlow", "json unmarshal error", err)
		return GetSettingsFlowResponse{}, kratosReqHeaderForNext, err
	}

	// create response
	response := GetSettingsFlowResponse{
		Header: kratosResp.Header,
		SettingsFlow: SettingsFlow{
			FlowID:    kratosRespBody.ID,
			CsrfToken: getCsrfTokenFromFlowUi(kratosRespBody.Ui),
		},
	}

	return response, kratosReqHeaderForNext, nil
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

func CreateSettingsFlow(ctx context.Context, r CreateSettingsFlowRequest) (CreateSettingsFlowResponse, KratosRequestHeader, error) {
	// Request to kratos
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_CREATE_SETTINGS_FLOW,
		Header: r.Header,
	})
	if err != nil {
		slog.ErrorContext(ctx, "CreateSettingsFlow", "requestKratosPublic error", err)
		return CreateSettingsFlowResponse{}, kratosReqHeaderForNext, err
	}

	// Parse response body
	var kratosRespBody kratosCreateSettingsFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetSettingsFlow", "json unmarshal error", err)
		return CreateSettingsFlowResponse{}, kratosReqHeaderForNext, err
	}

	// create response
	response := CreateSettingsFlowResponse{
		Header: kratosResp.Header,
		SettingsFlow: SettingsFlow{
			FlowID:    kratosRespBody.ID,
			CsrfToken: getCsrfTokenFromFlowUi(kratosRespBody.Ui),
		},
	}

	return response, r.Header, nil
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

func UpdateSettingsFlow(ctx context.Context, r UpdateSettingsFlowRequest) (UpdateSettingsFlowResponse, KratosRequestHeader, error) {
	// valiate parameter
	if r.Body.Method == "password" {
		if r.Body.Password == "" {
			return UpdateSettingsFlowResponse{}, r.Header, errors.New("missing password in body")
		}
	} else if r.Body.Method == "profile" {
		if r.Body.Traits == (Traits{}) {
			return UpdateSettingsFlowResponse{}, r.Header, errors.New("missing traits in body")
		}
	} else {
		slog.ErrorContext(ctx, "UpdateSettingsFlow", "Method", r.Body.Method)
		return UpdateSettingsFlowResponse{}, r.Header, fmt.Errorf("invalid method: %s", r.Body.Method)
	}

	// Request to kratos
	kratosInputBytes, err := json.Marshal(r.Body)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateSettingsFlow", "json unmarshal error", err)
		return UpdateSettingsFlowResponse{}, r.Header, err
	}
	kratosResp, kratosReqHeaderForNext, err := requestKratosPublic(ctx, kratosRequest{
		Method:    http.MethodPost,
		Path:      PATH_SELF_SERVICE_UPDATE_SETTINGS_FLOW,
		Query:     map[string]string{"flow": r.FlowID},
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
			return response, kratosReqHeaderForNext, err
		}
	}

	// Parse response body
	var kratosRespBody kratosUpdateSettingsFlowRespnseBody
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "UpdateSettingsFlow", "json unmarshal error", err)
		return response, kratosReqHeaderForNext, err
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

	return response, kratosReqHeaderForNext, nil
}
