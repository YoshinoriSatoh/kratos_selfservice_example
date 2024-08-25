package kratos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
	ID     string          `json:"id"`
	Ui     uiContainer     `json:"ui"`
	Active CredentialsType `json:"active"`
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
	response := GetRegistrationFlowResponse{
		Header: kratosResp.Header,
		RegistrationFlow: RegistrationFlow{
			FlowID:         kratosRespBody.ID,
			CsrfToken:      getCsrfTokenFromFlowUi(kratosRespBody.Ui),
			CredentialType: kratosRespBody.Active,
		},
	}
	if kratosRespBody.Active == CredentialsTypeOIDC {
		// Set to response the traits that was got from OIDC provider if OIDC callback
		setTraitsFromUiNodes(&response.RegistrationFlow.Traits, kratosRespBody.Ui.Nodes)
	} else if kratosRespBody.Active == CredentialsTypePasskey {
		response.RegistrationFlow.PasskeyCreateData = getPasskeyCreateData(kratosRespBody.Ui.Nodes)
	}

	return response, nil
}

// --------------------------------------------------------------------------
// Create Registration Flow
// --------------------------------------------------------------------------
type CreateRegistrationFlowRequest struct {
	Header   KratosRequestHeader
	ReturnTo string
}

type CreateRegistrationFlowResponse struct {
	Header           KratosResponseHeader
	RegistrationFlow RegistrationFlow
}

type kratosCreateRegisrationFlowRespnseBody struct {
	ID     string          `json:"id"`
	Ui     uiContainer     `json:"ui"`
	Active CredentialsType `json:"active"`
}

func (p *Provider) CreateRegistrationFlow(ctx context.Context, r CreateRegistrationFlowRequest) (CreateRegistrationFlowResponse, error) {
	// Request to kratos
	path := PATH_SELF_SERVICE_CREATE_REGISTRATION_FLOW
	if r.ReturnTo != "" {
		path = fmt.Sprintf("%s?return_to=%s", path, r.ReturnTo)
	}
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   path,
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
	response := CreateRegistrationFlowResponse{
		Header: kratosResp.Header,
		RegistrationFlow: RegistrationFlow{
			FlowID:         kratosRespBody.ID,
			CsrfToken:      getCsrfTokenFromFlowUi(kratosRespBody.Ui),
			CredentialType: kratosRespBody.Active,
		},
	}
	if kratosRespBody.Active == CredentialsTypePasskey {
		response.RegistrationFlow.PasskeyCreateData = getPasskeyCreateData(kratosRespBody.Ui.Nodes)
	}

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
	CsrfToken       string  `json:"csrf_token"`
	Method          string  `json:"method"`
	Traits          Traits  `json:"traits"`
	Password        *string `json:"password"`
	Provider        *string `json:"provider"`
	PasskeyRegister *string `json:"passkey_register"`
}

type UpdateRegistrationFlowResponse struct {
	Header             KratosResponseHeader
	VerificationFlowID string
	RedirectBrowserTo  string
}

type kratosUpdateRegisrationFlowPasswordRespnseBody struct {
	ContinueWith []continueWith `json:"continue_with"`
	// Identity     Identity
	// Session      Session
	// SessionToken string
}

func (p *Provider) UpdateRegistrationFlow(ctx context.Context, r UpdateRegistrationFlowRequest) (UpdateRegistrationFlowResponse, error) {
	// valiate parameter
	if r.Body.Method == "password" {
		if r.Body.Password == nil {
			return UpdateRegistrationFlowResponse{}, errors.New("missing password in body")
		}
	} else if r.Body.Method == "oidc" {
		if r.Body.Provider == nil {
			return UpdateRegistrationFlowResponse{}, errors.New("missing provider in body")
		}
	} else if r.Body.Method == "passkey" {
		if r.Body.PasskeyRegister == nil {
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
	if err != nil {
		if kratosResp.StatusCode == http.StatusUnprocessableEntity {
			redirectBrowserTo = err.(ErrorBrowserLocationChangeRequired).RedirectBrowserTo
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
		Header:            kratosResp.Header,
		RedirectBrowserTo: redirectBrowserTo,
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
type CreateVerificationBrowserRequest struct {
	Header   KratosRequestHeader
	ReturnTo string
}

type CreateVerificationFlowResponse struct {
	Header           KratosResponseHeader
	VerificationFlow VerificationFlow
}

type kratosCreateVerificationFlowRespnseBody struct {
	ID string      `json:"id"`
	Ui uiContainer `json:"ui"`
}

func (p *Provider) CreateVerificationFlow(ctx context.Context, r CreateVerificationBrowserRequest) (CreateVerificationFlowResponse, error) {
	// Request to kratos
	path := PATH_SELF_SERVICE_CREATE_VERIFICATION_FLOW
	if r.ReturnTo != "" {
		path = fmt.Sprintf("%s?return_to=%s", path, r.ReturnTo)
	}
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   path,
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

type kratosUpdateVerificationFlowRequestBody struct {
	Method    string `json:"method"`
	Email     string `json:"email"`
	Code      string `json:"code"`
	CsrfToken string `json:"csrf_token"`
}

type UpdateVerificationFlowRequestBody struct {
	Code      string
	Email     string
	CsrfToken string
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
	// valiate and collect parameter
	//   email設定時は、Verification Flowを更新して、アカウント検証メールを送信
	//   code設定時は、Verification Flowを完了
	var kratosRequestBody kratosUpdateVerificationFlowRequestBody
	if r.Body.Email != "" && r.Body.Code == "" {
		kratosRequestBody = kratosUpdateVerificationFlowRequestBody{
			Method:    "code",
			Email:     r.Body.Email,
			CsrfToken: r.Body.CsrfToken,
		}
	} else if r.Body.Email == "" && r.Body.Code != "" {
		kratosRequestBody = kratosUpdateVerificationFlowRequestBody{
			Method:    "code",
			Code:      r.Body.Code,
			CsrfToken: r.Body.CsrfToken,
		}
	} else {
		slog.ErrorContext(ctx, "parameter convination error.", "email", r.Body.Email, "code", r.Body.Code)
		return UpdateVerificationFlowResponse{}, fmt.Errorf("parameter convination error. email: %s, code: %s", r.Body.Email, "code", r.Body.Code)
	}

	// Request to kratos
	kratosInputBytes, err := json.Marshal(kratosRequestBody)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateVerificationFlow", "json unmarshal error", err)
		return UpdateVerificationFlowResponse{}, err
	}
	kratosResp, err := p.requestKratosPublic(ctx, kratosRequest{
		Method:    http.MethodPost,
		Path:      fmt.Sprintf("%s?flow=%s", PATH_SELF_SERVICE_UPDATE_VERIFICATION_FLOW, r.FlowID),
		BodyBytes: kratosInputBytes,
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
	})
	if err != nil {
		slog.ErrorContext(ctx, "GeLoginFlow", "requestKratosPublic error", err)
		return GetLoginFlowResponse{}, err
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
	Header   KratosRequestHeader
	Refresh  bool
	ReturnTo string
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
	if r.ReturnTo != "" {
		path = fmt.Sprintf("%s?return_to=%s", path, r.ReturnTo)
	}
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

type UpdateLoginFlowInput struct {
	FlowID     string
	CsrfToken  string
	Identifier string
	Password   string
}

// Login Flow の送信(完了)
func (p *Provider) UpdateLoginFlow(ctx context.Context, w http.ResponseWriter, r *http.Request, i UpdateLoginFlowInput) (UpdateLoginFlowResponse, error) {
	kratosInput := kratosUpdateLoginFlowPasswordRequest{
		Method:     "password",
		Identifier: i.Identifier,
		Password:   i.Password,
		CsrfToken:  i.CsrfToken,
	}
	kratosInputBytes, err := json.Marshal(kratosInput)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateLoginFlow", "json unmarshal error", err)
		return UpdateLoginFlowResponse{}, err
	}

	kratosResp, err := p.requestKratosPublic(ctx, w, r, kratosRequest{
		Method:    http.MethodPost,
		Path:      fmt.Sprintf("%s?flow=%s", PATH_SELF_SERVICE_UPDATE_LOGIN_FLOW, i.FlowID),
		BodyBytes: kratosInputBytes,
	})
	if err != nil {
		slog.ErrorContext(ctx, "UpdateLoginFlow", "requestKratosPublic error", err)
		return UpdateLoginFlowResponse{}, err
	}

	kratosError := getKratosError(ctx, kratosResp.BodyBytes, kratosResp.StatusCode)
	if kratosError != nil {
		slog.ErrorContext(ctx, "UpdateLoginFlow", "kratos error", kratosError)
		return UpdateLoginFlowResponse{}, fmt.Errorf("kratos error: %w", kratosError)
	}

	var updateRegistrationFlowResp kratosUpdateRegisrationFlowPasswordRespnse
	if err := json.Unmarshal(kratosResp.BodyBytes, &updateRegistrationFlowResp); err != nil {
		slog.ErrorContext(ctx, "UpdateLoginFlow", "json unmarshal error", err)
		return UpdateLoginFlowResponse{}, err
	}

	// Cookie引き継ぎ
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))

	return UpdateLoginFlowResponse{
		RedirectBrowserTo: updateRegistrationFlowResp.RedirectBrowserTo,
	}, nil
}

type UpdateOidcLoginFlowInput struct {
	FlowID    string
	CsrfToken string
	Provider  string
}

func (p *Provider) UpdateOidcLoginFlow(ctx context.Context, w http.ResponseWriter, r *http.Request, i UpdateOidcLoginFlowInput) (UpdateLoginFlowResponse, error) {
	kratosInput := kratosUpdateLoginFlowOidcRequest{
		Method:    "oidc",
		CsrfToken: i.CsrfToken,
		Provider:  i.Provider,
	}
	kratosInputBytes, err := json.Marshal(kratosInput)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateLoginFlow", "json unmarshal error", err)
		return UpdateLoginFlowResponse{}, err
	}

	_, err = p.requestKratosPublic(ctx, w, r, kratosRequest{
		Method:    http.MethodPost,
		Path:      fmt.Sprintf("%s?flow=%s", PATH_SELF_SERVICE_UPDATE_LOGIN_FLOW, i.FlowID),
		BodyBytes: kratosInputBytes,
	})
	if err != nil {
		slog.ErrorContext(ctx, "UpdateLoginFlow", "requestKratosPublic error", err)
		return UpdateLoginFlowResponse{}, err
	}

	// Cookie引き継ぎ
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))

	return UpdateLoginFlowResponse{}, nil
}

// ------------------------- Logout -------------------------

func (p *Provider) Logout(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	kratosRespCreateFlow, err := p.requestKratosPublic(ctx, w, r, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_GET_LOGOUT_FLOW,
	})
	if err != nil {
		slog.ErrorContext(ctx, "Logout", "requestKratosPublic error", err)
		return err
	}

	var kratosRespBodyCreateFlow kratosCreateLogoutFlowRespnse
	if err := json.Unmarshal(kratosRespCreateFlow.BodyBytes, &kratosRespBodyCreateFlow); err != nil {
		slog.ErrorContext(ctx, "Logout", "json unmarshal error", err)
		return err
	}

	updateLogoutResp, err := p.requestKratosPublic(ctx, w, r, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s?flow=%s&token=%s", PATH_SELF_SERVICE_UPDATE_LOGOUT_FLOW, kratosRespBodyCreateFlow.ID, kratosRespBodyCreateFlow.LogoutToken),
	})
	if err != nil {
		slog.ErrorContext(ctx, "Logout", "requestKratosPublic error", err)
		return err
	}
	var kratosRespBodyUpdateFlow kratosUpdateLogoutFlowRequest
	if err := json.Unmarshal(updateLogoutResp.BodyBytes, &kratosRespBodyUpdateFlow); err != nil {
		slog.ErrorContext(ctx, "Logout", "json unmarshal error", err)
		return err
	}

	// Cookie引き継ぎ
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))

	return nil
}

// ------------------------- Recovery Flow -------------------------
type GetRecoveryFlowInput struct {
	FlowID string
}

func (p *Provider) GetRecoveryFlow(ctx context.Context, w http.ResponseWriter, r *http.Request, i GetRecoveryFlowInput) (RecoveryFlow, error) {
	kratosResp, err := p.requestKratosPublic(ctx, w, r, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s?id=%s", PATH_SELF_SERVICE_GET_RECOVERY_FLOW, i.FlowID),
	})
	if err != nil {
		slog.ErrorContext(ctx, "GetRecoveryFlow", "requestKratosPublic error", err)
		return RecoveryFlow{}, err
	}

	var getRecoveryFlowResp kratosGetRecoveryFlowRespnse
	if err := json.Unmarshal(kratosResp.BodyBytes, &getRecoveryFlowResp); err != nil {
		slog.ErrorContext(ctx, "GetRecoveryFlow", "json unmarshal error", err)
		return RecoveryFlow{}, err
	}

	var recoveryFlow RecoveryFlow
	recoveryFlow.FlowID = getRecoveryFlowResp.ID
	recoveryFlow.CsrfToken = getCsrfTokenFromFlowUi(getRecoveryFlowResp.Ui)

	return recoveryFlow, nil
}

type CreateRecoveryFlowInput struct {
}

func (p *Provider) CreateRecoveryFlow(ctx context.Context, w http.ResponseWriter, r *http.Request, i CreateRecoveryFlowInput) (RecoveryFlow, error) {
	kratosResp, err := p.requestKratosPublic(ctx, w, r, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_CREATE_RECOVERY_FLOW,
	})
	if err != nil {
		slog.ErrorContext(ctx, "CreateRecoveryFlow", "requestKratosPublic error", err)
		return RecoveryFlow{}, err
	}

	var createRecoveryFlowResp kratosCreateRecoveryFlowRespnse
	if err := json.Unmarshal(kratosResp.BodyBytes, &createRecoveryFlowResp); err != nil {
		slog.ErrorContext(ctx, "CreateRecoveryFlow", "json unmarshal error", err)
		return RecoveryFlow{}, err
	}

	var recoveryFlow RecoveryFlow
	recoveryFlow.FlowID = createRecoveryFlowResp.ID
	recoveryFlow.CsrfToken = getCsrfTokenFromFlowUi(createRecoveryFlowResp.Ui)

	return recoveryFlow, nil
}

type UpdateRecoveryFlowInput struct {
	FlowID    string
	CsrfToken string
	Email     string
	Code      string
}

// Recovery Flow の送信(完了)
func (p *Provider) UpdateRecoveryFlow(ctx context.Context, w http.ResponseWriter, r *http.Request, i UpdateRecoveryFlowInput) (UpdateRecoveryFlowResponse, error) {
	var (
		kratosInput kratosUpdateRecoveryFlowRequest
	)

	// email設定時は、Recovery Flowを更新して、アカウント復旧メールを送信
	// code設定時は、Recovery Flowを完了
	if i.Email != "" && i.Code == "" {
		kratosInput = kratosUpdateRecoveryFlowRequest{
			Method:    "code",
			Email:     i.Email,
			CsrfToken: i.CsrfToken,
		}
	} else if i.Email == "" && i.Code != "" {
		kratosInput = kratosUpdateRecoveryFlowRequest{
			Method:    "code",
			Code:      i.Code,
			CsrfToken: i.CsrfToken,
		}
	} else {
		slog.ErrorContext(ctx, "parameter convination error.", "email", i.Email, "code", i.Code)
		return UpdateRecoveryFlowResponse{}, fmt.Errorf("parameter convination error. email: %s, code: %s", i.Email, i.Code)
	}
	kratosInputBytes, err := json.Marshal(kratosInput)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateRecoveryFlow", "json unmarshal error", err)
		return UpdateRecoveryFlowResponse{}, err
	}

	// Recovery Flow の送信(完了)
	_, err = p.requestKratosPublic(ctx, w, r, kratosRequest{
		Method:    http.MethodPost,
		Path:      fmt.Sprintf("%s?flow=%s", PATH_SELF_SERVICE_GET_RECOVERY_FLOW, i.FlowID),
		BodyBytes: kratosInputBytes,
	})
	if err != nil {
		slog.ErrorContext(ctx, "UpdateRecoveryFlow", "requestKratosPublic error", err)
		return UpdateRecoveryFlowResponse{}, err
	}

	// Cookie引き継ぎ
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))

	return UpdateRecoveryFlowResponse{}, nil
}

// ------------------------- Settings Flow -------------------------
type GetSettingsFlowInput struct {
	FlowID string
}

func (p *Provider) GetSettingsFlow(ctx context.Context, w http.ResponseWriter, r *http.Request, i GetSettingsFlowInput) (SettingsFlow, error) {
	var (
		err error
	)

	kratosResp, err := p.requestKratosPublic(ctx, w, r, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s?id=%s", PATH_SELF_SERVICE_GET_SETTINGS_FLOW, i.FlowID),
	})
	if err != nil {
		slog.ErrorContext(ctx, "CreateSettingsFlow", "requestKratosPublic error", err)
		return SettingsFlow{}, err
	}
	var kratosRespBody kratosGetSettingsFlowRespnse
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetSettingsFlow", "json unmarshal error", err)
		return SettingsFlow{}, err
	}

	var settingsFlow SettingsFlow
	settingsFlow.FlowID = kratosRespBody.ID
	settingsFlow.CsrfToken = getCsrfTokenFromFlowUi(kratosRespBody.Ui)

	return settingsFlow, nil
}

type CreateSettingsFlowInput struct {
}

func (p *Provider) CreateSettingsFlow(ctx context.Context, w http.ResponseWriter, r *http.Request, i CreateSettingsFlowInput) (SettingsFlow, error) {
	var (
		err error
	)

	kratosResp, err := p.requestKratosPublic(ctx, w, r, kratosRequest{
		Method: http.MethodGet,
		Path:   PATH_SELF_SERVICE_CREATE_SETTINGS_FLOW,
	})
	if err != nil {
		slog.ErrorContext(ctx, "CreateSettingsFlow", "requestKratosPublic error", err)
		return SettingsFlow{}, err
	}

	var kratosRespBody kratosCreateSettingsFlowRespnse
	if err := json.Unmarshal(kratosResp.BodyBytes, &kratosRespBody); err != nil {
		slog.ErrorContext(ctx, "GetSettingsFlow", "json unmarshal error", err)
		return SettingsFlow{}, err
	}

	var settingsFlow SettingsFlow
	settingsFlow.FlowID = kratosRespBody.ID
	settingsFlow.CsrfToken = getCsrfTokenFromFlowUi(kratosRespBody.Ui)

	return settingsFlow, nil
}

type UpdateSettingsFlowInput struct {
	FlowID    string
	CsrfToken string
	Method    string
	Password  string
	Traits    Traits
}

// Settings Flow (password) の送信(完了)
func (p *Provider) UpdateSettingsFlow(ctx context.Context, w http.ResponseWriter, r *http.Request, i UpdateSettingsFlowInput) (UpdateSettingsFlowResponse, error) {
	var (
		kratosInput kratosUpdateSettingsFlowRequest
		err         error
	)

	if i.Method == "password" {
		kratosInput = kratosUpdateSettingsFlowRequest{
			CsrfToken: i.CsrfToken,
			Method:    i.Method,
			Password:  i.Password,
		}
	} else if i.Method == "profile" {
		kratosInput = kratosUpdateSettingsFlowRequest{
			CsrfToken: i.CsrfToken,
			Method:    i.Method,
			Traits:    i.Traits,
		}
	} else {
		slog.ErrorContext(ctx, "UpdateSettingsFlow", "Method", i.Method)
		return UpdateSettingsFlowResponse{}, fmt.Errorf("invalid method: %s", i.Method)
	}

	kratosInputBytes, err := json.Marshal(kratosInput)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateSettingsFlow", "json unmarshal error", err)
		return UpdateSettingsFlowResponse{}, err
	}

	_, err = p.requestKratosPublic(ctx, w, r, kratosRequest{
		Method:    http.MethodPost,
		Path:      fmt.Sprintf("%s[?flow=%s", PATH_SELF_SERVICE_UPDATE_SETTINGS_FLOW, i.FlowID),
		BodyBytes: kratosInputBytes,
	})
	if err != nil {
		slog.ErrorContext(ctx, "UpdateSettingsFlow", "requestKratosPublic error", err)
		return UpdateSettingsFlowResponse{}, err
	}

	// Cookie引き継ぎ
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))

	return UpdateSettingsFlowResponse{}, nil
}

func jsonMarshal[T any](i T) ([]byte, error) {
	return json.Marshal(i)
}
