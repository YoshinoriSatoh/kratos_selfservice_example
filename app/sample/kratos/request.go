package kratos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

type KratosRequestHeader struct {
	Cookie   string
	ClientIP string
}

type kratosRequest struct {
	Method    string
	Path      string
	BodyBytes []byte
	Header    KratosRequestHeader
}

type KratosResponseHeader struct {
	Cookie string
}

type kratosResponse struct {
	StatusCode int
	BodyBytes  []byte
	Header     KratosResponseHeader
}

func (p *Provider) requestKratosPublic(ctx context.Context, i kratosRequest) (kratosResponse, error) {
	return requestKratos(ctx, pkgVars.kratosPublicEndpoint, i)
}

func (p *Provider) requestKratosAdmin(ctx context.Context, i kratosRequest) (kratosResponse, error) {
	return requestKratos(ctx, pkgVars.kratosAdminEndpoint, i)
}

func requestKratos(ctx context.Context, endpoint string, i kratosRequest) (kratosResponse, error) {
	if i.Path != "/sessions/whoami" {
		slog.InfoContext(ctx, "requestKratos", "endpoint", endpoint, "input", i, "input.body", string(i.BodyBytes))
	}
	// slog.DebugContext(ctx, "requestKratos", "Cookie", r.Header.Get("Cookie"))

	req, err := http.NewRequest(
		i.Method,
		fmt.Sprintf("%s%s", endpoint, i.Path),
		bytes.NewBuffer(i.BodyBytes))
	if err != nil {
		slog.ErrorContext(ctx, "requestKratos", "NewRequestError", err)
		return kratosResponse{}, err
	}
	req.Header.Set("Cookie", i.Header.Cookie)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("True-Client-IP", i.Header.ClientIP)
	// req.Header.Set("X-Forwarded-For", r.RemoteAddr)

	// slog.DebugContext(ctx, "req", "Cookie", req.Header.Get("Cookie"))
	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "requestKratos", "http client do error", err)
		return kratosResponse{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.ErrorContext(ctx, "requestKratos", "read response body error", err)
		return kratosResponse{}, err
	}

	if i.Path != "/sessions/whoami" {
		slog.InfoContext(ctx, "requestKratos", "status code", resp.StatusCode, "body", string(body))
	}
	return kratosResponse{
		BodyBytes:  body,
		StatusCode: resp.StatusCode,
		Header: KratosResponseHeader{
			Cookie: strings.Join(resp.Header["Set-Cookie"], ";"),
		},
	}, getKratosError(ctx, body, resp.StatusCode)
}

func getKratosError(ctx context.Context, bodyBytes []byte, statusCode int) error {
	if statusCode == http.StatusOK {
		var resp kratosSuccessResponse
		if err := json.Unmarshal(bodyBytes, &resp); err != nil {
			slog.ErrorContext(ctx, "getErrorFromOutput", "json unmarshal error", err)
			return err
		}
		if resp.Ui == nil {
			return nil
		} else {
			return getErrorMessagesFromUi(*resp.Ui)
		}
	} else if statusCode == http.StatusBadRequest {
		// status code 400 の場合のレスポンスボディのフォーマットは複数存在する
		var resp kratosBadRequestErrorResponse
		if err := json.Unmarshal(bodyBytes, &resp); err != nil {
			slog.ErrorContext(ctx, "getErrorFromOutput", "json unmarshal error", err)
			return err
		}
		if resp.Error != nil {
			return *resp.Error
		} else if resp.Ui != nil {
			return getErrorMessagesFromUi(*resp.Ui)
		} else {
			slog.InfoContext(ctx, "Unknown error response format")
			return errors.New("unknown error response format")
		}
	} else if statusCode == http.StatusUnprocessableEntity {
		var errorBrowserLocationChangeRequired ErrorBrowserLocationChangeRequired
		if err := json.Unmarshal(bodyBytes, &errorBrowserLocationChangeRequired); err != nil {
			slog.ErrorContext(ctx, "getErrorFromOutput", "json unmarshal error", err)
			return err
		}
		return errorBrowserLocationChangeRequired
	} else {
		var errGeneric ErrorGeneric
		if err := json.Unmarshal(bodyBytes, &errGeneric); err != nil {
			slog.ErrorContext(ctx, "getErrorFromOutput", "json unmarshal error", err)
			return err
		}
		return errGeneric
	}
}

func getCsrfTokenFromFlowUi(ui uiContainer) string {
	for _, node := range ui.Nodes {
		if node.Attributes.Name == "csrf_token" {
			return node.Attributes.Value.(string)
		}
	}
	slog.Error("Missing csrf_token")
	return ""
}

func getErrorMessagesFromUi(ui uiContainer) error {
	var messages ErrorUiMessages
	for _, v := range ui.Messages {
		if v.Type == "error" {
			messages = append(messages, ErrorUiMessage{
				ID:   v.ID,
				Type: v.Type,
			})
		}
	}

	if len(messages) > 0 {
		return messages
	} else {
		return nil
	}
}

func getDuplicateIdentifierFromUi(ui uiContainer) string {
	slog.Info(fmt.Sprintf("%v", ui))
	for _, v := range ui.Messages {
		slog.Info(fmt.Sprintf("%v", v))
		if v.ID == 1010016 && v.Type == "info" {
			slog.Info(fmt.Sprintf("%v", v.ID))
			slog.Info(fmt.Sprintf("%v", v.Text))
			return v.Context["duplicateIdentifier"].(string)
		}
	}

	return ""
}

// func getErrorMessagesFromGenericError(err GenericError) error {
// 	// slog.Info("getErrorMessagesFromGenericError")
// 	// https://www.ory.sh/docs/kratos/concepts/ui-user-interface#ui-error-codes
// 	if err.ID == "security_csrf_violation" {
// 		return Error{
// 			ID:      err.ID,
// 			Message: err.Message,
// 		}
// 	}
// 	return Error{}
// }
