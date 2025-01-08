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
)

type KratosRequestHeader struct {
	Cookie   []string
	ClientIP string
}

type kratosRequest struct {
	Method    string
	Path      string
	Query     map[string]string
	BodyBytes []byte
	Header    KratosRequestHeader
}

type KratosResponseHeader struct {
	Cookie []string
}

type kratosResponse struct {
	StatusCode int
	BodyBytes  []byte
	Header     KratosResponseHeader
}

func requestKratosPublic(ctx context.Context, i kratosRequest) (kratosResponse, KratosRequestHeader, error) {
	resp, err := requestKratos(ctx, pkgVars.kratosPublicEndpoint, i)
	reqHeader := i.Header
	reqHeader.Cookie = resp.Header.Cookie
	// reqHeader.Cookie = strings.Join(resp.Header.Cookie, " ")
	return resp, reqHeader, err
}

func requestKratosAdmin(ctx context.Context, i kratosRequest) (kratosResponse, error) {
	return requestKratos(ctx, pkgVars.kratosAdminEndpoint, i)
}

func requestKratos(ctx context.Context, endpoint string, i kratosRequest) (kratosResponse, error) {
	// if i.Path != "/sessions/whoami" {
	// 	slog.InfoContext(ctx, "requestKratos", "endpoint", endpoint, "input", i, "input.body", string(i.BodyBytes))
	// }
	// slog.DebugContext(ctx, "requestKratos", "Cookie", r.Header.Get("Cookie"))

	req, err := http.NewRequest(
		i.Method,
		fmt.Sprintf("%s%s", endpoint, i.Path),
		bytes.NewBuffer(i.BodyBytes))
	if err != nil {
		slog.ErrorContext(ctx, "requestKratos", "NewRequestError", err)
		return kratosResponse{}, err
	}
	// req.Header.Set("Cookie", i.Header.Cookie)
	for _, v := range i.Header.Cookie {
		req.Header.Add("Cookie", v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("True-Client-IP", i.Header.ClientIP)
	// req.Header.Set("X-Forwarded-For", r.RemoteAddr)

	if len(i.Query) > 0 {
		query := req.URL.Query()
		for k, v := range i.Query {
			query.Add(k, v)
		}
		req.URL.RawQuery = query.Encode()
	}

	if i.Path != "/sessions/whoami" {
		slog.InfoContext(ctx, "requestKratos", "request", req)
	}

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
		slog.InfoContext(ctx, "requestKratos", "status code", resp.StatusCode, "body", string(body), "header", resp.Header)
	}

	return kratosResponse{
		BodyBytes:  body,
		StatusCode: resp.StatusCode,
		Header: KratosResponseHeader{
			Cookie: resp.Header["Set-Cookie"],
		},
	}, getKratosError(ctx, body, resp.StatusCode)
}

// status code 400 の場合のレスポンスボディのフォーマット
// ドキュメントではregistration flowが返却される記載しかないが、GenericErrorが返却される場合もある
// どちらの場合にも対応するため、必要なフィールドを全て定義している
type kratosBadRequestErrorResponse struct {
	Ui    *uiContainer  `json:"ui,omitempty"`
	Error *GenericError `json:"error,omitempty"`
}

func getKratosError(ctx context.Context, bodyBytes []byte, statusCode int) error {
	if statusCode == http.StatusOK {
		// UI Containerのmessages(type=error)があれば取得する
		var resp kratosSuccessResponse
		if err := json.Unmarshal(bodyBytes, &resp); err != nil {
			// status=okの場合に、レスポンスにuiがない場合はエラーがないものとして扱う
			// slog.DebugContext(ctx, "getErrorFromOutput", "json unmarshal error", err)
			return nil
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
		slog.DebugContext(ctx, "getKratosError", "statusCode", statusCode)
		var errorBrowserLocationChangeRequired ErrorBrowserLocationChangeRequired
		if err := json.Unmarshal(bodyBytes, &errorBrowserLocationChangeRequired); err != nil {
			slog.ErrorContext(ctx, "getErrorFromOutput", "json unmarshal error", err)
			return err
		}
		return errorBrowserLocationChangeRequired
	} else {
		if len(bodyBytes) == 0 {
			return nil
		}

		var errGeneric ErrorGeneric
		slog.ErrorContext(ctx, "getErrorFromOutput", "body bytes", string(bodyBytes))
		if err := json.Unmarshal(bodyBytes, &errGeneric); err != nil {
			slog.ErrorContext(ctx, "getErrorFromOutput", "json unmarshal error", err)
			return err
		}

		// aal2 required for session
		if statusCode == http.StatusForbidden && errGeneric.Err.ID == "session_aal2_required" {

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
				Text: v.Text,
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

func hasUiError(err error, id int64) bool {
	var kratosErrorUiMessages ErrorUiMessages
	if errors.As(err, &kratosErrorUiMessages) {
		for _, v := range err.(ErrorUiMessages) {
			if v.ID == id {
				return true
			}
		}
	}
	return false
}
