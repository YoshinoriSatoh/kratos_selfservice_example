package kratos

import (
	"log/slog"
	"strings"
	"time"
)

var (
	SettingsRequiredAal Aal
	SessionRequiredAal  Aal
	pkgVars             packageVariables
)

type packageVariables struct {
	locationJst                  *time.Location
	privilegedAccessLimitMinutes time.Duration
	kratosPublicEndpoint         string
	kratosAdminEndpoint          string
	// settingsRequiredAal          string
	// sessionRequiredAal           string
}

type InitInput struct {
	PrivilegedAccessLimitMinutes time.Duration
	KratosPublicEndpoint         string
	KratosAdminEndpoint          string
	SettingsRequiredAal          Aal
	SessionRequiredAal           Aal
}

func Init(i InitInput) {
	pkgVars.privilegedAccessLimitMinutes = i.PrivilegedAccessLimitMinutes
	pkgVars.kratosPublicEndpoint = i.KratosPublicEndpoint
	pkgVars.kratosAdminEndpoint = i.KratosAdminEndpoint
	SettingsRequiredAal = i.SettingsRequiredAal
	SessionRequiredAal = i.SessionRequiredAal

	var err error
	pkgVars.locationJst, err = time.LoadLocation("Asia/Tokyo")
	if err != nil {
		panic(err)
	}
}
func mergeProxyResponseCookies(reqCookie []string, proxyRespCookies []string) []string {
	var cookies []string
	var hasCsrfToken bool
	var hasSession bool
	for _, respcv := range proxyRespCookies {
		slog.Debug("mergeProxyResponseCookies", "respcv", respcv)
		v := strings.Split(respcv, ";")[0]
		cookies = append(cookies, v)
		if strings.HasPrefix(respcv, "csrf_token") {
			hasCsrfToken = true
		}
		if strings.HasPrefix(respcv, "kratos_session") {
			hasSession = true
		}
	}
	for _, reqcv := range reqCookie {
		// for _, reqcv := range strings.Split(reqCookie, "; ") {
		slog.Debug("mergeProxyResponseCookies", "reqcv", reqcv)
		if !hasCsrfToken && strings.HasPrefix(reqcv, "csrf_token") {
			cookies = append(cookies, reqcv)
		}
		if !hasSession && strings.HasPrefix(reqcv, "kratos_session") {
			cookies = append(cookies, reqcv)
		}
	}

	return cookies
	// return strings.Join(cookies, "; ")
}
