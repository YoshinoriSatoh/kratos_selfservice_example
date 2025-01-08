package kratos

import "time"

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
