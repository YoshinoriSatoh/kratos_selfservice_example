package kratos

import "time"

var pkgVars packageVariables

type packageVariables struct {
	locationJst                  *time.Location
	privilegedAccessLimitMinutes time.Duration
	kratosPublicEndpoint         string
	kratosAdminEndpoint          string
}

type InitInput struct {
	PrivilegedAccessLimitMinutes time.Duration
	KratosPublicEndpoint         string
	KratosAdminEndpoint          string
}

func Init(i InitInput) {
	pkgVars.privilegedAccessLimitMinutes = i.PrivilegedAccessLimitMinutes
	pkgVars.kratosPublicEndpoint = i.KratosPublicEndpoint
	pkgVars.kratosAdminEndpoint = i.KratosAdminEndpoint

	var err error
	pkgVars.locationJst, err = time.LoadLocation("Asia/Tokyo")
	if err != nil {
		panic(err)
	}
}
