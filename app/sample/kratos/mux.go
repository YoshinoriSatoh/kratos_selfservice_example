package kratos

import (
	"context"
	"log/slog"
)

// --------------------------------------------------------------------------
// Link Identity if exists
// --------------------------------------------------------------------------

type KratosLinkIdentityIfExistsRequest struct {
	ID               string `json:"id"`
	RequestHeader    KratosRequestHeader
	RegistrationFlow RegistrationFlow
}

// Upaate identity when user already registered with the same credential of provided the oidc provider.
func KratosLinkIdentityIfExists(ctx context.Context, r KratosLinkIdentityIfExistsRequest) (*UpdateRegistrationFlowResponse, error) {
	identity, err := AdminGetIdentity(ctx, AdminGetIdentityRequest{
		ID: r.ID,
	})
	if err != nil {
		slog.Error("AdminGetIdentity failed", "error", err)
		return nil, &Error{Err: err}
	}
	if identity != nil {
		// update Registration Flow
		kratosResp, err := UpdateRegistrationFlow(ctx, UpdateRegistrationFlowRequest{
			FlowID: r.RegistrationFlow.FlowID,
			Header: r.RequestHeader,
			Body: UpdateRegistrationFlowRequestBody{
				Method:    "oidc",
				CsrfToken: r.RegistrationFlow.CsrfToken,
				Provider:  string(r.RegistrationFlow.OidcProvider),
				Traits:    identity.Traits,
			},
		})
		if err != nil {
			slog.Error("UpdateRegistrationFlow failed", "error", err)
			return nil, &Error{Err: err}
		}
		return &kratosResp, nil
	}
	return nil, nil
}
