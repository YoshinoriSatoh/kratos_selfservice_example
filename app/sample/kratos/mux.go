package kratos

import (
	"context"
	"log/slog"
)

// --------------------------------------------------------------------------
// Link Identity if exists
// --------------------------------------------------------------------------

type KratosLinkIdentityIfExistsRequest struct {
	CredentialIdentifier string
	RequestHeader        KratosRequestHeader
	RegistrationFlow     RegistrationFlow
}

// Upaate identity when user already registered with the same credential of provided the oidc provider.
func KratosLinkIdentityIfExists(ctx context.Context, r KratosLinkIdentityIfExistsRequest) (*UpdateRegistrationFlowResponse, KratosRequestHeader, error) {
	identities, err := AdminListIdentities(ctx, AdminListIdentitiesRequest{
		CredentialIdentifier: r.CredentialIdentifier,
	})
	if err != nil {
		slog.Error("AdminGetIdentity failed", "error", err)
		return nil, r.RequestHeader, &Error{Err: err}
	}
	for _, identity := range identities {
		if identity.Traits.Email == r.CredentialIdentifier {
			// update Registration Flow
			kratosResp, kratosReqHeaderForNext, err := UpdateRegistrationFlow(ctx, UpdateRegistrationFlowRequest{
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
				return nil, kratosReqHeaderForNext, &Error{Err: err}
			}
			return &kratosResp, kratosReqHeaderForNext, nil
		}
	}
	return nil, r.RequestHeader, nil
}
