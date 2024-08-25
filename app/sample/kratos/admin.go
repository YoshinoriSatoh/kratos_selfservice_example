package kratos

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

const (
	PATH_ADMIN_LIST_IDENTITIES = "/admin/identities"
)

// --------------------------------------------------------------------------
// Admin Get Identity
// --------------------------------------------------------------------------
type AdminGetIdentityRequest struct {
	ID                string `json:"id"`
	IncludeCredential string `json:"include_credential"`
}

func (p *Provider) AdminGetIdentity(ctx context.Context, r AdminGetIdentityRequest) (Identity, error) {
	// Request to kratos
	kratosResp, err := p.requestKratosAdmin(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s/%s?include_credential=%s", PATH_ADMIN_LIST_IDENTITIES, r.ID, r.IncludeCredential),
	})
	if err != nil {
		slog.ErrorContext(ctx, "AdminGetIdentity", "requestKratosAdmin error", err)
		return Identity{}, err
	}

	var identity Identity
	if err := json.Unmarshal(kratosResp.BodyBytes, &identity); err != nil {
		slog.ErrorContext(ctx, "AdminGetIdentity", "json unmarshal error", err)
		return Identity{}, err
	}

	return identity, nil
}

// --------------------------------------------------------------------------
// Admin List Identities
// --------------------------------------------------------------------------
type AdminListIdentitiesRequest struct {
	CredentialIdentifier string `json:"credential_identifier"`
}

func (p *Provider) AdminListIdentities(ctx context.Context, r AdminListIdentitiesRequest) ([]Identity, error) {
	// Request to kratos
	kratosResp, err := p.requestKratosAdmin(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s?credential_identifier=%s", PATH_ADMIN_LIST_IDENTITIES, r.CredentialIdentifier),
	})
	if err != nil {
		slog.ErrorContext(ctx, "AdminListIdentity", "requestKratosAdmin error", err)
		return []Identity{}, err
	}

	var identities []Identity
	if err := json.Unmarshal(kratosResp.BodyBytes, &identities); err != nil {
		slog.ErrorContext(ctx, "AdminListIdentity", "json unmarshal error", err)
		return []Identity{}, err
	}

	return identities, nil
}
