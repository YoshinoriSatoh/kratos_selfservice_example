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
	ID string `json:"id"`
}

func AdminGetIdentity(ctx context.Context, r AdminGetIdentityRequest) (*Identity, error) {
	// Request to kratos
	kratosResp, err := requestKratosAdmin(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s/%s", PATH_ADMIN_LIST_IDENTITIES, r.ID),
	})
	if err != nil {
		slog.ErrorContext(ctx, "AdminGetIdentity", "requestKratosAdmin error", err)
		return &Identity{}, err
	}

	var identity Identity
	if err := json.Unmarshal(kratosResp.BodyBytes, &identity); err != nil {
		slog.ErrorContext(ctx, "AdminGetIdentity", "json unmarshal error", err)
		return &Identity{}, err
	}

	return &identity, nil
}

// --------------------------------------------------------------------------
// Admin List Identities
// --------------------------------------------------------------------------
type AdminListIdentitiesRequest struct {
	CredentialIdentifier string `json:"credentials_identifier"`
}

func AdminListIdentities(ctx context.Context, r AdminListIdentitiesRequest) ([]Identity, error) {
	// Request to kratos
	kratosResp, err := requestKratosAdmin(ctx, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s?credentials_identifier=%s", PATH_ADMIN_LIST_IDENTITIES, r.CredentialIdentifier),
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
