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

type AdminGetIdentityInput struct {
	ID                string `json:"id"`
	IncludeCredential string `json:"include_credential"`
}

func (p *Provider) AdminGetIdentity(ctx context.Context, w http.ResponseWriter, r *http.Request, i AdminGetIdentityInput) (Identity, error) {
	var (
		err error
	)

	kratosResp, err := p.requestKratosAdmin(ctx, w, r, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("/admin/identities/%s?include_credential=%s", i.ID, i.IncludeCredential),
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

type AdminListIdentitiesInput struct {
	CredentialIdentifier string `json:"credential_identifier"`
}

func (p *Provider) AdminListIdentities(ctx context.Context, w http.ResponseWriter, r *http.Request, i AdminListIdentitiesInput) ([]Identity, error) {
	var (
		err error
	)

	kratosResp, err := p.requestKratosAdmin(ctx, w, r, kratosRequest{
		Method: http.MethodGet,
		Path:   fmt.Sprintf("%s?credential_identifier=%s", PATH_ADMIN_LIST_IDENTITIES, i.CredentialIdentifier),
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
