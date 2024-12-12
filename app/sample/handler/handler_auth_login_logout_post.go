package handler

import (
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
)

// --------------------------------------------------------------------------
// POST /auth/logout
// --------------------------------------------------------------------------
func (p *Provider) handlePostAuthLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	topIndexView := newView("top/index.html")

	updateLogoutFlowResp, err := kratos.Logout(ctx, kratos.LogoutRequest{
		Header: makeDefaultKratosRequestHeader(r),
	})
	if err != nil {
		setHeadersForReplaceBody(w, "/")
		topIndexView.addParams(map[string]any{
			"Items": items,
		}).render(w, r, session)
	}

	// change location
	addCookies(w, updateLogoutFlowResp.Header.Cookie)
	w.Header().Set("HX-Location", "/")
}
