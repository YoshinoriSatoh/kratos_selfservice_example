package handler

import "net/http"

func (p *Provider) handlePostSmsSend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	p.d.Sms.Send(ctx, "test")
}
