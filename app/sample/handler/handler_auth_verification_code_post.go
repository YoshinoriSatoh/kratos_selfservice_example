package handler

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/YoshinoriSatoh/kratos_example/kratos"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// --------------------------------------------------------------------------
// POST /auth/verificatoin/code
// --------------------------------------------------------------------------
// Request parameters for handlePostAuthRegistrationCode
type postAuthVerificationCodeRequestParams struct {
	FlowID    string `validate:"uuid4"`
	CsrfToken string `validate:"required"`
	Code      string `validate:"required,len=6,number" ja:"検証コード"`
	Render    string
}

// Extract parameters from http request
func newPostAuthVerificationCodeRequestParams(r *http.Request) *postAuthVerificationCodeRequestParams {
	return &postAuthVerificationCodeRequestParams{
		FlowID:    r.URL.Query().Get("flow"),
		Render:    r.PostFormValue("render"),
		CsrfToken: r.PostFormValue("csrf_token"),
		Code:      r.PostFormValue("code"),
	}
}

// Return parameters that can refer in view template
func (p *postAuthVerificationCodeRequestParams) toViewParams() map[string]any {
	return map[string]any{
		"VerificationFlowID": p.FlowID,
		"Render":             p.Render,
		"CsrfToken":          p.CsrfToken,
		"Code":               p.Code,
	}
}

// Validate request parameters and return viewError
// If you do not want Validation errors to be displayed near input fields,
// store them in ErrorMessages and return them, so that the errors are displayed anywhere in the template.
func (params *postAuthVerificationCodeRequestParams) validate() *viewError {
	viewError := newViewError().extract(pkgVars.validate.Struct(params))

	for k := range viewError.validationFieldErrors {
		if k == "FlowID" || k == "CsrfToken" {
			viewError.messages = append(viewError.messages, newErrorMsg(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "ERR_FALLBACK",
			})))
			break
		}
	}
	// Individual validations write here that cannot validate in common validations

	return viewError
}

// Views
type postAuthVerificationCodeViews struct {
	verificationCode *view
	loginIndex       *view
}

// collect rendering data and validate request parameters.
func preparePostAuthVerificationCode(w http.ResponseWriter, r *http.Request) (*postAuthVerificationCodeRequestParams, postAuthVerificationCodeViews, *viewError, error) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data
	baseViewError := newViewError().addMessage(pkgVars.loc.MustLocalize(&i18n.LocalizeConfig{
		MessageID: "ERR_VERIFICATION_DEFAULT",
	}))
	reqParams := newPostAuthVerificationCodeRequestParams(r)
	views := postAuthVerificationCodeViews{
		verificationCode: newView("auth/verification/_code_form.html").addParams(reqParams.toViewParams()),
		loginIndex:       newView("auth/login/index.html").addParams(reqParams.toViewParams()),
	}

	// validate request parameters
	if viewError := reqParams.validate(); viewError.hasError() {
		views.verificationCode.addParams(viewError.toViewParams()).render(w, r, session)
		return reqParams, views, baseViewError, fmt.Errorf("validation error: %v", viewError)
	}

	return reqParams, views, baseViewError, nil
}

func (p *Provider) handlePostAuthVerificationCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := getSession(ctx)

	// collect rendering data and validate request parameters.
	reqParams, views, baseViewError, err := preparePostAuthVerificationCode(w, r)
	if err != nil {
		slog.ErrorContext(ctx, "preparePostAuthVerificationCode failed", "err", err)
		return
	}

	// Verification Flow 更新
	_, kratosReqHeaderForNext, err := kratos.UpdateVerificationFlow(ctx, kratos.UpdateVerificationFlowRequest{
		FlowID: reqParams.FlowID,
		Header: makeDefaultKratosRequestHeader(r),
		Body: kratos.UpdateVerificationFlowRequestBody{
			Code:      reqParams.Code,
			CsrfToken: reqParams.CsrfToken,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "update verification error", "err", err.Error())
		views.verificationCode.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	if reqParams.Render != "" {
		fmt.Println(reqParams.Render)
		v := viewFromQueryParam(reqParams.Render)
		setHeadersForReplaceBody(w, v.Path)
		viewFromQueryParam(reqParams.Render).render(w, r, session)
		return
	}

	// create login flow
	createLoginFlowResp, _, err := kratos.CreateLoginFlow(ctx, kratos.CreateLoginFlowRequest{
		Header:  kratosReqHeaderForNext,
		Refresh: true,
		Aal:     kratos.Aal1,
	})
	if err != nil {
		slog.ErrorContext(ctx, "update verification error", "err", err.Error())
		views.verificationCode.addParams(baseViewError.extract(err).toViewParams()).render(w, r, session)
		return
	}

	// render page
	addCookies(w, createLoginFlowResp.Header.Cookie)
	setHeadersForReplaceBody(w, fmt.Sprintf("/auth/login?flow=%s", createLoginFlowResp.LoginFlow.FlowID))
	views.loginIndex.addParams(map[string]any{
		"LoginFlowID": createLoginFlowResp.LoginFlow.FlowID,
		"Information": "コードによる検証が完了しました。お手数ですが改めてログインしてください。",
		"CsrfToken":   createLoginFlowResp.LoginFlow.CsrfToken,
	}).render(w, r, session)
}
