package handler

// // Handler GET /my/password
// type handleGetMyPasswordRequestParams struct {
// 	flowID string
// }

// func (p *Provider) handleGetMyPassword(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	session := getSession(ctx)

// 	reqParams := handleGetMyPasswordRequestParams{
// 		flowID: r.URL.Query().Get("flow"),
// 	}

// 	var (
// 		err          error
// 		settingsFlow kratos.SettingsFlow
// 	)
// 	if reqParams.flowID == "" {
// 		settingsFlow, err = p.d.Kratos.CreateSettingsBrowserFlow(ctx, w, r, kratos.CreateSettingsFlowInput{})
// 	} else {
// 		settingsFlow, err = p.d.Kratos.GetSettingsBrowserFlow(ctx, w, r, kratos.GetSettingsFlowInput{
// 			FlowID: reqParams.flowID,
// 		})
// 	}
// 	if err != nil {
// 		slog.ErrorContext(ctx, err.Error())
// 		w.WriteHeader(http.StatusOK)
// 		var (
// 			kratosErr     kratos.Error
// 			errorMessages []string
// 		)
// 		if errors.As(err, &kratosErr) {
// 			errorMessages = kratosErr.Messages
// 		} else {
// 			errorMessages = []string{"エラーが発生しました。管理者にお問い合わせください。"}
// 		}
// 		tmplErr := pkgVars.tmpl.ExecuteTemplate(w, "my/password/index.html", viewParameters(session, r, map[string]any{
// 			"ErrorMessages": errorMessages,
// 		}))
// 		if tmplErr != nil {
// 			slog.ErrorContext(ctx, tmplErr.Error())
// 		}
// 		return
// 	}

// 	// flowの情報に従ってレンダリング
// 	tmplErr := pkgVars.tmpl.ExecuteTemplate(w, "my/password/index.html", viewParameters(session, r, map[string]any{
// 		"SettingsFlowID":       settingsFlow.FlowID,
// 		"CsrfToken":            settingsFlow.CsrfToken,
// 		"RedirectFromRecovery": reqParams.flowID == "recovery",
// 	}))
// 	if tmplErr != nil {
// 		slog.ErrorContext(ctx, tmplErr.Error())
// 	}
// }

// // Handler POST /my/password
// type handlePostMyPasswordRequestParams struct {
// 	flowID               string `validate:"uuid4"`
// 	csrfToken            string `validate:"required"`
// 	password             string `validate:"required" ja:"パスワード"`
// 	passwordConfirmation string `validate:"required" ja:"パスワード確認"`
// }

// func (p *handlePostMyPasswordRequestParams) validate() map[string]validationFieldError {
// 	fieldErrors := extractValidationFieldErrors(pkgVars.validate.Struct(p))
// 	if p.password != p.passwordConfirmation {
// 		fieldErrors["Password"] = validationFieldError{
// 			Tag:     "Password",
// 			Message: "パスワードとパスワード確認が一致しません",
// 		}
// 	}
// 	return fieldErrors
// }

// func (p *Provider) handlePostMyPassword(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	session := getSession(ctx)

// 	reqParams := handlePostMyPasswordRequestParams{
// 		flowID:               r.URL.Query().Get("flow"),
// 		csrfToken:            r.PostFormValue("csrf_token"),
// 		password:             r.PostFormValue("password"),
// 		passwordConfirmation: r.PostFormValue("password_confirmation"),
// 	}
// 	validationFieldErrors := reqParams.validate()
// 	if len(validationFieldErrors) > 0 {
// 		tmplErr := pkgVars.tmpl.ExecuteTemplate(w, "my/password/_form.html", viewParameters(session, r, map[string]any{
// 			"SettingsFlowID":       reqParams.flowID,
// 			"CsrfToken":            reqParams.csrfToken,
// 			"Password":             reqParams.password,
// 			"ValidationFieldError": validationFieldErrors,
// 		}))
// 		if tmplErr != nil {
// 			slog.Error(tmplErr.Error())
// 		}
// 		return
// 	}

// 	var (
// 		kratosErr     kratos.Error
// 		errorMessages []string
// 	)
// 	// Setting Flow 更新
// 	_, err := p.d.Kratos.UpdateSettingsBrowserFlow(ctx, w, r, kratos.UpdateSettingsFlowInput{
// 		FlowID:    reqParams.flowID,
// 		CsrfToken: reqParams.csrfToken,
// 		Method:    "password",
// 		Password:  reqParams.password,
// 	})
// 	if err != nil {
// 		if errors.As(err, &kratosErr) {
// 			errorMessages = kratosErr.Messages
// 		} else {
// 			errorMessages = []string{"エラーが発生しました。管理者にお問い合わせください。"}
// 		}
// 		w.WriteHeader(http.StatusOK)
// 		pkgVars.tmpl.ExecuteTemplate(w, "my/password/_form.html", viewParameters(session, r, map[string]any{
// 			"SettingsFlowID": reqParams.flowID,
// 			"CsrfToken":      reqParams.csrfToken,
// 			"Password":       reqParams.password,
// 			"ErrorMessages":  errorMessages,
// 		}))
// 	}

// 	redirect(w, r, "/")
// 	w.WriteHeader(http.StatusOK)
// }

// // Handler GET /my/profile
// type handleGetMyProfileRequestParams struct {
// 	flowID string
// }

// func (p *Provider) handleGetMyProfile(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	session := getSession(ctx)

// 	reqParams := handleGetMyProfileRequestParams{
// 		flowID: r.URL.Query().Get("flow"),
// 	}

// 	var (
// 		err          error
// 		settingsFlow kratos.SettingsFlow
// 	)
// 	// Setting flowを新規作成した場合は、FlowIDを含めてリダイレクト
// 	if reqParams.flowID == "" {
// 		settingsFlow, err = p.d.Kratos.CreateSettingsBrowserFlow(ctx, w, r, kratos.CreateSettingsFlowInput{})
// 	} else {
// 		settingsFlow, err = p.d.Kratos.GetSettingsBrowserFlow(ctx, w, r, kratos.GetSettingsFlowInput{
// 			FlowID: reqParams.flowID,
// 		})
// 	}
// 	if err != nil {
// 		slog.ErrorContext(ctx, err.Error())
// 		w.WriteHeader(http.StatusOK)
// 		var (
// 			kratosErr     kratos.Error
// 			errorMessages []string
// 		)
// 		if errors.As(err, &kratosErr) {
// 			errorMessages = kratosErr.Messages
// 		} else {
// 			errorMessages = []string{"エラーが発生しました。管理者にお問い合わせください。"}
// 		}
// 		tmplErr := pkgVars.tmpl.ExecuteTemplate(w, "my/profile/index.html", viewParameters(session, r, map[string]any{
// 			"ErrorMessages": errorMessages,
// 		}))
// 		if tmplErr != nil {
// 			slog.ErrorContext(ctx, tmplErr.Error())
// 		}
// 		return
// 	}

// 	// // flowの情報に従ってレンダリング
// 	// var information string
// 	// if existsAfterLoginHook(r, AFTER_LOGIN_HOOK_COOKIE_KEY_SETTINGS_PROFILE_UPDATE) {
// 	// 	information = "プロフィールを更新しました。"
// 	// 	deleteAfterLoginHook(w, AFTER_LOGIN_HOOK_COOKIE_KEY_SETTINGS_PROFILE_UPDATE)
// 	// }
// 	pkgVars.tmpl.ExecuteTemplate(w, "my/profile/index.html", viewParameters(session, r, map[string]any{
// 		"SettingsFlowID": settingsFlow.FlowID,
// 		"CsrfToken":      settingsFlow.CsrfToken,
// 		"Email":          session.Identity.Traits.Email,
// 		"Firstname":      session.Identity.Traits.Firstname,
// 		"Lastname":       session.Identity.Traits.Lastname,
// 		"Nickname":       session.Identity.Traits.Nickname,
// 		"Birthdate":      session.Identity.Traits.Birthdate,
// 		// "Information":    information,
// 	}))
// }

// // Handler GET /my/profile/edit
// type handleGetMyProfileEditRequestParams struct {
// 	flowID string
// }

// func (p *Provider) handleGetMyProfileEdit(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	session := getSession(ctx)

// 	reqParams := handleGetMyProfileEditRequestParams{
// 		flowID: r.URL.Query().Get("flow"),
// 	}

// 	var (
// 		err          error
// 		settingsFlow kratos.SettingsFlow
// 	)
// 	if reqParams.flowID == "" {
// 		settingsFlow, err = p.d.Kratos.CreateSettingsBrowserFlow(ctx, w, r, kratos.CreateSettingsFlowInput{})
// 	} else {
// 		settingsFlow, err = p.d.Kratos.GetSettingsBrowserFlow(ctx, w, r, kratos.GetSettingsFlowInput{
// 			FlowID: reqParams.flowID,
// 		})
// 	}
// 	if err != nil {
// 		slog.ErrorContext(ctx, err.Error())
// 		w.WriteHeader(http.StatusOK)
// 		var (
// 			kratosErr     kratos.Error
// 			errorMessages []string
// 		)
// 		if errors.As(err, &kratosErr) {
// 			errorMessages = kratosErr.Messages
// 		} else {
// 			errorMessages = []string{"エラーが発生しました。管理者にお問い合わせください。"}
// 		}
// 		tmplErr := pkgVars.tmpl.ExecuteTemplate(w, "my/profile/index.html", viewParameters(session, r, map[string]any{
// 			"ErrorMessages": errorMessages,
// 		}))
// 		if tmplErr != nil {
// 			slog.ErrorContext(ctx, tmplErr.Error())
// 		}
// 		return
// 	}
// 	// セッションから現在の値を取得
// 	params := loadProfileFromSessionIfEmpty(updateProfileParams{}, session)

// 	pkgVars.tmpl.ExecuteTemplate(w, "my/profile/edit.html", viewParameters(session, r, map[string]any{
// 		"SettingsFlowID": settingsFlow.FlowID,
// 		"CsrfToken":      settingsFlow.CsrfToken,
// 		"Email":          params.Email,
// 		"Firstname":      params.Firstname,
// 		"Lastname":       params.Lastname,
// 		"Nickname":       params.Nickname,
// 		"Birthdate":      params.Birthdate,
// 	}))
// }

// // Handler GET /my/profile/_form
// type handleGetMyProfileFormRequestParams struct {
// 	flowID string
// }

// func (p *Provider) handleGetMyProfileForm(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	session := getSession(ctx)

// 	reqParams := handleGetMyProfileFormRequestParams{}

// 	var (
// 		err          error
// 		settingsFlow kratos.SettingsFlow
// 	)
// 	if reqParams.flowID == "" {
// 		settingsFlow, err = p.d.Kratos.CreateSettingsBrowserFlow(ctx, w, r, kratos.CreateSettingsFlowInput{})
// 	} else {
// 		settingsFlow, err = p.d.Kratos.GetSettingsBrowserFlow(ctx, w, r, kratos.GetSettingsFlowInput{
// 			FlowID: reqParams.flowID,
// 		})
// 	}
// 	if err != nil {
// 		slog.ErrorContext(ctx, err.Error())
// 		w.WriteHeader(http.StatusOK)
// 		var (
// 			kratosErr     kratos.Error
// 			errorMessages []string
// 		)
// 		if errors.As(err, &kratosErr) {
// 			errorMessages = kratosErr.Messages
// 		} else {
// 			errorMessages = []string{"エラーが発生しました。管理者にお問い合わせください。"}
// 		}
// 		tmplErr := pkgVars.tmpl.ExecuteTemplate(w, "my/profile/form.html", viewParameters(session, r, map[string]any{
// 			"ErrorMessages": errorMessages,
// 		}))
// 		if tmplErr != nil {
// 			slog.ErrorContext(ctx, tmplErr.Error())
// 		}
// 		return
// 	}

// 	// セッションから現在の値を取得
// 	params := loadProfileFromSessionIfEmpty(updateProfileParams{}, session)

// 	pkgVars.tmpl.ExecuteTemplate(w, "my/profile/_form.html", viewParameters(session, r, map[string]any{
// 		"SettingsFlowID": settingsFlow.FlowID,
// 		"CsrfToken":      settingsFlow.CsrfToken,
// 		"Email":          params.Email,
// 		"Firstname":      params.Firstname,
// 		"Lastname":       params.Lastname,
// 		"Nickname":       params.Nickname,
// 		"Birthdate":      params.Birthdate,
// 	}))
// }

// // Handler POST /my/profile
// type handlePostMyProfileRequestPostForm struct {
// 	flowID    string `validate:"required,uuid4"`
// 	csrfToken string `validate:"required"`
// 	Email     string `validate:"required,email" ja:"メールアドレス"`
// 	Firstname string `validate:"required,min=5,max=20" ja:"氏名(性)"`
// 	Lastname  string `validate:"required,min=5,max=20" ja:"氏名(名)"`
// 	Nickname  string `validate:"required,min=5,max=20" ja:"ニックネーム"`
// 	Birthdate string `validate:"required,datatime=2006-01-02" ja:"生年月日"`
// }

// func (p *handlePostMyProfileRequestPostForm) validate() map[string]validationFieldError {
// 	fieldErrors := extractValidationFieldErrors(pkgVars.validate.Struct(p))
// 	return fieldErrors
// }

// // Handler POST /my/profile
// func (p *Provider) handlePostMyProfile(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	session := getSession(ctx)

// 	reqParams := handlePostMyProfileRequestPostForm{
// 		flowID:    r.URL.Query().Get("flow"),
// 		csrfToken: r.PostFormValue("csrf_token"),
// 		Email:     r.PostFormValue("email"),
// 		Lastname:  r.PostFormValue("lastname"),
// 		Firstname: r.PostFormValue("firstname"),
// 		Nickname:  r.PostFormValue("nickname"),
// 		Birthdate: fmt.Sprintf("%s-%s-%s", r.PostFormValue("birthdate_year"), r.PostFormValue("birthdate_month"), r.PostFormValue("birthdate_day")),
// 	}
// 	validationFieldErrors := reqParams.validate()
// 	if len(validationFieldErrors) > 0 {
// 		tmplErr := pkgVars.tmpl.ExecuteTemplate(w, "my/profile/_form.html", viewParameters(session, r, map[string]any{
// 			"RegistrationFlowID":   reqParams.flowID,
// 			"CsrfToken":            reqParams.csrfToken,
// 			"Email":                reqParams.Email,
// 			"Firstname":            reqParams.Firstname,
// 			"Lastname":             reqParams.Lastname,
// 			"Nickname":             reqParams.Nickname,
// 			"Birthdate":            reqParams.Birthdate,
// 			"ValidationFieldError": validationFieldErrors,
// 		}))
// 		if tmplErr != nil {
// 			slog.ErrorContext(ctx, tmplErr.Error())
// 		}
// 		return
// 	}

// 	params := loadProfileFromSessionIfEmpty(updateProfileParams{
// 		FlowID:    reqParams.flowID,
// 		Email:     reqParams.Email,
// 		Firstname: reqParams.Firstname,
// 		Lastname:  reqParams.Lastname,
// 		Nickname:  reqParams.Nickname,
// 		Birthdate: reqParams.Birthdate,
// 	}, session)

// 	deleteAfterLoginHook(w, AFTER_LOGIN_HOOK_COOKIE_KEY_SETTINGS_PROFILE_UPDATE)

// 	// セッションが privileged_session_max_age を過ぎていた場合、ログイン画面へリダイレクト（再ログインの強制）
// 	if session.NeedLoginWhenPrivilegedAccess() {
// 		err := saveAfterLoginHook(w, afterLoginHook{
// 			Operation: AFTER_LOGIN_HOOK_OPERATION_UPDATE_PROFILE,
// 			Params:    params,
// 		}, AFTER_LOGIN_HOOK_COOKIE_KEY_SETTINGS_PROFILE_UPDATE)
// 		if err != nil {
// 			tmplErr := pkgVars.tmpl.ExecuteTemplate(w, "my/profile/_form.html", viewParameters(session, r, map[string]any{
// 				"SettingsFlowID": reqParams.flowID,
// 				"CsrfToken":      reqParams.csrfToken,
// 				"ErrorMessages":  []string{"Error"},
// 				"Email":          params.Email,
// 				"Firstname":      params.Firstname,
// 				"Lastname":       params.Lastname,
// 				"Nickname":       params.Nickname,
// 				"Birthdate":      params.Birthdate,
// 			}))
// 			if tmplErr != nil {
// 				slog.ErrorContext(ctx, tmplErr.Error())
// 			}
// 		} else {
// 			returnTo := url.QueryEscape("/my/profile")
// 			slog.InfoContext(ctx, returnTo)
// 			redirect(w, r, fmt.Sprintf("/auth/login?return_to=%s", returnTo))
// 		}
// 		return
// 	}

// 	var (
// 		kratosErr     kratos.Error
// 		errorMessages []string
// 	)
// 	// Settings Flow の送信(完了)
// 	_, err := p.d.Kratos.UpdateSettingsBrowserFlow(ctx, w, r, kratos.UpdateSettingsFlowInput{
// 		FlowID:    reqParams.flowID,
// 		CsrfToken: reqParams.csrfToken,
// 		Traits: kratos.Traits{
// 			Email:     params.Email,
// 			Firstname: params.Firstname,
// 			Lastname:  params.Lastname,
// 			Nickname:  params.Nickname,
// 			Birthdate: params.Birthdate,
// 		},
// 	})
// 	if err != nil {
// 		slog.Error(err.Error())
// 		if errors.As(err, &kratosErr) {
// 			errorMessages = kratosErr.Messages
// 		} else {
// 			errorMessages = []string{"エラーが発生しました。管理者にお問い合わせください。"}
// 		}
// 		tmplErr := pkgVars.tmpl.ExecuteTemplate(w, "my/profile/_form.html", viewParameters(session, r, map[string]any{
// 			"CsrfToken":     reqParams.csrfToken,
// 			"Email":         params.Email,
// 			"Firstname":     params.Firstname,
// 			"Lastname":      params.Lastname,
// 			"Nickname":      params.Nickname,
// 			"Birthdate":     params.Birthdate,
// 			"ErrorMessages": errorMessages,
// 		}))
// 		if tmplErr != nil {
// 			slog.ErrorContext(ctx, tmplErr.Error())
// 		}
// 		return
// 	}

// 	redirect(w, r, "/")
// 	w.WriteHeader(http.StatusOK)
// }

// type updateProfileParams struct {
// 	FlowID    string `json:"flow_id"`
// 	Email     string `json:"email"`
// 	Firstname string `json:"firstname"`
// 	Lastname  string `json:"lastname"`
// 	Nickname  string `json:"nickname"`
// 	Birthdate string `json:"birthdate"`
// }

// func loadProfileFromSessionIfEmpty(params updateProfileParams, session *kratos.Session) updateProfileParams {
// 	if session != nil {
// 		if params.Email == "" {
// 			params.Email = session.Identity.Traits.Email
// 		}
// 		if params.Firstname == "" {
// 			params.Firstname = session.Identity.Traits.Firstname
// 		}
// 		if params.Lastname == "" {
// 			params.Lastname = session.Identity.Traits.Lastname
// 		}
// 		if params.Nickname == "" {
// 			params.Nickname = session.Identity.Traits.Nickname
// 		}
// 		if params.Birthdate == "" {
// 			params.Birthdate = session.Identity.Traits.Birthdate
// 		}
// 	}
// 	return params
// }

// func (p *Provider) updateProfile(w http.ResponseWriter, r *http.Request, params updateProfileParams) error {
// 	ctx := r.Context()
// 	session := getSession(ctx)

// 	params = loadProfileFromSessionIfEmpty(updateProfileParams{
// 		Email:     params.Email,
// 		Firstname: params.Firstname,
// 		Lastname:  params.Lastname,
// 		Nickname:  params.Nickname,
// 		Birthdate: params.Birthdate,
// 	}, session)

// 	settingsFlow, err := p.d.Kratos.GetSettingsBrowserFlow(ctx, w, r, kratos.GetSettingsFlowInput{
// 		FlowID: params.FlowID,
// 	})
// 	if err != nil {
// 		slog.Error(err.Error())
// 		return err
// 	}

// 	// Settings Flow の送信(完了)
// 	_, err = p.d.Kratos.UpdateSettingsBrowserFlow(ctx, w, r, kratos.UpdateSettingsFlowInput{
// 		FlowID:    settingsFlow.FlowID,
// 		CsrfToken: settingsFlow.CsrfToken,
// 		Traits: kratos.Traits{
// 			Email:     params.Email,
// 			Firstname: params.Firstname,
// 			Lastname:  params.Lastname,
// 			Nickname:  params.Nickname,
// 			Birthdate: params.Birthdate,
// 		},
// 	})
// 	if err != nil {
// 		slog.Error(err.Error())
// 		return err
// 	}
// 	return nil
// }
