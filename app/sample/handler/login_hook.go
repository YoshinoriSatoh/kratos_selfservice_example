package handler

// type afterLoginHook struct {
// 	Operation afterLoginHookOperation `json:"operation"`
// 	Params    interface{}             `json:"params"`
// }

// type afterLoginHookOperation string

// const (
// 	AFTER_LOGIN_HOOK_OPERATION_UPDATE_PROFILE = "update_profile"
// )

// type afterLoginHookCookieKey string

// const (
// 	AFTER_LOGIN_HOOK_COOKIE_KEY_SETTINGS_PROFILE_UPDATE = "after_login_hook_settings_profile_update"
// )

// func saveAfterLoginHook(w http.ResponseWriter, loginHook afterLoginHook, cookieKey afterLoginHookCookieKey) error {
// 	cookieString, err := json.Marshal(loginHook)
// 	if err != nil {
// 		slog.Error(err.Error())
// 		return err
// 	}
// 	base64CookieString := base64.URLEncoding.EncodeToString(cookieString)
// 	http.SetCookie(w, &http.Cookie{
// 		Name:     string(cookieKey),
// 		Value:    base64CookieString,
// 		MaxAge:   3600,
// 		Path:     pkgVars.cookieParams.Path,
// 		Domain:   pkgVars.cookieParams.Domain,
// 		Secure:   pkgVars.cookieParams.Secure,
// 		HttpOnly: true,
// 	})
// 	return nil
// }

// func existsAfterLoginHook(r *http.Request, cookieKey afterLoginHookCookieKey) bool {
// 	_, err := r.Cookie(string(cookieKey))
// 	if err != nil {
// 		// Cookieがない場合にエラーとはしない
// 		slog.Info(err.Error())
// 		return false
// 	} else {
// 		return true
// 	}
// }

// func loadAfterLoginHook(r *http.Request, cookieKey afterLoginHookCookieKey) (afterLoginHook, error) {
// 	cookieString, err := r.Cookie(string(cookieKey))
// 	if err != nil {
// 		// Cookieがない場合にエラーとはしない
// 		slog.Info(err.Error())
// 		return afterLoginHook{}, nil
// 	}
// 	cookieBytes, err := base64.URLEncoding.DecodeString(cookieString.Value)
// 	if err != nil {
// 		slog.Error(err.Error())
// 		return afterLoginHook{}, err
// 	}

// 	var hook afterLoginHook
// 	err = json.Unmarshal(cookieBytes, &hook)
// 	if err != nil {
// 		slog.Error(err.Error())
// 		return afterLoginHook{}, err
// 	}

// 	return hook, nil
// }

// func deleteAfterLoginHook(w http.ResponseWriter, cookieKey afterLoginHookCookieKey) {
// 	http.SetCookie(w, &http.Cookie{
// 		Name:     string(cookieKey),
// 		Value:    "",
// 		MaxAge:   -1,
// 		Path:     pkgVars.cookieParams.Path,
// 		Domain:   pkgVars.cookieParams.Domain,
// 		Secure:   pkgVars.cookieParams.Secure,
// 		HttpOnly: true,
// 	})
// }
