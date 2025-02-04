package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"regexp"

	"github.com/YoshinoriSatoh/kratos_example/kratos"
)

func parseDate(date string) (string, string, string) {
	var (
		year  string
		month string
		day   string
	)
	r := regexp.MustCompile(`(?P<Year>\d{4})-(?P<Month>\d{2})-(?P<Day>\d{2})`)
	if r.Match([]byte(date)) {
		caps := r.FindStringSubmatch(date)
		year = caps[1]
		month = caps[2]
		day = caps[3]
	}

	return year, month, day
}

func makeDefaultKratosRequestHeader(r *http.Request) kratos.KratosRequestHeader {
	var cookies []string
	for _, v := range r.Cookies() {
		cookies = append(cookies, v.String())
	}
	return kratos.KratosRequestHeader{
		Cookie:   cookies,
		ClientIP: r.RemoteAddr,
	}
}

func bindAndValidateRequest(r *http.Request, dest interface{}) error {
	// クエリパラメータを構造体にコピー
	query := r.URL.Query()
	if v, ok := dest.(interface{ SetQuery(url.Values) }); ok {
		v.SetQuery(query)
	}

	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	// JSONボディをデコード
	if err := decoder.Decode(dest); err != nil {
		slog.Error("bindRequest error", "err", err)
		return err
	}

	// validate request parameters
	if err := pkgVars.validate.Struct(dest); err != nil {
		slog.Info("handlePostAuthLogin validation error", "err", err)
		return err
	}

	return nil
}

// toMap converts any struct to map[string]any using reflection
func requestParamsToMap(in interface{}) map[string]any {
	out := make(map[string]any)
	v := reflect.ValueOf(in)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return out
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		name := t.Field(i).Name

		// 値の型に応じた処理
		switch field.Kind() {
		case reflect.Struct:
			// ネストされた構造体を再帰的に処理
			out[name] = requestParamsToMap(field.Interface())
		case reflect.Ptr:
			// ポインタの場合
			if !field.IsNil() {
				if field.Elem().Kind() == reflect.Struct {
					// ポインタが指す先が構造体の場合は再帰的に処理
					out[name] = requestParamsToMap(field.Interface())
				} else {
					// それ以外の場合は値をそのまま格納
					out[name] = field.Elem().Interface()
				}
			} else {
				out[name] = nil
			}
		default:
			// その他の型は単純に値を格納
			out[name] = field.Interface()
		}
	}
	return out
}
