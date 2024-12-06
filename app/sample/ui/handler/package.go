package handler

import (
	"html/template"
	"reflect"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/sprig/v3"
	"github.com/go-playground/locales/ja"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	ja_translations "github.com/go-playground/validator/v10/translations/ja"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var pkgVars packageVariables

type packageVariables struct {
	tmpl         *template.Template
	validate     *validator.Validate
	trans        ut.Translator
	cookieParams CookieParams
	printer      *message.Printer
	loc          *i18n.Localizer
}

type CookieParams struct {
	SessionCookieName string
	Path              string
	Domain            string
	Secure            bool
}

type InitInput struct {
	CookieParams CookieParams
}

func Init(i InitInput) {
	loadTemplate()
	initValidator()
	pkgVars.cookieParams = i.CookieParams
	pkgVars.printer = message.NewPrinter(language.Japanese)

	// i18n
	bundle := i18n.NewBundle(language.Japanese)
	bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	bundle.LoadMessageFile("ui/active.ja.toml")

	pkgVars.loc = i18n.NewLocalizer(bundle, language.Japanese.String())
}

func loadTemplate() {
	funcMap := template.FuncMap{
		"safehtml": func(text string) template.HTML {
			return template.HTML(text)
		},
		"safeattr": func(text string) template.HTMLAttr {
			return template.HTMLAttr(text)
		},
	}
	pkgVars.tmpl = template.Must(template.New("").Funcs(sprig.FuncMap()).Funcs(funcMap).ParseGlob("ui/templates/**/*.html"))
	pkgVars.tmpl = template.Must(pkgVars.tmpl.ParseGlob("ui/templates/**/**/*.html"))
}

func initValidator() {
	ja := ja.New()
	uni := ut.New(ja)
	pkgVars.trans, _ = uni.GetTranslator("ja")

	pkgVars.validate = validator.New(validator.WithRequiredStructEnabled())
	pkgVars.validate.RegisterValidation("date", validateDate)
	pkgVars.validate.RegisterTagNameFunc(func(field reflect.StructField) string {
		fieldName := field.Tag.Get("ja")
		if fieldName == "-" {
			return ""
		}
		return fieldName
	})
	err := ja_translations.RegisterDefaultTranslations(pkgVars.validate, pkgVars.trans)
	if err != nil {
		panic(err)
	}
}

func validateDate(fl validator.FieldLevel) bool {
	_, err := time.Parse("2006-01-02", fl.Field().String())
	return err == nil
}
