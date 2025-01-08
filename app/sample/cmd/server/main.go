package main

import (
	"log/slog"
	"net/http"

	"github.com/m-mizutani/clog"

	"github.com/YoshinoriSatoh/kratos_example/handler"
	"github.com/YoshinoriSatoh/kratos_example/kratos"
	"github.com/YoshinoriSatoh/kratos_example/sms"
)

var (
	handlerProvider *handler.Provider
	smsProvider     *sms.Provider
)

func init() {
	// Set up logger
	slog.SetDefault(slog.New(clog.New(
		clog.WithColor(true),
		clog.WithSource(true),
		clog.WithLevel(slog.LevelDebug),
		clog.WithPrinter(clog.PrettyPrinter),
	)))

	err := LoadConfig()
	if err != nil {
		panic(err)
	}

	// Init packages
	kratos.Init(kratos.InitInput{
		PrivilegedAccessLimitMinutes: 10,
		KratosPublicEndpoint:         "http://kratos:4433",
		KratosAdminEndpoint:          "http://kratos:4434",
		SettingsRequiredAal:          kratos.Aal(config.Kratos.SettingsRequiredAal),
		SessionRequiredAal:           kratos.Aal(config.Kratos.SessionRequiredAal),
	})

	handler.Init(handler.InitInput{
		CookieParams: handler.CookieParams{
			SessionCookieName: "kratos_session",
			Path:              "/",
			Domain:            "localhost",
			Secure:            false,
		},
	})

	if config.Local.AwsProfile == "" {
		smsProvider, err = sms.New(config.Sms.AwsRegion)
	} else {
		smsProvider, err = sms.New(config.Sms.AwsRegion, sms.WithProfile(config.Local.AwsProfile))
	}
	if err != nil {
		panic(err)
	}

	handlerProvider, err = handler.New(
		handler.NewInput{
			Dependencies: handler.Dependencies{
				Sms: smsProvider,
			},
		},
	)
	if err != nil {
		panic(err)
	}
}

func main() {
	mux := http.NewServeMux()
	mux = handlerProvider.RegisterHandles(mux)

	if err := http.ListenAndServe(":3000", mux); err != nil {
		panic(err)
	}
}
