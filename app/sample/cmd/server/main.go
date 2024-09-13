package main

import (
	"kratos_example/externals/sms"
	"kratos_example/handler"
	"kratos_example/kratos"
	"log/slog"
	"net/http"
	"os"
)

var (
	kratosProvider  *kratos.Provider
	handlerProvider *handler.Provider
	smsProvider     *sms.Provider
)

func init() {
	// Set up logger
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	})))

	err := LoadConfig()
	if err != nil {
		panic(err)
	}

	// Init packages
	kratos.Init(kratos.InitInput{
		PrivilegedAccessLimitMinutes: 10,
		KratosPublicEndpoint:         "http://kratos:4433",
		KratosAdminEndpoint:          "http://kratos:4434",
	})

	handler.Init(handler.InitInput{
		CookieParams: handler.CookieParams{
			SessionCookieName: "kratos_session",
			Path:              "/",
			Domain:            "localhost",
			Secure:            false,
		},
	})

	// Create package providers with dependencies
	kratosProvider, err = kratos.New(
		kratos.NewInput{
			Dependencies: kratos.Dependencies{},
		},
	)
	if err != nil {
		panic(err)
	}

	if config.AwsProfile == "" {
		smsProvider, err = sms.New(config.Sms.AwsRegion)
	} else {
		smsProvider, err = sms.New(config.Sms.AwsRegion, sms.WithProfile(config.AwsProfile))
	}
	if err != nil {
		panic(err)
	}

	handlerProvider, err = handler.New(
		handler.NewInput{
			Dependencies: handler.Dependencies{
				Kratos: kratosProvider,
				Sms:    smsProvider,
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
