package main

import (
	"kratos_example/handler"
	"kratos_example/kratos"
	"log/slog"
	"net/http"
	"os"
)

var (
	kratosProvider  *kratos.Provider
	handlerProvider *handler.Provider
)

func init() {
	// Set up logger
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	})))

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
	var err error

	kratosProvider, err = kratos.New(
		kratos.NewInput{
			Dependencies: kratos.Dependencies{},
		},
	)
	if err != nil {
		panic(err)
	}

	handlerProvider, err = handler.New(
		handler.NewInput{
			Dependencies: handler.Dependencies{
				Kratos: kratosProvider,
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
