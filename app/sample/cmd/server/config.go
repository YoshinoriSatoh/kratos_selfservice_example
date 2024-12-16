package main

import (
	"fmt"
	"log"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

var config Config

type Config struct {
	Local  Local
	Sms    Sms
	Kratos Kratos
}

type Local struct {
	AwsProfile string `required:"false" split_words:"true"`
}

type Sms struct {
	AwsRegion string `required:"false" split_words:"true"`
}

type Kratos struct {
	SettingsRequiredAal string `required:"false" split_words:"true"`
	SessionRequiredAal  string `required:"false" split_words:"true"`
}

func LoadConfig() error {
	var err error

	// .envファイルがある場合(=ローカル環境)はロード
	// ECS環境はタスクの実行環境に環境変数が設定されている
	err = godotenv.Load()
	if err == nil {
		log.Println("Loading .env file")
	}

	err = envconfig.Process("local", &config.Local)
	fmt.Printf("local config: %v\n", config.Local)
	if err != nil {
		return err
	}

	err = envconfig.Process("sms", &config.Sms)
	fmt.Printf("sms config: %v\n", config.Sms)
	if err != nil {
		return err
	}

	err = envconfig.Process("kratos", &config.Kratos)
	fmt.Printf("kratos config: %v\n", config.Kratos)
	if err != nil {
		return err
	}

	return nil
}
