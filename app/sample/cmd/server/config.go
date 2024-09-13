package main

import (
	"fmt"
	"log"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

var config Config

type Config struct {
	AwsProfile string `required:"false" split_words:"true"`
	Sms        Sms
}

type Sms struct {
	AwsRegion string `required:"false" split_words:"true"`
}

func LoadConfig() error {
	var err error

	// .envファイルがある場合(=ローカル環境)はロード
	// ECS環境はタスクの実行環境に環境変数が設定されている
	err = godotenv.Load()
	if err == nil {
		log.Println("Loading .env file")
	}

	err = envconfig.Process("", &config)
	fmt.Printf("root config: %v\n", config)
	if err != nil {
		return err
	}

	err = envconfig.Process("sms", &config.Sms)
	fmt.Printf("sms config: %v\n", config.Sms)
	if err != nil {
		return err
	}

	return nil
}
