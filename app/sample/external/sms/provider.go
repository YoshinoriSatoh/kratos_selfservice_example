package sms

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

type Provider struct {
	profile string
	region  string
	client  *sns.Client
}

type Option func(*Provider)

func New(region string, options ...Option) (*Provider, error) {
	p := &Provider{
		region: region,
	}

	for _, option := range options {
		option(p)
	}

	var (
		cfg aws.Config
		err error
	)
	if p.profile == "" {
		cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithRegion(p.region))
	} else {
		cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithRegion(p.region), config.WithSharedConfigProfile(p.profile))
	}
	if err != nil {
		slog.Error("sms New() error", "err", err)
	}
	p.client = sns.NewFromConfig(cfg)

	return p, nil
}

func WithProfile(profile string) Option {
	return func(p *Provider) {
		p.profile = profile
	}
}

func (p *Provider) Send(ctx context.Context, message string) {
	_, err := p.client.Publish(ctx, &sns.PublishInput{
		// TopicArn: aws.String(p.topicArn),
		PhoneNumber: aws.String("+8109020776263"),
		Message:     aws.String(message),
	})
	if err != nil {
		slog.ErrorContext(ctx, "sms Send() error", "err", err)
	}
}
