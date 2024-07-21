package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/dictav/go-oidc/adb2c"
)

type contextKey string

const (
	keyEmail contextKey = "email"
)

const (
	lenBearer        = 7   // len("bearer ")
	minAuthHeaderLen = 500 // the length of my auth token sample is 960. this value is not logical.
)

func Email(ctx context.Context) (string, error) {
	v := ctx.Value(keyEmail)

	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("no email") //nolint:perfsprint
	}

	return s, nil
}

func SetEmail(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, keyEmail, email)
}

type option struct {
	allowNoAuth      bool
	azureADB2CTenant string
}

type Option = func(*option)

func WithAllowNoAuth() Option {
	return func(o *option) {
		o.allowNoAuth = true
	}
}

func WithAzureADB2CTenant(tenant string) Option {
	return func(o *option) {
		o.azureADB2CTenant = tenant
	}
}

func Authenticate(ctx context.Context, authHeader string, opts ...Option) (context.Context, error) {
	var opt option
	for _, f := range opts {
		f(&opt)
	}

	if opt.allowNoAuth && authHeader == "" {
		return ctx, nil
	}

	token, err := extractBearerToken(authHeader)
	if err != nil {
		return nil, err
	}

	t, err := adb2c.Parse(ctx, opt.azureADB2CTenant, []byte(token))
	if err != nil {
		return nil, fmt.Errorf("token parse error: %w", err)
	}

	email, err := adb2c.Email(t)
	if err != nil {
		return nil, fmt.Errorf("failed to get email: %w", err)
	}

	return SetEmail(ctx, email), nil
}

func extractBearerToken(ah string) (string, error) {
	n := len(ah)
	if n < minAuthHeaderLen {
		return "", fmt.Errorf("authorization header too short: len=%d", n)
	}

	// use TrimPrefix instead of HasPrefix because TrimPrefix is faster.
	if len(strings.TrimPrefix(ah, "Bearer ")) == n && len(strings.TrimPrefix(ah, "bearer ")) == n {
		return "", fmt.Errorf("authorization header should start with bearer: %s*", ah[:15])
	}

	return ah[lenBearer:], nil
}
