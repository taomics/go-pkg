package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/taomics/go-pkg/oidc"
)

type contextKey string

const (
	keyEmail contextKey = "email"
)

const (
	lenBearer        = 7   // len("bearer ")
	minAuthHeaderLen = 500 // the length of my auth token sample is 960. this value is not logical.
)

// Email extracts the authenticated user's email address from the context.
// It returns an error if the email is not present or is empty.
func Email(ctx context.Context) (string, error) {
	v := ctx.Value(keyEmail)

	s, ok := v.(string)
	if !ok || s == "" {
		return "", errors.New("no email")
	}

	return s, nil
}

// SetEmail stores the authenticated user's email address in the context
// and returns the updated context.
func SetEmail(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, keyEmail, email)
}

// SetValidAudience registers a global callback function to validate token audiences.
// This is highly recommended to prevent token reuse across different applications.
func SetValidAudience(f func(audiences []string) bool) {
	oidc.SetValidAudience(f)
}

type option struct {
	azureADB2CTenant string
}

// Option defines a functional option for configuring the Authenticate function.
type Option = func(*option)

// WithAzureADB2CTenant returns an Option that configures the Azure AD B2C tenant name.
// This is required when validating tokens issued by Azure AD B2C.
func WithAzureADB2CTenant(tenant string) Option {
	return func(o *option) {
		o.azureADB2CTenant = tenant
	}
}

// Authenticate validates the provided Authorization header (which must start with "Bearer " or "bearer "),
// parses and verifies the OIDC token, extracts the user's email address, and stores it in the returned context.
//
// It automatically detects the token issuer (Google, Apple, or Azure AD B2C) and fetches
// the corresponding provider metadata and JWK set to verify the token signature.
func Authenticate(ctx context.Context, authHeader string, opts ...Option) (context.Context, error) {
	if authHeader == "" {
		return nil, errors.New("authorization header is empty")
	}

	var opt option
	for _, f := range opts {
		f(&opt)
	}

	token, err := extractBearerToken(authHeader)
	if err != nil {
		return nil, err
	}

	var parseOpts []oidc.ParseOption

	if opt.azureADB2CTenant != "" {
		parseOpts = append(parseOpts, oidc.WithAzureADB2CTenant(opt.azureADB2CTenant))
	}

	t, err := oidc.Parse(ctx, []byte(token), parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("token parse error: %w", err)
	}

	email, err := oidc.Email(t)
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
