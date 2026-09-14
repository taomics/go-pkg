package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"slices"
	"sync"
	"time"

	"github.com/jwx-go/jwkfetch/v4"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

const (
	expirationMargin     = 60 * time.Second
	registrationTimeout  = 5 * time.Second
	metadataFetchTimeout = 5 * time.Second
	maxMetadataSize      = 1024 * 1024 // 1MB
)

var (
	// DefaultHTTPClient is the HTTP client used for fetching provider metadata and JWKS.
	// If customizing, configure it before any calls to Parse or JWKSet.
	DefaultHTTPClient = &http.Client{} //nolint:exhaustruct,exhaustruct_v5

	getJWKCache = sync.OnceValues(func() (*jwkfetch.Cache, error) {
		return jwkfetch.NewCache(
			context.Background(),
			httprc.NewClient(),
			jwkfetch.WithHTTPClient(DefaultHTTPClient),
		)
	})
	cacheProviderMeta = make(map[string]*ProviderMetadata)
	validAudience     func(audiences []string) bool
	muxAud            sync.RWMutex
	muxPM             sync.RWMutex
)

// SetValidAudience sets the function used to validate audiences.
func SetValidAudience(f func(audiences []string) bool) {
	muxAud.Lock()
	validAudience = f
	muxAud.Unlock()
}

func validateAudience(audiences []string, aud string) error {
	muxAud.RLock()

	f := validAudience

	muxAud.RUnlock()

	if aud == "" && f == nil {
		slog.Warn("strongly recommend checking the Audience using SetValidAudience or WithAudience option")
		return nil
	}

	if aud != "" {
		if !containsAudience(audiences, aud) {
			return fmt.Errorf("invalid audience (option): want=%s, got=%q", aud, audiences)
		}

		return nil
	}

	if !f(audiences) {
		return fmt.Errorf("invalid audience (func): got=%q", audiences)
	}

	return nil
}

func containsAudience(list []string, aud string) bool {
	return slices.Contains(list, aud)
}

type parseOption struct {
	aud              string
	adb2cTenant      string
	configurationURI string
}

// ParseOption represents an option for parsing an OIDC token.
type ParseOption func(*parseOption)

// WithAudience returns a ParseOption that configures an expected audience.
func WithAudience(aud string) ParseOption {
	return func(o *parseOption) {
		o.aud = aud
	}
}

// WithAzureADB2CTenant returns a ParseOption that configures the expected Azure AD B2C tenant.
func WithAzureADB2CTenant(tenant string) ParseOption {
	return func(o *parseOption) {
		o.adb2cTenant = tenant
	}
}

// WithConfigurationURI returns a ParseOption that overrides the OpenID configuration URI.
func WithConfigurationURI(uri string) ParseOption {
	return func(o *parseOption) {
		o.configurationURI = uri
	}
}

// Parse parses and validates an OIDC ID token, returning the parsed jwt.Token.
//
// It automatically detects the token's issuer (supporting Google, Apple, and Azure AD B2C),
// fetches the respective OpenID provider metadata and JWK set (JWKS) using an internal cache,
// and cryptographically verifies the token signature.
//
// In addition to cryptographic signature validation, it performs custom checks including:
//   - Verifying the Audience claim (customizable via WithAudience or SetValidAudience).
//   - Verifying that the token's Expiration is valid, incorporating a 60-second margin.
//
// To configure custom behaviors, you can pass ParseOptions such as:
//   - WithAudience(aud): Limits valid audience to a specific string.
//   - WithAzureADB2CTenant(tenant): Sets the expected tenant name for Azure AD B2C issuer validation.
//   - WithConfigurationURI(uri): Overrides the default OpenID discovery endpoint.
//
//nolint:cyclop,funlen,ireturn
func Parse(ctx context.Context, token []byte, opts ...ParseOption) (jwt.Token, error) {
	var opt parseOption

	for _, f := range opts {
		f(&opt)
	}

	t, err := jwt.ParseInsecure(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	aud, _ := t.Audience()
	if err := validateAudience(aud, opt.aud); err != nil {
		return nil, err
	}

	var cfguri string

	iss, ok := t.Issuer()
	if !ok {
		return nil, errors.New("issuer not found in token")
	}

	switch {
	case iss == appleIssuer:
		cfguri = appleConfigurationURI
	case iss == googleIssuer:
		cfguri = googleConfigurationURI
	case adb2cIssuerRegex.MatchString(iss):
		var err error

		cfguri, err = makeADB2CConfigurationURI(opt.adb2cTenant, t)
		if err != nil {
			return nil, fmt.Errorf("make adb2c configuration uri: %w", err)
		}

	default:
		if opt.configurationURI != "" {
			cfguri = opt.configurationURI
		} else {
			return nil, fmt.Errorf("not supported issuer: %s", iss)
		}
	}

	exp, ok := t.Expiration()
	if !ok {
		return nil, errors.New("expiration not found in token")
	}

	if time.Until(exp) < expirationMargin {
		return nil, fmt.Errorf("token is too old: %s", exp)
	}

	if nbf, ok := t.NotBefore(); ok {
		if time.Now().Add(expirationMargin).Before(nbf) {
			return nil, fmt.Errorf("token is not active yet: %s", nbf)
		}
	}

	cfg, err := fetchProviderMetadata(ctx, cfguri)
	if err != nil {
		return nil, err
	}

	if cfg.Issuer != iss {
		return nil, fmt.Errorf("issuer mismatch: token=%s, metadata=%s", iss, cfg.Issuer)
	}

	jwks, err := JWKSet(ctx, cfguri)
	if err != nil {
		return nil, err
	}

	if jwks.Len() == 0 {
		return nil, errors.New("there is no key in JWKS")
	}

	parsedToken, err := jwt.Parse(token, jwt.WithKeySet(jwks, jws.WithInferAlgorithmFromKey(true)), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("verify error: %w", err)
	}

	return parsedToken, nil
}

// JWKSet fetches and returns the JSON Web Key (JWK) set from the given OIDC configuration URI.
//
// It first retrieves the provider metadata to discover the `jwks_uri`. Then, it registers
// the discovered URI to an internal, thread-safe, auto-refreshing jwkfetch.Cache.
//
// To prevent network downtime from blocking the application indefinitely, registration
// is protected by a 5-second timeout context (or the provided context's timeout).
// Subsequent lookups read from the local cache.
//
//nolint:ireturn
func JWKSet(ctx context.Context, cfguri string) (jwk.Set, error) {
	cfg, err := fetchProviderMetadata(ctx, cfguri)
	if err != nil {
		return nil, fmt.Errorf("fetch provider metadata: %w", err)
	}

	cache, err := getJWKCache()
	if err != nil {
		return nil, fmt.Errorf("initialize jwk cache: %w", err)
	}

	if !cache.IsRegistered(ctx, cfg.JWKSURI) {
		// Use a timeout context for registration to avoid infinite blocking when the JWKS endpoint is down.
		regCtx, regCancel := context.WithTimeout(ctx, registrationTimeout)
		defer regCancel()

		// jwkfetch.Cache is thread-safe.
		if err := cache.Register(regCtx, cfg.JWKSURI); err != nil {
			return nil, fmt.Errorf("register jwks_uri: %w", err)
		}
	}

	set, err := cache.Lookup(ctx, cfg.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("get jwk set: %w", err)
	}

	return set, nil
}

// Email extracts, normalizes, and validates the email address claim from the given OIDC token.
//
// It supports extracting email addresses from various provider-specific claims:
//   - Standard "email" claim (Google, Apple).
//   - "preferred_username" or the "emails" string array (Azure AD B2C).
//
// Extracted emails are parsed and validated to ensure they conform to a correct email format.
func Email(t jwt.Token) (string, error) {
	iss, ok := t.Issuer()
	if !ok {
		return "", errors.New("issuer not found in token")
	}

	switch {
	case iss == appleIssuer:
		return email(t, appleEmailKey)
	case iss == googleIssuer:
		return email(t, googleEmailKey)
	case adb2cIssuerRegex.MatchString(iss):
		return adb2cEmail(t)
	default:
		return "", fmt.Errorf("email not supported for %s", iss)
	}
}

func email(t jwt.Token, key string) (string, error) {
	v, err := jwt.Get[string](t, key)
	if err != nil {
		return "", fmt.Errorf("there is no email in token: %w", err)
	}

	if err := validateEmailValue(v); err != nil {
		return "", err
	}

	return v, nil
}

func validateEmailValue(v any) error {
	s, ok := v.(string)
	if !ok || s == "" {
		return fmt.Errorf("unexpected email value: %v", v)
	}

	if _, err := mail.ParseAddress(s); err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	return nil
}

func fetchProviderMetadata(ctx context.Context, cfguri string) (*ProviderMetadata, error) {
	muxPM.RLock()

	cache, ok := cacheProviderMeta[cfguri]

	muxPM.RUnlock()

	if ok {
		return cache, nil
	}

	fetchCtx, cancel := context.WithTimeout(ctx, metadataFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, cfguri, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid uri (%s): %w", cfguri, err)
	}

	res, err := DefaultHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", cfguri, err)
	}

	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http get %s: status=%d", cfguri, res.StatusCode)
	}

	var cfg ProviderMetadata
	if err := json.NewDecoder(io.LimitReader(res.Body, maxMetadataSize)).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse provider metadata: %w", err)
	}

	if err := cfg.Valid(); err != nil {
		return nil, fmt.Errorf("invalid metadata: %w", err)
	}

	muxPM.Lock()
	cacheProviderMeta[cfguri] = &cfg
	muxPM.Unlock()

	return &cfg, nil
}
