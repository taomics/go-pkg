// Package oidc implements OpenID Connect token parsing and validation.
package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwt"
)

const (
	adb2cDefaultAuthorityDomain = "login.microsoftonline.com"
	adb2cAuthorityDomainSuffix  = ".b2clogin.com"
	adb2cTenantSuffix           = ".onmicrosoft.com"
	adb2cConfigurationURISuffix = "/v2.0/.well-known/openid-configuration"
	adb2cEmailKey               = "preferred_username"
	adb2cEmailsKey              = "emails"
)

var adb2cIssuerRegex = regexp.MustCompile(`^https://(login.microsoftonline.com|[a-zA-Z0-9-]+\.b2clogin\.com)/`)

func adb2cEmail(t jwt.Token) (string, error) {
	if v, err := jwt.Get[string](t, adb2cEmailKey); err == nil {
		if err := validateEmailValue(v); err == nil {
			return v, nil
		}
	}

	raw, err := jwt.Get[any](t, adb2cEmailsKey)
	if err != nil {
		return "", fmt.Errorf("there is no email in token: %w", err)
	}

	var emails []string

	switch val := raw.(type) {
	case []string:
		emails = val
	case []any:
		for _, item := range val {
			if s, ok := item.(string); ok {
				emails = append(emails, s)
			}
		}
	}

	for _, email := range emails {
		if err := validateEmailValue(email); err == nil {
			return email, nil
		}
	}

	return "", errors.New("there is no valid email in token")
}

// makeADB2CConfigurationURI builds the URI for the OpenID Configuration document.
//
// Reference: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc#find-your-apps-openid-configuration-document-uri
//
// Why doesn't it use the `iss` field from the OpenID Connect ID Token?
//
// The ID Token in Azure AD B2C includes an `iss` field formatted like below:
//
//	https://{tenant}.b2clogin.com/{tenant_uuid}/v2.0
//
// According to OpenID Connect Discovery 1.0, the OpenID Configuration URI should be:
//
//	https://{tenant}.b2clogin.com/{tenant_uuid}/v2.0/.well-known/openid-configuration
//
// Unfortunately, this URI returns a 404 error when a User-flow/Custom-policy is configured.
// As a workaround, the following URI format is effective:
//
//	https://{tenant}.b2clogin.com/{tenant_uuid}/v2.0/.well-known/openid-configuration?p={policy}
//
// However, this format is not documented in the official Azure documentation.
// The official documentation suggests using:
//
//	https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policy}/v2.0/.well-known/openid-configuration
//
// Therefore, this function needs to manually set the tenant and policy values.
func makeADB2CConfigurationURI(tenant string, token jwt.Token) (string, error) {
	policy, err := extractADB2CPolicy(token)
	if err != nil {
		return "", err
	}

	if tenant == "" && policy != "" {
		return "", errors.New("not support specifying only policy")
	}

	if tenant == "" {
		tenant = "common"
	}

	u := new(url.URL)
	u.Scheme = "https"

	switch tenant {
	case "common", "organizations", "consumers":
		if policy != "" {
			return "", fmt.Errorf("not support specifying policy for %q", tenant)
		}

		u.Host = adb2cDefaultAuthorityDomain
		u.Path = "/" + tenant

	default:
		u.Host = tenant + adb2cAuthorityDomainSuffix
		u.Path = "/" + tenant + adb2cTenantSuffix

		if policy != "" {
			u.Path += "/" + policy
		}
	}

	u.Path += adb2cConfigurationURISuffix
	cfguri := u.String()

	if _, err := url.Parse(cfguri); err != nil {
		return "", fmt.Errorf("invalid url: %s", cfguri)
	}

	return cfguri, nil
}

func isSafePolicyName(s string) bool {
	if s == "" {
		return false
	}

	return strings.IndexFunc(s, func(r rune) bool {
		return !isSafePolicyRune(r)
	}) == -1
}

func isSafePolicyRune(r rune) bool {
	if r >= 'a' && r <= 'z' {
		return true
	}

	if r >= 'A' && r <= 'Z' {
		return true
	}

	if r >= '0' && r <= '9' {
		return true
	}

	return r == '_' || r == '-'
}

func extractADB2CPolicy(token jwt.Token) (string, error) {
	if v, err := jwt.Get[any](token, "tfp"); err == nil {
		s, ok := v.(string)
		if !ok {
			return "", errors.New("invalid tfp type")
		}

		if !isSafePolicyName(s) {
			return "", errors.New("invalid tfp format")
		}

		return s, nil
	}

	if v, err := jwt.Get[any](token, "acr"); err == nil {
		s, ok := v.(string)
		if !ok {
			return "", errors.New("invalid acr type")
		}

		if !isSafePolicyName(s) {
			return "", errors.New("invalid acr format")
		}

		return s, nil
	}

	return "", nil
}
