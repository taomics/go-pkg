package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/taomics/go-pkg/auth"
	"github.com/taomics/go-pkg/oidc"
)

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

var testKey jwk.Key

//nolint:cyclop
func TestMain(m *testing.M) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate private key: %v", err))
	}

	jwkKey, err := jwk.Import[jwk.Key](privateKey)
	if err != nil {
		panic(fmt.Sprintf("failed to create JWK: %v", err))
	}

	if err := jwkKey.Set(jwk.KeyIDKey, "test-kid"); err != nil {
		panic(fmt.Sprintf("failed to set KeyIDKey: %v", err))
	}

	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		panic(fmt.Sprintf("failed to set AlgorithmKey: %v", err))
	}

	testKey = jwkKey

	pubKey, err := testKey.PublicKey()
	if err != nil {
		panic(fmt.Sprintf("failed to create public JWK: %v", err))
	}

	jwks := jwk.NewSet()

	if err := jwks.AddKey(pubKey); err != nil {
		panic(fmt.Sprintf("failed to add public key to JWKS: %v", err))
	}

	jwksJSON, err := json.Marshal(jwks)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal JWKS: %v", err))
	}

	mock := &mockTransport{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			urlStr := req.URL.String()

			var body string

			status := http.StatusOK

			switch urlStr {
			case "https://accounts.google.com/.well-known/openid-configuration":
				body = `{
					"issuer": "https://accounts.google.com",
					"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
					"token_endpoint": "https://oauth2.googleapis.com/token",
					"jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
					"response_types_supported": ["code", "token", "id_token"],
					"subject_types_supported": ["public"],
					"id_token_signing_alg_values_supported": ["RS256"]
				}`
			case "https://www.googleapis.com/oauth2/v3/certs":
				body = string(jwksJSON)
			case "https://appleid.apple.com/.well-known/openid-configuration":
				body = `{
					"issuer": "https://appleid.apple.com",
					"authorization_endpoint": "https://appleid.apple.com/auth/authorize",
					"token_endpoint": "https://appleid.apple.com/auth/token",
					"jwks_uri": "https://appleid.apple.com/auth/keys",
					"response_types_supported": ["code", "token", "id_token"],
					"subject_types_supported": ["public"],
					"id_token_signing_alg_values_supported": ["RS256"]
				}`
			case "https://appleid.apple.com/auth/keys":
				body = string(jwksJSON)
			case "https://mytenant.b2clogin.com/mytenant.onmicrosoft.com/mypolicy/v2.0/.well-known/openid-configuration":
				body = `{
					"issuer": "https://mytenant.b2clogin.com/mytenant-uuid/v2.0",
					"authorization_endpoint": "https://mytenant.b2clogin.com/mytenant.onmicrosoft.com/oauth2/v2.0/authorize",
					"token_endpoint": "https://mytenant.b2clogin.com/mytenant.onmicrosoft.com/oauth2/v2.0/token",
					"jwks_uri": "https://mytenant.b2clogin.com/mytenant.onmicrosoft.com/mypolicy/discovery/v2.0/keys",
					"response_types_supported": ["code", "token", "id_token"],
					"subject_types_supported": ["public"],
					"id_token_signing_alg_values_supported": ["RS256"]
				}`
			case "https://mytenant.b2clogin.com/mytenant.onmicrosoft.com/mypolicy/discovery/v2.0/keys":
				body = string(jwksJSON)
			default:
				status = http.StatusNotFound
				body = "not found"
			}

			hdr := make(http.Header)
			hdr.Set("Content-Type", "application/json")

			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     hdr,
				Request:    req,
			}, nil
		},
	}

	oidc.DefaultHTTPClient = &http.Client{
		Transport: mock,
	}

	os.Exit(m.Run())
}

func createToken(t *testing.T, key jwk.Key, issuer, email string, extraClaims map[string]any) string {
	t.Helper()

	token := jwt.New()

	_ = token.Set(jwt.IssuerKey, issuer)
	_ = token.Set(jwt.AudienceKey, "test-aud")
	_ = token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))

	if email != "" {
		if issuer == "https://appleid.apple.com" || issuer == "https://accounts.google.com" {
			_ = token.Set("email", email)
		} else {
			_ = token.Set("preferred_username", email)
		}
	}

	for k, v := range extraClaims {
		_ = token.Set(k, v)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return string(signed)
}

func TestEmailAndSetEmail(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Test Email with no email in context
	_, err := auth.Email(ctx)
	if err == nil {
		t.Error("expected error when no email in context, got nil")
	}

	// Test SetEmail and Email
	testEmail := "test@example.com"
	ctx = auth.SetEmail(ctx, testEmail)

	email, err := auth.Email(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if email != testEmail {
		t.Errorf("expected email %q, got %q", testEmail, email)
	}
}

//nolint:paralleltest
func TestAuthenticate_Google(t *testing.T) {
	longClaim := map[string]any{"dummy": strings.Repeat("a", 500)}
	token := createToken(t, testKey, "https://accounts.google.com", "google@example.com", longClaim)
	authHeader := "Bearer " + token

	ctx, err := auth.Authenticate(t.Context(), authHeader)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	email, err := auth.Email(ctx)
	if err != nil {
		t.Fatalf("failed to get email from context: %v", err)
	}

	if email != "google@example.com" {
		t.Errorf("expected email google@example.com, got %q", email)
	}
}

//nolint:paralleltest
func TestAuthenticate_Apple(t *testing.T) {
	longClaim := map[string]any{"dummy": strings.Repeat("a", 500)}
	token := createToken(t, testKey, "https://appleid.apple.com", "apple@example.com", longClaim)
	authHeader := "Bearer " + token

	ctx, err := auth.Authenticate(t.Context(), authHeader)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	email, err := auth.Email(ctx)
	if err != nil {
		t.Fatalf("failed to get email from context: %v", err)
	}

	if email != "apple@example.com" {
		t.Errorf("expected email apple@example.com, got %q", email)
	}
}

//nolint:paralleltest
func TestAuthenticate_AzureADB2C(t *testing.T) {
	claims := map[string]any{
		"tfp":   "mypolicy",
		"dummy": strings.Repeat("a", 500),
	}
	token := createToken(t, testKey, "https://mytenant.b2clogin.com/mytenant-uuid/v2.0", "b2c@example.com", claims)
	authHeader := "Bearer " + token

	ctx, err := auth.Authenticate(t.Context(), authHeader, auth.WithAzureADB2CTenant("mytenant"))
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	email, err := auth.Email(ctx)
	if err != nil {
		t.Fatalf("failed to get email from context: %v", err)
	}

	if email != "b2c@example.com" {
		t.Errorf("expected email b2c@example.com, got %q", email)
	}
}

//nolint:paralleltest
func TestAuthenticate_Errors(t *testing.T) {
	longClaim := map[string]any{"dummy": strings.Repeat("a", 500)}

	t.Run("Empty Auth Header", func(t *testing.T) {
		_, err := auth.Authenticate(t.Context(), "")
		if err == nil {
			t.Error("expected error for empty auth header, got nil")
		}
	})

	t.Run("Header Too Short", func(t *testing.T) {
		_, err := auth.Authenticate(t.Context(), "Bearer short")
		if err == nil {
			t.Error("expected error for short auth header, got nil")
		}
	})

	t.Run("Missing Bearer Prefix", func(t *testing.T) {
		token := createToken(t, testKey, "https://accounts.google.com", "google@example.com", longClaim)
		authHeader := "Token " + token

		_, err := auth.Authenticate(t.Context(), authHeader)
		if err == nil {
			t.Error("expected error for missing Bearer prefix, got nil")
		}
	})

	t.Run("Invalid Token Format", func(t *testing.T) {
		authHeader := "Bearer " + strings.Repeat("a", 500)

		_, err := auth.Authenticate(t.Context(), authHeader)
		if err == nil {
			t.Error("expected error for invalid token format, got nil")
		}
	})

	t.Run("Expired Token", func(t *testing.T) {
		token := jwt.New()

		_ = token.Set(jwt.IssuerKey, "https://accounts.google.com")
		_ = token.Set(jwt.AudienceKey, "test-aud")
		_ = token.Set(jwt.ExpirationKey, time.Now().Add(-time.Hour))
		_ = token.Set("email", "expired@example.com")
		_ = token.Set("dummy", strings.Repeat("a", 500))

		signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), testKey))
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}

		authHeader := "Bearer " + string(signed)

		_, err = auth.Authenticate(t.Context(), authHeader)
		if err == nil {
			t.Error("expected error for expired token, got nil")
		}
	})

	t.Run("Missing Email Claim", func(t *testing.T) {
		token := createToken(t, testKey, "https://accounts.google.com", "", longClaim)
		authHeader := "Bearer " + token

		_, err := auth.Authenticate(t.Context(), authHeader)
		if err == nil {
			t.Error("expected error for token missing email claim, got nil")
		} else {
			t.Logf("Missing Email Claim error: %v", err)
		}
	})
}

//nolint:paralleltest
func TestAuthenticate_SetValidAudience(t *testing.T) {
	// Set a custom audience validator that rejects everything
	auth.SetValidAudience(func(audiences []string) bool {
		return false
	})
	defer auth.SetValidAudience(nil)

	longClaim := map[string]any{"dummy": strings.Repeat("a", 500)}
	token := createToken(t, testKey, "https://accounts.google.com", "google@example.com", longClaim)
	authHeader := "Bearer " + token

	_, err := auth.Authenticate(t.Context(), authHeader)
	if err == nil {
		t.Error("expected error due to custom audience validator rejecting the token, got nil")
	}
}
