package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/taomics/go-pkg/oidc"
)

const (
	testKeyID = "test-kid"
)

// newKey generates a new RSA private key.
//
//nolint:ireturn
func newKey() (jwk.Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	key, err := jwk.Import[jwk.Key](priv)
	if err != nil {
		return nil, fmt.Errorf("import raw key: %w", err)
	}

	if err := key.Set(jwk.KeyIDKey, testKeyID); err != nil {
		return nil, fmt.Errorf("set key ID: %w", err)
	}

	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return nil, fmt.Errorf("set key algorithm: %w", err)
	}

	return key, nil
}

// newJws returns a signed JWT token.
func newJws(key jwk.Key, issuer, audience string, expiration time.Duration, claims map[string]any) (string, error) {
	token := jwt.New()
	if err := token.Set(jwt.IssuerKey, issuer); err != nil {
		return "", fmt.Errorf("set issuer: %w", err)
	}

	if err := token.Set(jwt.AudienceKey, audience); err != nil {
		return "", fmt.Errorf("set audience: %w", err)
	}

	if err := token.Set(jwt.ExpirationKey, time.Now().Add(expiration)); err != nil {
		return "", fmt.Errorf("set expiration: %w", err)
	}

	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			return "", fmt.Errorf("set custom claim %q: %w", k, err)
		}
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

//nolint:cyclop,gocognit,paralleltest,gocyclo,maintidx
func TestParse(t *testing.T) {
	key, err := newKey()
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	pubKey, err := key.PublicKey()
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}

	jwks := jwk.NewSet()
	if err := jwks.AddKey(pubKey); err != nil {
		t.Fatalf("failed to add key to jwks: %v", err)
	}

	// Setup a test HTTP server to provide OIDC configuration and JWKS
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                "https://issuer.example.com",
				"jwks_uri":                              "http://" + r.Host + "/jwks.json",
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"subject_types_supported":               []string{"public"},
				"response_types_supported":              []string{"id_token"},
				"token_endpoint":                        "http://" + r.Host + "/token",
				"authorization_endpoint":                "http://" + r.Host + "/auth",
			})
		case "/jwks.json":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	t.Run("success", func(t *testing.T) {
		token, err := newJws(key, "https://issuer.example.com", "test-audience", time.Hour, nil)
		if err != nil {
			t.Fatalf("failed to create JWS: %v", err)
		}

		parsed, err := oidc.Parse(context.Background(), []byte(token),
			oidc.WithAudience("test-audience"),
			oidc.WithConfigurationURI(ts.URL+"/.well-known/openid-configuration"),
		)
		if err != nil {
			t.Fatalf("Parse() failed: %v", err)
		}

		iss, _ := parsed.Issuer()
		if iss != "https://issuer.example.com" {
			t.Errorf("issuer mismatch: got %q, want %q", iss, "https://issuer.example.com")
		}
	})

	t.Run("verification error (wrong key)", func(t *testing.T) {
		wrongKey, err := newKey()
		if err != nil {
			t.Fatalf("failed to create wrong key: %v", err)
		}

		token, err := newJws(wrongKey, "https://issuer.example.com", "test-audience", time.Hour, nil)
		if err != nil {
			t.Fatalf("failed to create JWS: %v", err)
		}

		_, err = oidc.Parse(context.Background(), []byte(token),
			oidc.WithAudience("test-audience"),
			oidc.WithConfigurationURI(ts.URL+"/.well-known/openid-configuration"),
		)
		if err == nil {
			t.Error("expected signature verification error, got nil")
		}
	})

	t.Run("token is too old (expired)", func(t *testing.T) {
		token, err := newJws(key, "https://issuer.example.com", "test-audience", -time.Hour, nil)
		if err != nil {
			t.Fatalf("failed to create JWS: %v", err)
		}

		_, err = oidc.Parse(context.Background(), []byte(token),
			oidc.WithAudience("test-audience"),
			oidc.WithConfigurationURI(ts.URL+"/.well-known/openid-configuration"),
		)
		if err == nil {
			t.Error("expected expiration error, got nil")
		}
	})

	t.Run("token with exp remaining less than margin is rejected as too old", func(t *testing.T) {
		token, err := newJws(key, "https://issuer.example.com", "test-audience", 30*time.Second, nil)
		if err != nil {
			t.Fatalf("failed to create JWS: %v", err)
		}

		_, err = oidc.Parse(context.Background(), []byte(token),
			oidc.WithAudience("test-audience"),
			oidc.WithConfigurationURI(ts.URL+"/.well-known/openid-configuration"),
		)
		if err == nil {
			t.Error("expected error for token with < 60s remaining, got nil")
		}
	})

	t.Run("token nbf within clock skew is accepted", func(t *testing.T) {
		token, err := newJws(key, "https://issuer.example.com", "test-audience", time.Hour, map[string]any{
			jwt.NotBeforeKey: time.Now().Add(10 * time.Second),
		})
		if err != nil {
			t.Fatalf("failed to create JWS: %v", err)
		}

		_, err = oidc.Parse(context.Background(), []byte(token),
			oidc.WithAudience("test-audience"),
			oidc.WithConfigurationURI(ts.URL+"/.well-known/openid-configuration"),
		)
		if err != nil {
			t.Errorf("expected success for nbf within clock skew margin, got error: %v", err)
		}
	})

	t.Run("token nbf too far in future is rejected", func(t *testing.T) {
		token, err := newJws(key, "https://issuer.example.com", "test-audience", time.Hour, map[string]any{
			jwt.NotBeforeKey: time.Now().Add(2 * time.Minute),
		})
		if err != nil {
			t.Fatalf("failed to create JWS: %v", err)
		}

		_, err = oidc.Parse(context.Background(), []byte(token),
			oidc.WithAudience("test-audience"),
			oidc.WithConfigurationURI(ts.URL+"/.well-known/openid-configuration"),
		)
		if err == nil {
			t.Error("expected not active yet error, got nil")
		}
	})

	t.Run("invalid audience", func(t *testing.T) {
		token, err := newJws(key, "https://issuer.example.com", "wrong-audience", time.Hour, nil)
		if err != nil {
			t.Fatalf("failed to create JWS: %v", err)
		}

		_, err = oidc.Parse(context.Background(), []byte(token),
			oidc.WithAudience("test-audience"),
			oidc.WithConfigurationURI(ts.URL+"/.well-known/openid-configuration"),
		)
		if err == nil {
			t.Error("expected audience mismatch error, got nil")
		}
	})

	t.Run("unsupported issuer", func(t *testing.T) {
		token, err := newJws(key, "https://unsupported.com", "test-audience", time.Hour, nil)
		if err != nil {
			t.Fatalf("failed to create JWS: %v", err)
		}

		_, err = oidc.Parse(context.Background(), []byte(token),
			oidc.WithAudience("test-audience"),
		)
		if err == nil {
			t.Error("expected unsupported issuer error, got nil")
		}
	})

	t.Run("jwks fetch error", func(t *testing.T) {
		// This test needs its own server to simulate a JWKS fetch failure
		errorTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"issuer":                                "https://issuer.example.com",
					"jwks_uri":                              "http://" + r.Host + "/jwks.json", // This will fail
					"id_token_signing_alg_values_supported": []string{"RS256"},
					"subject_types_supported":               []string{"public"},
					"response_types_supported":              []string{"id_token"},
					"token_endpoint":                        "http://" + r.Host + "/token",
					"authorization_endpoint":                "http://" + r.Host + "/auth",
				})
			case "/jwks.json":
				http.Error(w, "internal server error", http.StatusInternalServerError)
			default:
				http.NotFound(w, r)
			}
		}))
		defer errorTs.Close()

		token, err := newJws(key, "https://issuer.example.com", "test-audience", time.Hour, nil)
		if err != nil {
			t.Fatalf("failed to create JWS: %v", err)
		}

		_, err = oidc.Parse(context.Background(), []byte(token),
			oidc.WithAudience("test-audience"),
			oidc.WithConfigurationURI(errorTs.URL+"/.well-known/openid-configuration"),
		)
		if err == nil {
			t.Error("expected jwks fetch error, got nil")
		}
	})

	t.Run("metadata response exceeds size limit", func(t *testing.T) {
		largeTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer": "https://issuer.example.com", "dummy": "` + strings.Repeat("A", 1024*1024+10) + `"}`))
		}))
		defer largeTs.Close()

		token, err := newJws(key, "https://issuer.example.com", "test-audience", time.Hour, nil)
		if err != nil {
			t.Fatalf("failed to create JWS: %v", err)
		}

		_, err = oidc.Parse(context.Background(), []byte(token),
			oidc.WithAudience("test-audience"),
			oidc.WithConfigurationURI(largeTs.URL+"/.well-known/openid-configuration"),
		)
		if err == nil {
			t.Error("expected metadata size limit error, got nil")
		}
	})

	t.Run("success with ADB2C issuer", func(t *testing.T) {
		if os.Getenv("RUN_LIVE_TESTS") == "" {
			t.Skip("RUN_LIVE_TESTS is not set; skipping live network test")
		}

		issuer := "https://mytenant.b2clogin.com/12345678-1234-1234-1234-123456789012/v2.0/"

		token, err := newJws(key, issuer, "test-audience", time.Hour, map[string]any{"tfp": "B2C_1_signin"})
		if err != nil {
			t.Fatalf("failed to create JWS: %v", err)
		}

		// This will fail because it tries to fetch from a real URL.
		// We are only checking that the option is used and the parse logic proceeds to the fetching step.
		_, err = oidc.Parse(context.Background(), []byte(token),
			oidc.WithAudience("test-audience"),
			oidc.WithAzureADB2CTenant("mytenant"),
		)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		// This proves we went down the right path.
		if !strings.Contains(err.Error(), "connect to") && !strings.Contains(err.Error(), "invalid url") && !strings.Contains(err.Error(), "status=404") {
			t.Errorf("expected a network, url, or 404 error, but got: %v", err)
		}
	})

	t.Run("missing kid in token header", func(t *testing.T) {
		noKidKey, err := newKey()
		if err != nil {
			t.Fatalf("failed to create key: %v", err)
		}

		_ = noKidKey.Remove(jwk.KeyIDKey)

		token, err := newJws(noKidKey, "https://issuer.example.com", "test-audience", time.Hour, nil)
		if err != nil {
			t.Fatalf("failed to create JWS: %v", err)
		}

		_, err = oidc.Parse(context.Background(), []byte(token),
			oidc.WithAudience("test-audience"),
			oidc.WithConfigurationURI(ts.URL+"/.well-known/openid-configuration"),
		)
		if err == nil {
			t.Error("expected missing kid error, got nil")
		} else if !strings.Contains(err.Error(), "no key ID") {
			t.Errorf("expected error message to contain 'no key ID', got: %v", err)
		}
	})

	t.Run("missing alg in token header", func(t *testing.T) {
		// Header without "alg"
		// {"typ":"JWT","kid":"test-kid"}
		header := "eyJ0eXAiOiJKV1QiLCJraWQiOiJ0ZXN0LWtpZCJ9"

		validToken, err := newJws(key, "https://issuer.example.com", "test-audience", time.Hour, nil)
		if err != nil {
			t.Fatalf("failed to create JWS: %v", err)
		}

		parts := strings.Split(validToken, ".")
		if len(parts) != 3 {
			t.Fatalf("unexpected token format")
		}

		invalidToken := header + "." + parts[1] + "." + parts[2]

		_, err = oidc.Parse(context.Background(), []byte(invalidToken),
			oidc.WithAudience("test-audience"),
			oidc.WithConfigurationURI(ts.URL+"/.well-known/openid-configuration"),
		)
		if err == nil {
			t.Error("expected missing alg error, got nil")
		} else if !strings.Contains(err.Error(), "could not verify message") {
			t.Errorf("expected error message to contain 'could not verify message', got: %v", err)
		}
	})
}

//nolint:cyclop,gocognit,paralleltest
func TestValidateAudience(t *testing.T) {
	// usage: validateAudience(token.Audience(), parseOption.aud)
	token := jwt.New()
	if err := token.Set(jwt.AudienceKey, []string{
		"https://example.com",
		"https://accounts.example.com",
	}); err != nil {
		t.Fatal(err)
	}

	audiences, _ := token.Audience()

	t.Log("audiences:", audiences)

	t.Run("no validation", func(t *testing.T) {
		oidc.SetValidAudience(nil)

		if err := oidc.Export_validateAudience(nil, ""); err != nil {
			t.Errorf("should not return error")
		}

		if err := oidc.Export_validateAudience(audiences, ""); err != nil {
			t.Errorf("should not return error")
		}
	})

	t.Run("WithAudience Option", func(t *testing.T) {
		if err := oidc.Export_validateAudience(audiences, "https://example.com"); err != nil {
			t.Errorf("should not return error: err=%s", err)
		}

		if err := oidc.Export_validateAudience(audiences, "https://accounts.example.com"); err != nil {
			t.Errorf("should not return error: err=%s", err)
		}

		if err := oidc.Export_validateAudience(audiences, "https://akuma.example.com"); err == nil {
			t.Errorf("should return error")
		}

		if err := oidc.Export_validateAudience(nil, "https://example.com"); err == nil {
			t.Errorf("should return error")
		}
	})

	t.Run("SetValidAudience", func(t *testing.T) {
		defer oidc.SetValidAudience(nil)

		t.Run("allow accounts.example.com", func(t *testing.T) {
			oidc.SetValidAudience(func(audiences []string) bool {
				for _, aud := range audiences {
					switch aud {
					case "https://accounts.example.com":
						return true
					}
				}

				return false
			})

			if err := oidc.Export_validateAudience(audiences, ""); err != nil {
				t.Errorf("should not return error: err=%s", err)
			}
		})

		t.Run("allow akuma.example.com", func(t *testing.T) {
			oidc.SetValidAudience(func(audiences []string) bool {
				for _, aud := range audiences {
					switch aud {
					case "https://akuma.example.com":
						return true
					}
				}

				return false
			})

			if err := oidc.Export_validateAudience(audiences, ""); err == nil {
				t.Errorf("should return error")
			}
		})

		t.Run("always true", func(t *testing.T) {
			t.Parallel()

			oidc.SetValidAudience(func(_ []string) bool {
				return true
			})

			if err := oidc.Export_validateAudience(nil, ""); err != nil {
				t.Errorf("should not return error: %v", err)
			}
		})
	})
}

//nolint:cyclop
func TestEmail(t *testing.T) {
	t.Parallel()

	t.Run("Google success", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://accounts.google.com")
		_ = tok.Set("email", "google@example.com")

		email, err := oidc.Email(tok)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if email != "google@example.com" {
			t.Errorf("got %q, want %q", email, "google@example.com")
		}
	})

	t.Run("Apple success", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://appleid.apple.com")
		_ = tok.Set("email", "apple@example.com")

		email, err := oidc.Email(tok)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if email != "apple@example.com" {
			t.Errorf("got %q, want %q", email, "apple@example.com")
		}
	})

	t.Run("ADB2C preferred_username success", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://tenant.b2clogin.com/tfp/")
		_ = tok.Set("preferred_username", "adb2c-pref@example.com")

		email, err := oidc.Email(tok)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if email != "adb2c-pref@example.com" {
			t.Errorf("got %q, want %q", email, "adb2c-pref@example.com")
		}
	})

	t.Run("ADB2C emails array success", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://tenant.b2clogin.com/tfp/")
		_ = tok.Set("emails", []any{"invalid-email", "adb2c-array@example.com"})

		email, err := oidc.Email(tok)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if email != "adb2c-array@example.com" {
			t.Errorf("got %q, want %q", email, "adb2c-array@example.com")
		}
	})

	t.Run("unsupported issuer", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://unsupported.com")

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("invalid email format", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://accounts.google.com")
		_ = tok.Set("email", "not-an-email")

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("empty email", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://accounts.google.com")
		_ = tok.Set("email", "")

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("unexpected type email", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://accounts.google.com")
		_ = tok.Set("email", 123)

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("ADB2C no email in token", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://tenant.b2clogin.com/tfp/")

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("ADB2C unexpected emails value type", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://tenant.b2clogin.com/tfp/")
		_ = tok.Set("emails", "not-an-array")

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("ADB2C preferred_username wrong type", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://tenant.b2clogin.com/tfp/")
		_ = tok.Set("preferred_username", 123)
		_ = tok.Set("emails", []any{"invalid-email"})

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

//nolint:cyclop
func TestMakeADB2CConfigurationURI(t *testing.T) {
	t.Parallel()

	t.Run("common tenant without policy", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()

		uri, err := oidc.Export_makeADB2CConfigurationURI("", tok)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
		if uri != expected {
			t.Errorf("got %q, want %q", uri, expected)
		}
	})

	t.Run("common tenant with policy (error)", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set("tfp", "B2C_1_signin")

		_, err := oidc.Export_makeADB2CConfigurationURI("", tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("specific tenant with policy", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set("tfp", "B2C_1_signin")

		uri, err := oidc.Export_makeADB2CConfigurationURI("mytenant", tok)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := "https://mytenant.b2clogin.com/mytenant.onmicrosoft.com/B2C_1_signin/v2.0/.well-known/openid-configuration"
		if uri != expected {
			t.Errorf("got %q, want %q", uri, expected)
		}
	})

	t.Run("specific tenant without policy", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()

		uri, err := oidc.Export_makeADB2CConfigurationURI("mytenant", tok)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := "https://mytenant.b2clogin.com/mytenant.onmicrosoft.com/v2.0/.well-known/openid-configuration"
		if uri != expected {
			t.Errorf("got %q, want %q", uri, expected)
		}
	})

	t.Run("invalid tfp type", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set("tfp", 123)

		_, err := oidc.Export_makeADB2CConfigurationURI("mytenant", tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("specific tenant with policy in acr", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set("acr", "B2C_1_signin_acr")

		uri, err := oidc.Export_makeADB2CConfigurationURI("mytenant", tok)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := "https://mytenant.b2clogin.com/mytenant.onmicrosoft.com/B2C_1_signin_acr/v2.0/.well-known/openid-configuration"
		if uri != expected {
			t.Errorf("got %q, want %q", uri, expected)
		}
	})

	t.Run("invalid acr type", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set("acr", 123)

		_, err := oidc.Export_makeADB2CConfigurationURI("mytenant", tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("invalid tfp format (traversal)", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set("tfp", "../malicious_policy")

		_, err := oidc.Export_makeADB2CConfigurationURI("mytenant", tok)
		if err == nil {
			t.Error("expected error for traversal in tfp, got nil")
		}
	})

	t.Run("invalid acr format (special chars)", func(t *testing.T) {
		t.Parallel()

		tok := jwt.New()
		_ = tok.Set("acr", "policy/with/slashes")

		_, err := oidc.Export_makeADB2CConfigurationURI("mytenant", tok)
		if err == nil {
			t.Error("expected error for slashes in acr, got nil")
		}
	})
}

type testRoundTripper func(req *http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

//nolint:cyclop,paralleltest
func TestDefaultHTTPClient_UsedForJWKS(t *testing.T) {
	origTransport := oidc.DefaultHTTPClient.Transport
	defer func() {
		oidc.DefaultHTTPClient.Transport = origTransport
	}()

	key, err := newKey()
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	pubKey, err := key.PublicKey()
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}

	jwks := jwk.NewSet()
	if err := jwks.AddKey(pubKey); err != nil {
		t.Fatalf("failed to add key to jwks: %v", err)
	}

	jwksJSON, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("failed to marshal jwks: %v", err)
	}

	var metadataFetched, jwksFetched bool

	oidc.DefaultHTTPClient.Transport = testRoundTripper(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://custom-client-test.example.com/.well-known/openid-configuration":
			metadataFetched = true
			body := `{
				"issuer": "https://custom-client-test.example.com",
				"jwks_uri": "https://custom-client-test.example.com/keys",
				"id_token_signing_alg_values_supported": ["RS256"],
				"subject_types_supported": ["public"],
				"response_types_supported": ["id_token"],
				"token_endpoint": "https://custom-client-test.example.com/token",
				"authorization_endpoint": "https://custom-client-test.example.com/auth"
			}`

			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    req,
			}, nil
		case "https://custom-client-test.example.com/keys":
			jwksFetched = true

			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(string(jwksJSON))),
				Request:    req,
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("not found")),
				Request:    req,
			}, nil
		}
	})

	set, err := oidc.JWKSet(context.Background(), "https://custom-client-test.example.com/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("JWKSet failed: %v", err)
	}

	if set.Len() == 0 {
		t.Error("expected non-empty key set")
	}

	if !metadataFetched {
		t.Error("expected metadata to be fetched via DefaultHTTPClient")
	}

	if !jwksFetched {
		t.Error("expected JWKS to be fetched via DefaultHTTPClient")
	}
}
