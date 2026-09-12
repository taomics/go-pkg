package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log"
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
func newKey() (jwk.Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	key, err := jwk.Import[jwk.Key](priv)
	if err != nil {
		return nil, err
	}

	if err := key.Set(jwk.KeyIDKey, testKeyID); err != nil {
		return nil, err
	}

	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return nil, err
	}

	return key, nil
}

// newJws returns a signed JWT token.
func newJws(key jwk.Key, issuer, audience string, expiration time.Duration, claims map[string]interface{}) (string, error) {
	token := jwt.New()
	if err := token.Set(jwt.IssuerKey, issuer); err != nil {
		return "", err
	}

	if err := token.Set(jwt.AudienceKey, audience); err != nil {
		return "", err
	}

	if err := token.Set(jwt.ExpirationKey, time.Now().Add(expiration)); err != nil {
		return "", err
	}

	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			return "", err
		}
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

//nolint:cyclop,gocognit,paralleltest
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
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
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
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
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

	t.Run("success with ADB2C issuer", func(t *testing.T) {
		issuer := "https://mytenant.b2clogin.com/12345678-1234-1234-1234-123456789012/v2.0/"
		token, err := newJws(key, issuer, "test-audience", time.Hour, map[string]interface{}{"tfp": "B2C_1_signin"})
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
		if !strings.Contains(err.Error(), "connect to") && !strings.Contains(err.Error(), "invalid url") && !strings.Contains(err.Error(), "stauts=404") {
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
		} else if !strings.Contains(err.Error(), "missing kid") {
			t.Errorf("expected error message to contain 'missing kid', got: %v", err)
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
		} else if !strings.Contains(err.Error(), "missing alg") {
			t.Errorf("expected error message to contain 'missing alg', got: %v", err)
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
			oidc.SetValidAudience(func(_ []string) bool {
				return false
			})

			if err := oidc.Export_validateAudience(nil, ""); err == nil {
				t.Errorf("should not return error")
			}
		})
	})
}

func testJWKSet(t *testing.T, cfguri string) {
	t.Helper()

	ctx := context.Background()

	set, err := oidc.JWKSet(ctx, cfguri)
	if err != nil {
		t.Fatal(err)
	}

	if !oidc.CheckCache(cfguri) {
		t.Errorf("should be registered: %s", cfguri)
	}

	t.Logf("there is %d keys", set.Len())

	if set.Len() == 0 {
		t.Fatal("empty JWK set")
	}

	for idx, key := range set.All() {
		v, err := jwk.PublicKeyOf(key)
		if err != nil {
			t.Errorf("failed to get public key: %v", err)
			continue
		}

		kid, _ := v.KeyID()
		t.Logf("%d: %+v", idx, kid)
	}
}

func testParse(t *testing.T, envkey string, opts ...oidc.ParseOption) {
	t.Helper()

	token := os.Getenv(envkey)
	if token == "" {
		t.Skip(envkey + " is not set")
	}

	ret, err := oidc.Parse(context.Background(), []byte(token), opts...)
	if err != nil {
		t.Fatal(err)
	}

	email, err := oidc.Email(ret)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Parse %s: email=%s", envkey, email)
}

func TestEmail(t *testing.T) {
	t.Run("Google success", func(t *testing.T) {
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
		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://tenant.b2clogin.com/tfp/")
		_ = tok.Set("emails", []interface{}{"invalid-email", "adb2c-array@example.com"})

		email, err := oidc.Email(tok)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if email != "adb2c-array@example.com" {
			t.Errorf("got %q, want %q", email, "adb2c-array@example.com")
		}
	})

	t.Run("unsupported issuer", func(t *testing.T) {
		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://unsupported.com")

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("invalid email format", func(t *testing.T) {
		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://accounts.google.com")
		_ = tok.Set("email", "not-an-email")

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("empty email", func(t *testing.T) {
		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://accounts.google.com")
		_ = tok.Set("email", "")

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("unexpected type email", func(t *testing.T) {
		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://accounts.google.com")
		_ = tok.Set("email", 123)

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("ADB2C no email in token", func(t *testing.T) {
		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://tenant.b2clogin.com/tfp/")

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("ADB2C unexpected emails value type", func(t *testing.T) {
		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://tenant.b2clogin.com/tfp/")
		_ = tok.Set("emails", "not-an-array")

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("ADB2C preferred_username wrong type", func(t *testing.T) {
		tok := jwt.New()
		_ = tok.Set(jwt.IssuerKey, "https://tenant.b2clogin.com/tfp/")
		_ = tok.Set("preferred_username", 123)
		_ = tok.Set("emails", []interface{}{"invalid-email"})

		_, err := oidc.Email(tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestMakeADB2CConfigurationURI(t *testing.T) {
	t.Run("common tenant without policy", func(t *testing.T) {
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
		tok := jwt.New()
		_ = tok.Set("tfp", "B2C_1_signin")
		_, err := oidc.Export_makeADB2CConfigurationURI("", tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("specific tenant with policy", func(t *testing.T) {
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
		tok := jwt.New()
		_ = tok.Set("tfp", 123)
		_, err := oidc.Export_makeADB2CConfigurationURI("mytenant", tok)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}
