package oidc_test

import (
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/taomics/go-pkg/oidc"
)

func TestJWKSet_adb2c(t *testing.T) {
	t.Parallel()

	// test with common authority
	cfguri, err := oidc.Export_makeADB2CConfigurationURI("", jwt.New())
	if err != nil {
		t.Fatal(err)
	}

	testJWKSet(t, cfguri)
}

func TestParse_ADB2C(t *testing.T) {
	t.Parallel()

	tenant := os.Getenv("ADB2C_TENANT")
	if tenant == "" {
		t.Log("NO SET ADB2C_TENANT")
	}

	testParse(t, "ADB2C_ID_TOKEN", oidc.WithAzureADB2CTenant(tenant))
}
