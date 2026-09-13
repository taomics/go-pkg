//go:build integration

package oidc_test

import (
	"testing"

	"github.com/taomics/go-pkg/oidc"
)

func TestJWKSet_apple(t *testing.T) {
	t.Parallel()
	testJWKSet(t, oidc.Export_appleConfigurationURI)
}

func TestParse_Apple(t *testing.T) {
	t.Parallel()
	testParse(t, "APPLE_ID_TOKEN")
}
