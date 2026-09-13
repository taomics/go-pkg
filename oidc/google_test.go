//go:build integration

package oidc_test

import (
	"testing"

	"github.com/taomics/go-pkg/oidc"
)

func TestJWKSet_Google(t *testing.T) {
	t.Parallel()
	testJWKSet(t, oidc.Export_googleConfigurationURI)
}

func TestParse_Google(t *testing.T) {
	t.Parallel()
	testParse(t, "GOOGLE_ID_TOKEN")
}
