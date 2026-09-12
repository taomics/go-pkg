package oidc_test

import (
	"testing"

	"github.com/taomics/go-pkg/oidc"
)

func TestProviderMetadata_Valid(t *testing.T) {
	// A baseline valid metadata struct
	validMetadata := func() *oidc.ProviderMetadata {
		return &oidc.ProviderMetadata{
			Issuer:                           "https://issuer.example.com",
			JWKSURI:                          "https://issuer.example.com/jwks",
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
			SubjectTypesSupported:            []string{"public"},
			ResponseTypesSupported:           []string{"id_token"},
			TokenEndpoint:                    "https://issuer.example.com/token",
			AuthorizationEndpoint:            "https://issuer.example.com/auth",
		}
	}

	t.Run("success", func(t *testing.T) {
		meta := validMetadata()
		if err := meta.Valid(); err != nil {
			t.Errorf("should be valid, but got error: %v", err)
		}
	})

	// Table-driven test for missing required fields
	testCases := []struct {
		name      string
		mutator   func(*oidc.ProviderMetadata)
		expectErr bool
	}{
		{
			name:      "missing issuer",
			mutator:   func(m *oidc.ProviderMetadata) { m.Issuer = "" },
			expectErr: true,
		},
		{
			name:      "missing jwks_uri",
			mutator:   func(m *oidc.ProviderMetadata) { m.JWKSURI = "" },
			expectErr: true,
		},
		{
			name:      "missing id_token_signing_alg_values_supported",
			mutator:   func(m *oidc.ProviderMetadata) { m.IDTokenSigningAlgValuesSupported = nil },
			expectErr: true,
		},
		{
			name:      "empty id_token_signing_alg_values_supported",
			mutator:   func(m *oidc.ProviderMetadata) { m.IDTokenSigningAlgValuesSupported = []string{} },
			expectErr: true,
		},
		{
			name:      "missing subject_types_supported",
			mutator:   func(m *oidc.ProviderMetadata) { m.SubjectTypesSupported = nil },
			expectErr: true,
		},
		{
			name:      "missing response_types_supported",
			mutator:   func(m *oidc.ProviderMetadata) { m.ResponseTypesSupported = nil },
			expectErr: true,
		},
		{
			name:      "missing token_endpoint",
			mutator:   func(m *oidc.ProviderMetadata) { m.TokenEndpoint = "" },
			expectErr: true,
		},
		{
			name:      "missing authorization_endpoint",
			mutator:   func(m *oidc.ProviderMetadata) { m.AuthorizationEndpoint = "" },
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			meta := validMetadata()
			tc.mutator(meta)

			err := meta.Valid()
			if tc.expectErr && err == nil {
				t.Error("expected error, but got nil")
			}

			if !tc.expectErr && err != nil {
				t.Errorf("did not expect error, but got: %v", err)
			}
		})
	}
}
