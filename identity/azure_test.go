package identity_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/taomics/go-pkg/identity"
)

func TestAzureIdentity(t *testing.T) {
	if v := os.Getenv("IDENTITY_ENDPOINT"); v != "" {
		t.Fatal("IDENTITY_ENDPOINT should not be set for test")
	}

	ctx := context.Background()

	_, err := identity.GetAzureManagedIdentity(ctx)
	if !errors.Is(err, identity.ErrInvalidEndpoint) {
		t.Errorf("should return ErrInvalidEndpoint: %s", err)
	}
}
