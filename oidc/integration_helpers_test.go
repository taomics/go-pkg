//go:build integration

package oidc_test

import (
	"context"
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/taomics/go-pkg/oidc"
)

func testJWKSet(t *testing.T, cfguri string) {
	t.Helper()

	if os.Getenv("RUN_LIVE_TESTS") == "" {
		t.Skip("RUN_LIVE_TESTS is not set; skipping live network test")
	}

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

	t.Logf("Parse %s: email=%s", envkey, email)
}
