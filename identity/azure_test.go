package identity_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/taomics/go-pkg/identity"
)

func TestAzure_GetAzureManagedIdentity(t *testing.T) {
	if v := os.Getenv("IDENTITY_ENDPOINT"); v != "" {
		t.Fatal("IDENTITY_ENDPOINT should not be set for test")
	}

	ctx := context.Background()

	_, err := identity.GetAzureManagedIdentity(ctx)
	if !errors.Is(err, identity.ErrInvalidEndpoint) {
		t.Errorf("should return ErrInvalidEndpoint: %s", err)
	}
}

func TestAzure_RunRefreshLoop_update(t *testing.T) {
	os.Setenv("IDENTITY_ENDPOINT", "http://test")
	defer os.Unsetenv("IDENTITY_ENDPOINT")

	ctx := context.Background()

	aid := &identity.AzureManagedIdentity{
		AccessToken: "test token",
		ExpiresOn:   time.Now().Add(5 * time.Millisecond),
	}

	identity.SetFetcher(&testFetcher{
		status: 200,
		body: &testFetcherBody{
			AccessToken: "test token 2",
			ExpiresOn:   strconv.Itoa(int(aid.ExpiresOn.Add(5 * time.Second).Unix())),
		},
	})
	defer identity.SetFetcher(nil)

	done := make(chan struct{})
	defer close(done)

	tested := false

	err := aid.RunRefreshLoop(ctx, func(token *identity.AzureManagedIdentity, err error) error {
		if tested {
			return fmt.Errorf("stop loop")
		}

		if err != nil {
			t.Errorf("should not return error: %s", err)
		} else {
			if "test token 2" != token.AccessToken {
				t.Errorf(`want "test token 2", got %q`, token.AccessToken)
			}
		}

		done <- struct{}{}
		tested = true

		return nil
	})

	if err != nil {
		t.Fatal(err)
	}

	// first
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout")
	case <-done:
		break
	}

	// second
	select {
	case <-time.After(100 * time.Millisecond):
		break
	case <-done:
		t.Error("should be timeout because that callback return error")
	}
}

func TestAzure_RunRefreshLoop_failUpdate(t *testing.T) {
	os.Setenv("IDENTITY_ENDPOINT", "http://test")
	defer os.Unsetenv("IDENTITY_ENDPOINT")

	ctx := context.Background()

	aid := &identity.AzureManagedIdentity{
		AccessToken: "test token",
		ExpiresOn:   time.Now().Add(5 * time.Millisecond),
	}

	identity.SetFetcher(&testFetcher{
		status: 200,
		body: &testFetcherBody{
			AccessToken: "test token", // same token
			ExpiresOn:   strconv.Itoa(int(time.Now().Add(5 * time.Second).Unix())),
		},
	})
	defer identity.SetFetcher(nil)

	done := make(chan struct{})

	err := aid.RunRefreshLoop(ctx, func(token *identity.AzureManagedIdentity, err error) error {
		if err == nil {
			t.Errorf("should return error")
		} else {
			t.Log(err)
		}

		done <- struct{}{}

		return nil
	})

	if err != nil {
		t.Fatal(err)
	}

	// first
	select {
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout")
	case <-done:
		break
	}

	// second
	select {
	case <-time.After(100 * time.Millisecond):
		break
	case <-done:
		t.Error("should be timeout because of fail refresh loop")
	}
}

type testFetcher struct {
	status int
	body   *testFetcherBody
}

type testFetcherBody struct {
	AccessToken string `json:"access_token"`
	ExpiresOn   string `json:"expires_on"`
}

func (f *testFetcher) Fetch(ctx context.Context, req *http.Request) (*http.Response, error) {
	var b bytes.Buffer
	if f.body != nil {
		if err := json.NewEncoder(&b).Encode(f.body); err != nil {
			return nil, err
		}
	}

	res := http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(&b),
	}

	return &res, nil
}
