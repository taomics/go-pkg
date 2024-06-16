package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

var (
	ErrInvalidEndpoint = errors.New("invalid endpoint")
)

type AzureIdentity struct {
	AccessToken string
	ExpiresOn   time.Time
}

// https://github.com/Azure/azure-sdk-for-go/blob/main/sdk/azidentity/TROUBLESHOOTING.md#verify-the-app-service-managed-identity-endpoint-is-available
func GetAzureManagedIdentity(ctx context.Context) (*AzureIdentity, error) {
	const (
		apiVersion          = "2019-08-01"
		resource            = "https://ossrdbms-aad.database.windows.net" // also work with "https://management.core.windows.net/"
		envIdentityEndpoint = "IDENTITY_ENDPOINT"
		envIdentityHeader   = "IDENTITY_HEADER"
	)

	endpoint := os.Getenv(envIdentityEndpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("%w: please set IDENTITY_ENDPOINT", ErrInvalidEndpoint)
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEndpoint, err)
	}

	q := u.Query()

	q.Add("api-version", apiVersion)
	q.Add("resource", resource)

	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("x-identity-header", os.Getenv(envIdentityHeader))

	var (
		res         *http.Response
		maxAttempts = 5
	)

	//
	for {
		res, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}

		maxAttempts--

		if maxAttempts == 0 {
			return nil, err
		}

		log.Println(err.Error(), "retrying in 5 seconds...")
		time.Sleep(5 * time.Second)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		buf, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("unexpected status %d: %s: %s", res.StatusCode, string(buf), u)
	}

	obj := make(map[string]any)

	if err := json.NewDecoder(res.Body).Decode(&obj); err != nil {
		return nil, err
	}

	at, ok := obj["access_token"]
	if !ok {
		return nil, fmt.Errorf("no access_token")
	}

	st, ok := at.(string)
	if !ok {
		return nil, fmt.Errorf("invalid access_token")
	}

	exp, ok := obj["expires_on"]
	if !ok {
		return nil, fmt.Errorf("no expires_on")
	}

	sexp, ok := exp.(string)
	if !ok {
		return nil, fmt.Errorf("invalid expires_on type")
	}

	n, err := strconv.Atoi(sexp)
	if err != nil {
		return nil, err
	}

	t := time.Unix(int64(n), 0)
	if t.Before(time.Now()) {
		return nil, fmt.Errorf("already expired: %s", t)
	}

	return &AzureIdentity{
		AccessToken: st,
		ExpiresOn:   t,
	}, nil
}
