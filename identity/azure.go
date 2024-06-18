package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

var (
	ErrInvalidEndpoint = errors.New("invalid endpoint")
)

type AzureManagedIdentityOption func(*azureFetchOption)

type azureFetchOption struct {
	maxAttempts int
}

func WithMaxAttempts(n int) AzureManagedIdentityOption {
	return func(o *azureFetchOption) {
		o.maxAttempts = n
	}
}

type AzureManagedIdentity struct {
	AccessToken string
	ExpiresOn   time.Time
}

// https://github.com/Azure/azure-sdk-for-go/blob/main/sdk/azidentity/TROUBLESHOOTING.md#verify-the-app-service-managed-identity-endpoint-is-available
func GetAzureManagedIdentity(ctx context.Context, opts ...AzureManagedIdentityOption) (*AzureManagedIdentity, error) {
	const (
		apiVersion          = "2019-08-01"
		resource            = "https://ossrdbms-aad.database.windows.net" // also work with "https://management.core.windows.net/"
		envIdentityEndpoint = "IDENTITY_ENDPOINT"
		envIdentityHeader   = "IDENTITY_HEADER"
	)

	opt := azureFetchOption{
		maxAttempts: 5,
	}

	for _, f := range opts {
		f(&opt)
	}

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

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	req.Header.Add("x-identity-header", os.Getenv(envIdentityHeader))

	var (
		res         *http.Response
		maxAttempts = opt.maxAttempts
	)

	for {
		res, err = defaultFetcher.Fetch(ctx, req)
		if err == nil {
			break
		}

		maxAttempts--

		if maxAttempts <= 0 {
			return nil, fmt.Errorf("filed to get: %w", err)
		}

		slog.Warn("go-pkg/identity: retrying in 5 seconds...", "error", err)
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

	return &AzureManagedIdentity{
		AccessToken: st,
		ExpiresOn:   t,
	}, nil
}

func (a *AzureManagedIdentity) RunRefreshLoop(
	ctx context.Context,
	callback func(*AzureManagedIdentity, error) error,
	opts ...AzureManagedIdentityOption,
) error {
	const retryInterval = 5 * time.Minute
	d, err := refreshDuration(a.ExpiresOn)
	if err != nil {
		return err
	}
	ti := time.NewTimer(d)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return

			case <-ti.C:
				var d time.Duration

				token, err := GetAzureManagedIdentity(ctx, opts...)
				if err == nil && token.AccessToken == a.AccessToken {
					err = errors.New("token is not updated")
				}

				if err == nil {
					d, err = refreshDuration(token.ExpiresOn)
				}

				if err != nil {
					slog.Warn("go-pkg/identity: failed to get new azure managed identity", "error", err)
				} else {
					err = callback(token, nil)
					if err != nil {
						slog.Warn("go-pkg/identity: cannot use a new azure managed identity in callback", "error", err)
					}
				}

				// retry
				if err != nil {
					if time.Until(a.ExpiresOn) < retryInterval {
						_ = callback(nil, fmt.Errorf("token expired too soon, cannot refresh token: expires_on=%s", a.ExpiresOn))
						return
					}

					ti.Reset(retryInterval)
					break
				}

				a.AccessToken = token.AccessToken
				a.ExpiresOn = token.ExpiresOn

				ti.Reset(d)
			}
		}
	}()

	return nil
}

func refreshDuration(t time.Time) (time.Duration, error) {
	const refreshMargion = 1 * time.Hour

	d := time.Until(t)
	if d < 0 {
		return 0, fmt.Errorf("unexpected negative refresh duration (avoiding infinity loop):  expires_on=%s", t)
	}

	if d < refreshMargion {
		slog.Warn("go-pkg/identity: duration is too short", "duration", d)
		return d, nil
	}

	d -= refreshMargion

	slog.Info("go-pkg/identity: refresh duration", "duration", d)

	return d, nil
}
