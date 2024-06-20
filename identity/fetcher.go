package identity

import (
	"context"
	"net/http"
)

var defaultFetcher Fetcher = httpFetcher{&http.Client{}}

type Fetcher interface {
	Fetch(context.Context, *http.Request) (*http.Response, error)
}

func SetFetcher(f Fetcher) {
	if f == nil {
		f = httpFetcher{&http.Client{}}
	}

	defaultFetcher = f
}

type httpFetcher struct {
	client *http.Client
}

func (f httpFetcher) Fetch(ctx context.Context, req *http.Request) (*http.Response, error) {
	return f.client.Do(req.WithContext(ctx))
}
