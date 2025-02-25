package pubsub_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/taomics/go-pkg/pubsub"
)

type mockMessageHandler struct {
	handleFunc func(context.Context, []byte) error
}

func (m *mockMessageHandler) Handle(ctx context.Context, message []byte) error {
	return m.handleFunc(ctx, message)
}

func TestNewSubscriptionHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		method         string
		body           string
		handleFunc     func(context.Context, []byte) error
		wantStatusCode int
	}{
		{
			name:   "valid message",
			method: http.MethodPost,
			body:   `{"message":{"data":"eyJoZWFsdGhmZWVkYmFja19pZCI6InRlc3QifQ=="}}`,
			handleFunc: func(_ context.Context, _ []byte) error {
				return nil
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "invalid method",
			method:         http.MethodGet,
			body:           "",
			handleFunc:     nil,
			wantStatusCode: http.StatusMethodNotAllowed,
		},
		{
			name:           "invalid json",
			method:         http.MethodPost,
			body:           `invalid json`,
			handleFunc:     nil,
			wantStatusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := &mockMessageHandler{handleFunc: tt.handleFunc}
			server := httptest.NewServer(pubsub.NewSubscriptionHandler(handler))

			defer server.Close()

			req, err := http.NewRequestWithContext(context.Background(), tt.method, server.URL, strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("failed to send request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("got status code %d, want %d", resp.StatusCode, tt.wantStatusCode)
			}
		})
	}
}
