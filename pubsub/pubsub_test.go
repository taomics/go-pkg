package pubsub_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gpubsub "cloud.google.com/go/pubsub"
	"github.com/taomics/go-pkg/pubsub"
)

type mockMessageHandler struct {
	handleFunc func([]byte) error
}

func (m *mockMessageHandler) Handle(message []byte) error {
	return m.handleFunc(message)
}

func TestNewSubscriptionHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		method         string
		body           string
		handleFunc     func([]byte) error
		wantStatusCode int
	}{
		{
			name:   "valid message",
			method: http.MethodPost,
			body:   `{"message":{"data":"eyJoZWFsdGhmZWVkYmFja19pZCI6InRlc3QifQ=="}}`,
			handleFunc: func(_ []byte) error {
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

type mockTopic struct {
	err error
}

func (t *mockTopic) Publish(_ context.Context, _ *gpubsub.Message) *gpubsub.PublishResult {
	return &gpubsub.PublishResult{}
}

func (t *mockTopic) Stop() {}

type mockClient struct {
	topic *mockTopic
}

func (m *mockClient) Topic(_ string) pubsub.Topic {
	return m.topic
}

func (m *mockClient) Close() error {
	return nil
}

func TestPublish(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	message := &pubsub.GenerateHealthFeedbackMessage{
		HealthFeedbackID: "test",
	}

	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{
			name:    "successful publish",
			err:     nil,
			wantErr: false,
		},
		{
			name:    "publish error",
			err:     context.DeadlineExceeded,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockTopic := &mockTopic{err: tt.err}
			p := &pubsub.DefaultPublisher{
				Client: &mockClient{topic: mockTopic},
			}

			err := p.Publish(ctx, pubsub.TopicGenerateHealthFeedback, message)
			if (err != nil) != tt.wantErr {
				t.Errorf("Publish() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPublishContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()



	message := &pubsub.GenerateHealthFeedbackMessage{
		HealthFeedbackID: "test",
	}

	mockTopic := &mockTopic{err: context.DeadlineExceeded}
	p := &pubsub.DefaultPublisher{
		Client: &mockClient{topic: mockTopic},
	}

	// Wait for context to be cancelled
	time.Sleep(2 * time.Millisecond)

	if err := p.Publish(ctx, pubsub.TopicGenerateHealthFeedback, message); err == nil {
		t.Error("Publish() should return error when context is cancelled")
	}
}
