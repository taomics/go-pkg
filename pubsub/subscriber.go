package pubsub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/taomics/go-pkg/log"
)

var errRetryable = errors.New("retryable error")

func RetryableError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errRetryable, fmt.Sprintf(format, args...))
}

// MessageHandler defines the interface for handling Pub/Sub messages.
type MessageHandler interface {
	Handle(ctx context.Context, message []byte) error
}

// PubSubMessage is the payload of a Pub/Sub event.
// See the documentation for more details:
// https://cloud.google.com/pubsub/docs/reference/rest/v1/PubsubMessage
//
//nolint:revive
type PubSubMessage struct {
	Message struct {
		Data []byte `json:"data,omitempty"`
		ID   string `json:"id"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

// NewSubscriptionHandler creates a new HTTP handler for Pub/Sub push subscriptions.
func NewSubscriptionHandler(handler MessageHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Errorf("read request body: %v", err)
			return // return 200 OK, no need to retry
		}

		var msg PubSubMessage
		if err := json.Unmarshal(body, &msg); err != nil {
			log.Errorf("failed to decode message: body=%s: %v", body, err)
			return // return 200 OK, no need to retry
		}

		if len(msg.Message.Data) == 0 {
			log.Errorf("empty data: msg=%+v", msg)
			return // return 200 OK, no need to retry
		}

		if err := handler.Handle(r.Context(), msg.Message.Data); err != nil {
			log.Errorf("failed to handle message: %v: msg=%+v: %v", err, msg)

			if errors.Is(err, errRetryable) {
				w.WriteHeader(http.StatusInternalServerError)
				return // return 500 Internal Server, need to retry
			}
		}
	}
}
