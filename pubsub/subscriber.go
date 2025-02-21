package pubsub

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/taomics/go-pkg/log"
)

// MessageHandler defines the interface for handling Pub/Sub messages.
type MessageHandler interface {
	Handle(message []byte) error
}

// Message represents the message structure received from Pub/Sub push subscription.
type Message struct {
	Message struct {
		Data []byte `json:"data"`
	} `json:"message"`
}

// NewSubscriptionHandler creates a new HTTP handler for Pub/Sub push subscriptions.
func NewSubscriptionHandler(handler MessageHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		var message Message
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			log.Errorf("failed to decode message: %v", err)
			http.Error(w, fmt.Sprintf("failed to decode message: %v", err), http.StatusBadRequest)

			return
		}

		if err := handler.Handle(message.Message.Data); err != nil {
			log.Errorf("failed to handle message: %v", err)
			http.Error(w, fmt.Sprintf("failed to handle message: %v", err), http.StatusInternalServerError)

			return
		}

		w.WriteHeader(http.StatusOK)
	}
}
