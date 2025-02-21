package pubsub

import (
	"context"
	"encoding/json"
	"fmt"

	"cloud.google.com/go/pubsub"
	"github.com/taomics/go-pkg/log"
)

// Publisher defines the interface for publishing messages to topics.
type Publisher interface {
	Publish(ctx context.Context, topic string, message interface{}) error
}

// NewPublisher creates a new Publisher instance.
// Topic represents a Pub/Sub topic.
type Topic interface {
	Publish(ctx context.Context, msg *pubsub.Message) *pubsub.PublishResult
	Stop()
}

// Client represents a Pub/Sub client.
type Client interface {
	Topic(id string) Topic
	Close() error
}

// DefaultPublisher is the default implementation of Publisher interface.
type DefaultPublisher struct {
	Client Client
}

// NewPublisher creates a new Publisher instance.
// realTopic wraps pubsub.Topic to implement Topic interface.
type realTopic struct {
	*pubsub.Topic
}

// realClient wraps pubsub.Client to implement Client interface.
type realClient struct {
	*pubsub.Client
}

func (c *realClient) Topic(id string) Topic {
	return &realTopic{c.Client.Topic(id)}
}

func NewPublisher(ctx context.Context, projectID string) (Publisher, error) {
	client, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub client: %w", err)
	}

	return &DefaultPublisher{Client: &realClient{client}}, nil
}

// Publish publishes a message to the specified topic.
func (p *DefaultPublisher) Publish(ctx context.Context, topic string, message interface{}) error {
	t := p.Client.Topic(topic)
	defer t.Stop()

	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	result := t.Publish(ctx, &pubsub.Message{Data: data})
	if _, err := result.Get(ctx); err != nil {
		log.Errorf("failed to publish message: %v", err)
		return fmt.Errorf("failed to publish message: %w", err)
	}

	log.Printf("published message to topic %s", topic)

	return nil
}
