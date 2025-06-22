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
	Publish(ctx context.Context, topic string, message Message, opts ...PublishOption) error
}

type puslishOption struct {
	attr  map[string]string
	order string
}

type PublishOption func(*puslishOption)

func WithAttributes(attr map[string]string) PublishOption {
	return func(o *puslishOption) {
		o.attr = attr
	}
}

func WithOrderingKey(order string) PublishOption {
	return func(o *puslishOption) {
		o.order = order
	}
}

// client wraps pubsub.Client to implement Client interface.
type client struct {
	c *pubsub.Client
}

//nolint:ireturn
func NewPublisher(ctx context.Context, projectID string) (Publisher, error) {
	c, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub client: %w", err)
	}

	return &client{c: c}, nil
}

// Publish publishes a message to the specified topic.
func (p *client) Publish(ctx context.Context, topic string, message Message, opts ...PublishOption) error {
	var popts puslishOption
	for _, f := range opts {
		f(&popts)
	}

	t := p.c.Topic(topic)
	defer t.Stop()

	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	//nolint:exhaustruct
	result := t.Publish(ctx, &pubsub.Message{
		Data:        data,
		Attributes:  popts.attr,
		OrderingKey: popts.order,
	})
	if _, err := result.Get(ctx); err != nil {
		log.Errorf("failed to publish message: %v", err)
		return fmt.Errorf("failed to publish message: %w", err)
	}

	log.Printf("published message to topic %s", topic)

	return nil
}
