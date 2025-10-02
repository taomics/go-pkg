package pubsub

import (
	"context"
	"encoding/json"
	"fmt"

	pubsub "cloud.google.com/go/pubsub/v2"
	"github.com/taomics/go-pkg/log"
)

// Publisher defines the interface for publishing messages to topics.
type Publisher interface {
	Publish(ctx context.Context, message Message, opts ...PublishOption) error
	Topic() string
	Close() error
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

// client wraps pubsub.Publisher to implement Publisher interface.
type client struct {
	c         *pubsub.Client
	publisher *pubsub.Publisher
	topicID   string
}

// NewPublisher creates a new Publisher instance for the specified project and topic.
// A caller should Close() the returned Publisher when it is no longer needed to release resources.
// if projectID is empty, it will be automatically detected.
//
//nolint:ireturn
func NewPublisher(ctx context.Context, projectID string, topicID string) (Publisher, error) {
	if projectID == "" {
		projectID = pubsub.DetectProjectID // Automatically detect the project ID of this application.
	}

	c, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub client: %w", err)
	}

	return &client{
		c:         c,
		publisher: c.Publisher(topicID),
		topicID:   topicID,
	}, nil
}

// Publish publishes a message to the specified topic.
func (c *client) Publish(ctx context.Context, message Message, opts ...PublishOption) error {
	var popts puslishOption
	for _, f := range opts {
		f(&popts)
	}

	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	//nolint:exhaustruct
	result := c.publisher.Publish(ctx, &pubsub.Message{
		Data:        data,
		Attributes:  popts.attr,
		OrderingKey: popts.order,
	})
	if _, err := result.Get(ctx); err != nil {
		log.Errorf("failed to publish message: %v", err)
		return fmt.Errorf("failed to publish message: %w", err)
	}

	log.Printf("published message to topic %s", c.topicID)

	return nil
}

// Topic returns the topic ID the publisher is publishing to.
func (c *client) Topic() string {
	return c.topicID
}

// Close stops the publisher and closes the pubsub client.
func (c *client) Close() error {
	c.publisher.Stop()

	if err := c.c.Close(); err != nil {
		return fmt.Errorf("failed to close pubsub.Client: %w", err)
	}

	return nil
}
