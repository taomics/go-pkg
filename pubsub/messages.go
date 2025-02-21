package pubsub

// CreateHealthFeedbackJobMessage represents the message structure for create-health-feedback-job topic.
type CreateHealthFeedbackJobMessage struct {
	AccountID          string  `json:"account_id"`
	EventType          string  `json:"event_type"`
	LifestyleJournalID *string `json:"lifestylejournal_id,omitempty"` // lifejournal_recorded の場合にのみ存在
	HealthMode         *string `json:"health_mode,omitempty"`         // health_mode_updated の場合にのみ存在
}

// GenerateHealthFeedbackMessage represents the message structure for generate-health-feedback topic.
type GenerateHealthFeedbackMessage struct {
	HealthFeedbackID string `json:"healthfeedback_id"`
}
