package pubsub

const (
	Topic_CreateHealthFeedbackJob = "create-health-feedback-job"
	Topic_GenerateHealthFeedback  = "generate-health-feedback"
)

type HealthFeedbackEventType string

const (
	HealthFeedbackEventType_LifeJournalRecorded HealthFeedbackEventType = "lifejournal_recorded"
	HealthFeedbackEventType_HealthModeUpdated   HealthFeedbackEventType = "health_mode_updated"
)

// CreateHealthFeedbackJobMessage represents the message structure for create-health-feedback-job topic.
type CreateHealthFeedbackJobMessage struct {
	AccountID int64                   `json:"account_id"`
	EventType HealthFeedbackEventType `json:"event_type"`

	// LifestyleJournalID is require only when EventType is lifejournal_recorded.
	LifestyleJournalID int64 `json:"lifestylejournal_id,omitempty"`

	// HealthMode is require only when EventType is health_mode_updated.
	HealthMode string `json:"health_mode,omitempty"`
}

// GenerateHealthFeedbackMessage represents the message structure for generate-health-feedback topic.
type GenerateHealthFeedbackMessage struct {
	HealthFeedbackID int64 `json:"healthfeedback_id"`
}
