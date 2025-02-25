package pubsub

const (
	Topic_CreateHealthFeedbackJob = "create-health-feedback-job"
	Topic_GenerateHealthFeedback  = "generate-health-feedback"
)

type HealthFeedbackEventType string

const (
	HealthFeedbackEventType_LifestyleJournalRecorded HealthFeedbackEventType = "lifestyle_journal_recorded"
	HealthFeedbackEventType_HealthModeUpdated        HealthFeedbackEventType = "health_mode_updated"
)

type Message interface {
	message()
}

// CreateHealthFeedbackJobMessage represents the message structure for create-health-feedback-job topic.
type CreateHealthFeedbackJobMessage struct {
	AccountID int64                   `json:"account_id"`
	EventType HealthFeedbackEventType `json:"event_type"`

	// LifestyleJournalID is require only when EventType is lifestyle_journal_recorded.
	LifestyleJournalID int64 `json:"lifestylejournal_id,omitempty"`

	// OverridingLifestyleJournalID is option only when EventType is lifestyle_journal_recorded.
	OverridingLifestyleJournalID int64 `json:"overriding_lifestylejournal_id,omitempty"`

	// HealthMode is require only when EventType is health_mode_updated.
	HealthMode string `json:"health_mode,omitempty"`
}

func (CreateHealthFeedbackJobMessage) message() {}

// GenerateHealthFeedbackMessage represents the message structure for generate-health-feedback topic.
type GenerateHealthFeedbackMessage struct {
	HealthFeedbackID int64 `json:"healthfeedback_id"`
}

func (GenerateHealthFeedbackMessage) message() {}
