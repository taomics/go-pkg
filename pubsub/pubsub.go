package pubsub

import (
	"encoding/json"
	"fmt"
	"time"
)

//nolint:godoclint
const (
	// HealthFeedback topics.
	Topic_CreateHealthFeedbackJob = "create-health-feedback-job"
	Topic_GenerateHealthFeedback  = "generate-health-feedback"

	// Mail topics.
	Topic_MailRequests = "mail-requests"

	// Weekly Report topics.
	Topic_DailyFeedbackJob      = "daily-feedback-job"
	Topic_WeeklyReportJob       = "weekly-report-job"
	Topic_GenerateDailyFeedback = "generate-daily-feedback"
	Topic_GenerateWeeklyReport  = "generate-weekly-report"
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

// MailType represents the type of email being sent.
type MailType string

const (
	MailTypeOnDemand  MailType = "on-demand" // Email is sent on demand, e.g., user request
	MailTypeScheduled MailType = "scheduled" // Email is scheduled to be sent at a specific time by batch job
)

// MailRequest represents a request to send an email.
type MailRequest struct {
	MailContent

	MailSettings

	ID       string   `json:"id"`        // Unique identifier for the email request, e.g., UUID
	MailType MailType `json:"mail_type"` // Type of the email, e.g., on-demand or scheduled

	To Recipient `json:"to"`

	// SendAt is the time when the email should be sent.
	// This field is required for batch requests to schedule the email sending.
	// Assumed to be RFC 3339 string format in the JSON message.
	SendAt *JSONTime `json:"send_at,omitempty"`

	// MessageID is the unique identifier for the Pub/Sub message.
	MessageID string `json:"message_id,omitempty"` // Optional, used for Pub/Sub message tracking

	// BatchID is the identifier for the batch of emails, if this email is part of a batch.
	BatchID string `json:"batch_id,omitempty"` // Optional, used for batch sending
}

func (MailRequest) message() {}

type MailContent struct {
	// MailID is an identifier for the email content.
	// This ID should be unique for each recipient.
	MailID string `json:"mail_id"`

	Subject      string                 `json:"subject"`
	Body         string                 `json:"body,omitempty"`
	HTMLBody     string                 `json:"html_body,omitempty"`
	TemplateID   string                 `json:"template_id,omitempty"`
	TemplateData map[string]interface{} `json:"template_data,omitempty"`
	Attachments  []Attachment           `json:"attachments,omitempty"`
}

type MailSettings struct {
	FromEmail    string `json:"from_email,omitempty"`     // Optional sender email address to override the default sender
	FromName     string `json:"from_name,omitempty"`      // Optional sender name to override the default sender name
	ReplyToEmail string `json:"reply_to_email,omitempty"` // Optional reply-to email address to override the default reply-to address
	ReplyToName  string `json:"reply_to_name,omitempty"`  // Optional reply-to email address to override the default reply-to address
}

type Recipient struct {
	// UserID is the unique identifier for the recipient in the application.
	UserID string `json:"user_id"`

	// Email is the email address of the user at this request.
	Email string `json:"email"`

	// DisplayName is the name of the user at this request.
	// This field might be embedded in the email template.
	DisplayName string `json:"display_name,omitempty"` // Optional name of the recipient
}

// Attachment represents an email attachment.
type Attachment struct {
	Filename string `json:"filename"`
	Content  []byte `json:"content"`
	Type     string `json:"type"`
}

type JSONTime struct {
	time.Time
}

func (t *JSONTime) UnmarshalJSON(b []byte) error {
	// Try to unmarshal as time.Time at first
	if err := json.Unmarshal(b, &t.Time); err == nil {
		return nil
	}

	// Try to unmarshal as an int64 timestamp
	var timestamp int64
	if err := json.Unmarshal(b, &timestamp); err != nil {
		return fmt.Errorf("failed to unmarshal JSONTime: %w", err)
	}

	t.Time = time.Unix(timestamp, 0)

	return nil
}
