package pubsub

type DailyFeedbackEvent string

type DailyFeedbackJobMessage struct {
	AccountID int64  `json:"account_id"`
	Date      string `json:"date"`
}

func (DailyFeedbackJobMessage) message() {}

type GenerateDailyFeedbackMessage struct {
	DailyFeedbackID int64 `json:"dailyfeedback_id"`
}

func (GenerateDailyFeedbackMessage) message() {}

type WeeklyReportEvent string

const (
	WeeklyReportEvent_ThisWeekReportNotFound WeeklyReportEvent = "this_week_report_not_found"
	WeeklyReportEvent_SundayJournalWritten   WeeklyReportEvent = "sunday_journal_written"
	WeeklyReportEvent_WeeklyWorkerRequested  WeeklyReportEvent = "weekly_worker_requested"
)

type CreateWeeklyReportJobMessage struct {
	Event     WeeklyReportEvent `json:"event"`
	AccountID int64             `json:"account_id"`

	// WeeklyReportID is required only when EventType is WeeklyReportEventType_FinalizeReportRequested.
	WeeklyReportID int64 `json:"weeklyreport_id,omitempty"`
}

func (CreateWeeklyReportJobMessage) message() {}

type GenerateWeeklyReportMessage struct {
	WeeklyReportID int64 `json:"weeklyreport_id"`
}

func (GenerateWeeklyReportMessage) message() {}
