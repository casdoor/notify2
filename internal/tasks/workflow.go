package tasks

import (
	"time"

	"github.com/hanzoai/tasks/pkg/sdk/workflow"
)

// SendInput is the workflow + activity input. One pair per recipient.
// MessageID is the notifyd-generated message row id the worker updates
// as the send progresses (queued → sending → sent/failed).
type SendInput struct {
	MessageID  string         `json:"message_id"`
	TenantSlug string         `json:"tenant_slug"`
	Channel    string         `json:"channel"`
	Provider   string         `json:"provider,omitempty"`
	To         string         `json:"to"`
	Subject    string         `json:"subject,omitempty"`
	Body       string         `json:"body"`
	TemplateID string         `json:"template_id,omitempty"`
	Event      string         `json:"event,omitempty"`
	Vars       map[string]any `json:"vars,omitempty"`

	// Category is one of marketing.Category* on the marketing path or
	// any transactional/regulatory tag (empty = transactional). Drives
	// the List-Unsubscribe injection branch in Activities.Deliver.
	Category string `json:"category,omitempty"`

	// UserID is the destination user's IAM id. Required for marketing-
	// class sends so the unsubscribe token signs on the right
	// principal. Ignored on the transactional path.
	UserID string `json:"user_id,omitempty"`

	// IsHTML is the body's content-type hint. True → text/html in the
	// MIME envelope; false → text/plain. Defaults to plain when the
	// caller omits it; templates that produce HTML must set it.
	IsHTML bool `json:"is_html,omitempty"`
}

// SendResult is the workflow return shape.
type SendResult struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
	Provider  string `json:"provider"`
	Error     string `json:"error,omitempty"`
}

// NotifySendWorkflow is the durable-execution entry point for async
// sends. The workflow body must be deterministic on its inputs — all
// I/O happens inside the Deliver activity.
//
// Single activity: this is intentional. A "send" is a unit of work,
// not a DAG; if a provider fails, retry the whole thing rather than
// trying to split rendering from delivery (rendering against the same
// vars yields the same body, so re-rendering on retry is free).
func NotifySendWorkflow(ctx workflow.Context, in SendInput) (SendResult, error) {
	actCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 60 * time.Second,
	})
	var res SendResult
	if err := workflow.ExecuteActivity(actCtx, "Deliver", in).Get(actCtx, &res); err != nil {
		return SendResult{
			MessageID: in.MessageID,
			Status:    "failed",
			Error:     err.Error(),
		}, err
	}
	return res, nil
}
