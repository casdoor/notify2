package routes

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/apis"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/router"
	"github.com/hanzoai/dbx"

	"github.com/hanzoai/notify/internal/event"
	"github.com/hanzoai/notify/internal/metering"
	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/internal/tasks"
	"github.com/hanzoai/notify/internal/template"
	"github.com/hanzoai/notify/pkg/types"
)

// mountSend wires /v1/notify/send (and per-channel convenience paths).
// The same Send handler powers all four: the path-only difference is
// the implied channel.
func mountSend(r *router.Router[*core.RequestEvent], app *base.Base, cfg Config) {
	r.POST("/v1/notify/send", sendHandler(app, cfg, ""))
	r.POST("/v1/notify/send/sms", sendHandler(app, cfg, string(types.ChannelSMS)))
	r.POST("/v1/notify/send/email", sendHandler(app, cfg, string(types.ChannelEmail)))
	r.POST("/v1/notify/send/voice", sendHandler(app, cfg, string(types.ChannelVoice)))
	r.POST("/v1/notify/send/whatsapp", sendHandler(app, cfg, string(types.ChannelWhatsApp)))
}

// sendHandler returns a handler that processes one POST. The optional
// pinnedChannel is set on the convenience routes; the unprefixed
// /v1/notify/send leaves it empty and reads SendRequest.Channel.
func sendHandler(app *base.Base, cfg Config, pinnedChannel string) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}

		var body types.SendRequest
		if err := e.BindBody(&body); err != nil {
			return apis.NewBadRequestError("malformed request body", err)
		}
		if pinnedChannel != "" {
			body.Channel = types.Channel(pinnedChannel)
		}
		if err := validateSendRequest(&body); err != nil {
			return apis.NewBadRequestError(err.Error(), nil)
		}

		// Resolve event policy (optional). When set, it can fill in
		// missing channel + template_id from the catalog.
		ev, err := event.Resolve(app, org, body.Event)
		if err != nil {
			return apis.NewInternalServerError("event resolve", err)
		}
		if ev != nil {
			if body.Channel == "" {
				body.Channel = types.Channel(firstChannel(ev.GetStringSlice("channels")))
			}
			if body.TemplateID == "" {
				body.TemplateID = ev.GetString("template_id")
			}
		}
		if body.Channel == "" {
			return apis.NewBadRequestError("channel is required (either in body or in the event policy)", nil)
		}

		// Render template if requested.
		subject := body.Subject
		text := body.Body
		if body.TemplateID != "" {
			tmpl, err := template.LoadPublished(app, org, body.TemplateID)
			if err != nil {
				return apis.NewBadRequestError(err.Error(), nil)
			}
			resolved, err := template.Render(tmpl, body.TemplateVars)
			if err != nil {
				return apis.NewBadRequestError(err.Error(), nil)
			}
			subject = resolved.Subject
			text = resolved.Body
			if body.Channel == "" {
				body.Channel = types.Channel(resolved.Channel)
			}
		}
		if text == "" {
			return apis.NewBadRequestError("body or template_id is required", nil)
		}

		// Idempotency: if a Message row already exists for the
		// (tenant, idempotency_key) pair, return it as-is. The schema
		// has a partial unique index that backs this.
		if body.IdempotencyKey != "" {
			if existing, err := findByIdempotency(app, org, body.IdempotencyKey); err == nil && existing != nil {
				return jsonOK(e, types.SendResponse{
					MessageID: existing.Id,
					TaskID:    existing.GetString("task_id"),
					Status:    existing.GetString("status"),
				})
			}
		}

		sync := e.Request.URL.Query().Get("sync") == "true"

		// One Message row per recipient — fan out.
		ctx := e.Request.Context()
		out := make([]types.SendResponse, 0, len(body.To))
		for _, to := range body.To {
			resp, err := dispatchOne(ctx, app, cfg, org, body, to, subject, text, sync)
			if err != nil {
				return apis.NewInternalServerError("dispatch", err)
			}
			out = append(out, resp)
		}

		// Single-recipient sends return a flat object; multi-recipient
		// returns an array. This keeps the simple case simple.
		if len(out) == 1 {
			return jsonOK(e, out[0])
		}
		return jsonOK(e, map[string]any{"items": out})
	}
}

// dispatchOne creates the Message row, then dispatches sync or async.
func dispatchOne(ctx context.Context, app *base.Base, cfg Config, org string, req types.SendRequest, to, subject, text string, sync bool) (types.SendResponse, error) {
	rec, err := createMessage(app, org, req, to, subject, text)
	if err != nil {
		return types.SendResponse{}, fmt.Errorf("create message: %w", err)
	}

	in := tasks.SendInput{
		MessageID:  rec.Id,
		TenantSlug: org,
		Channel:    string(req.Channel),
		Provider:   req.Provider,
		To:         to,
		Subject:    subject,
		Body:       text,
		TemplateID: req.TemplateID,
		Event:      req.Event,
		Vars:       req.TemplateVars,
	}

	if sync || cfg.Worker == nil || !cfg.Worker.Started() {
		// Sync path: call the activity directly. The activity does its
		// own row updates so the Message reflects the outcome.
		acts := tasks.NewActivities(app, cfg.Resolver)
		result, err := acts.Deliver(ctx, in)
		if err != nil {
			return types.SendResponse{
				MessageID: rec.Id,
				Status:    schema.MessageStatusFailed,
				Error:     err.Error(),
			}, nil
		}
		return types.SendResponse{
			MessageID: rec.Id,
			Status:    result.Status,
			Error:     result.Error,
		}, nil
	}

	// Async path: enqueue via tasks.
	taskID, err := cfg.Worker.Dispatch(ctx, in)
	if err != nil {
		return types.SendResponse{}, fmt.Errorf("dispatch: %w", err)
	}
	rec.Set("task_id", taskID)
	if err := app.Save(rec); err != nil {
		return types.SendResponse{}, fmt.Errorf("save task_id: %w", err)
	}
	return types.SendResponse{
		MessageID: rec.Id,
		TaskID:    taskID,
		Status:    schema.MessageStatusQueued,
	}, nil
}

// createMessage materializes the Message row. The route fan-out path
// calls this once per recipient.
func createMessage(app *base.Base, org string, req types.SendRequest, to, subject, body string) (*core.Record, error) {
	col, err := app.FindCollectionByNameOrId(schema.Messages)
	if err != nil {
		return nil, fmt.Errorf("find collection: %w", err)
	}
	rec := core.NewRecord(col)
	rec.Set("tenant", org)
	rec.Set("channel", string(req.Channel))
	// Provider may be empty here — the activity fills it in once the
	// resolver picks one.
	rec.Set("provider", req.Provider)
	rec.Set("to", to)
	rec.Set("subject", subject)
	rec.Set("body", body)
	rec.Set("template_id", req.TemplateID)
	rec.Set("event", req.Event)
	rec.Set("status", schema.MessageStatusQueued)
	rec.Set("idempotency_key", req.IdempotencyKey)
	if err := app.Save(rec); err != nil {
		return nil, fmt.Errorf("save: %w", err)
	}
	return rec, nil
}

// findByIdempotency returns the existing row for the (tenant, key) pair
// or nil if no match exists.
func findByIdempotency(app *base.Base, tenant, key string) (*core.Record, error) {
	if key == "" {
		return nil, nil
	}
	rows, err := app.FindRecordsByFilter(
		schema.Messages,
		"tenant = {:tenant} && idempotency_key = {:key}",
		"-created", 1, 0,
		dbx.Params{"tenant": tenant, "key": key},
	)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0], nil
}

// validateSendRequest is a syntactic gate. Semantic checks (provider
// exists, template published, …) happen downstream and report through
// the message row's status/error.
func validateSendRequest(r *types.SendRequest) error {
	if len(r.To) == 0 {
		return errors.New("to is required")
	}
	if r.SendAt != "" {
		if _, err := time.Parse(time.RFC3339, r.SendAt); err != nil {
			return fmt.Errorf("send_at must be RFC3339: %w", err)
		}
	}
	return nil
}

// firstChannel returns the first non-empty entry in xs, or "".
func firstChannel(xs []string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

// _ keeps metering imported even when only the activity calls it; this
// makes the dependency obvious to readers of routes/.
var _ = metering.Aggregate
