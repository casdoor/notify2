package routes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

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
func mountSend(r *router.Router[*core.RequestEvent], app core.App, cfg Config) {
	r.POST("/v1/notify/send", sendHandler(app, cfg, ""))
	r.POST("/v1/notify/send/sms", sendHandler(app, cfg, string(types.ChannelSMS)))
	r.POST("/v1/notify/send/email", sendHandler(app, cfg, string(types.ChannelEmail)))
	r.POST("/v1/notify/send/voice", sendHandler(app, cfg, string(types.ChannelVoice)))
	r.POST("/v1/notify/send/whatsapp", sendHandler(app, cfg, string(types.ChannelWhatsApp)))
}

// sendHandler returns a handler that processes one POST. The optional
// pinnedChannel is set on the convenience routes; the unprefixed
// /v1/notify/send leaves it empty and reads SendRequest.Channel.
//
// Mode selection:
//
//   - ?sync=true   — block on Deliver, return 200 with the terminal result.
//   - default      — enqueue via Dispatcher, return 202 with {task_id, message_id}.
//     The caller polls GET /v1/notify/messages/{id} for the outcome.
//
// There is no third mode. Async with a missing/unstarted Dispatcher
// returns 503 — silently falling back to sync would hide a production
// misconfiguration (CONTRACT.md §3: workers are mandatory).
func sendHandler(app core.App, cfg Config, pinnedChannel string) func(*core.RequestEvent) error {
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
		// Convenience fallback: when the caller supplies an event name
		// but no template_id and no event row resolved (or the event row
		// did not declare a template_id), try to load a published
		// template whose name equals the event name. This is the
		// IAM/auth-OTP path: hanzoai/iam sends `event="iam.otp_sent"`
		// + template_vars and relies on the tenant having a published
		// template named "iam.otp_sent" — without this fallback every
		// such send 400s unless the tenant also pre-registers a matching
		// events catalog row, which is needless ceremony for the 1:1
		// event→template common case.
		if body.TemplateID == "" && body.Body == "" && body.Event != "" {
			body.TemplateID = body.Event
		}
		if body.Channel == "" {
			return apis.NewBadRequestError("channel is required (either in body or in the event policy)", nil)
		}

		// Render template if requested.
		subject := body.Subject
		text := body.Body
		if body.TemplateID != "" {
			tmpl, err := template.LoadPublished(app, org, body.TemplateID, string(body.Channel))
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

		sync := e.Request.URL.Query().Get("sync") == "true"

		// Async mode is the default but it requires a healthy dispatcher.
		// Fail closed if it is missing so misconfigured pods are loud.
		if !sync {
			if cfg.Dispatcher == nil || !cfg.Dispatcher.Started() {
				return apis.NewApiError(
					http.StatusServiceUnavailable,
					"async dispatch unavailable: hanzoai/tasks worker is not connected — retry shortly or call POST /v1/notify/send?sync=true",
					nil,
				)
			}
		}

		// Idempotency: if a Message row already exists for the
		// (tenant, idempotency_key) pair, return it as-is. The schema
		// has a partial unique index that backs this.
		if body.IdempotencyKey != "" {
			if existing, err := findByIdempotency(app, org, body.IdempotencyKey); err == nil && existing != nil {
				resp := types.SendResponse{
					MessageID: existing.Id,
					TaskID:    existing.GetString("task_id"),
					Status:    existing.GetString("status"),
				}
				return writeOne(e, resp, sync)
			}
		}

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
			return writeOne(e, out[0], sync)
		}
		return writeMany(e, out, sync)
	}
}

// writeOne writes a single SendResponse with the right HTTP status code:
// 200 for sync, 202 for async (Accepted — the work is enqueued).
func writeOne(e *core.RequestEvent, resp types.SendResponse, sync bool) error {
	if sync {
		return e.JSON(http.StatusOK, resp)
	}
	return e.JSON(http.StatusAccepted, resp)
}

// writeMany mirrors writeOne for the multi-recipient case.
func writeMany(e *core.RequestEvent, out []types.SendResponse, sync bool) error {
	body := map[string]any{"items": out}
	if sync {
		return e.JSON(http.StatusOK, body)
	}
	return e.JSON(http.StatusAccepted, body)
}

// dispatchOne creates the Message row, then dispatches sync or async.
func dispatchOne(ctx context.Context, app core.App, cfg Config, org string, req types.SendRequest, to, subject, text string, sync bool) (types.SendResponse, error) {
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
		Category:   req.Category,
		UserID:     req.UserID,
		// Email defaults to text/html (matches the legacy
		// amazonses.Send + sendgrid.Send behaviour where the body is
		// treated as HTML). Non-email channels stay false so a future
		// raw-MIME branch on those channels would emit text/plain.
		IsHTML: req.Channel == types.ChannelEmail,
	}

	if sync {
		// Sync path: call the activity directly. The activity does its
		// own row updates so the Message reflects the outcome. When
		// the chain resolver is wired we build an activity that
		// prefers the per-channel chain over the single-provider
		// resolver — same code path the async worker uses.
		acts := tasks.NewActivitiesWithChain(app, cfg.Resolver, cfg.ChainResolver)
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

	// Async path: enqueue via Dispatcher. The caller already verified
	// cfg.Dispatcher is non-nil and Started, so a Dispatch error here
	// is a real failure (server unreachable, opcode rejected, …) and
	// must surface to the client rather than degrade to sync.
	taskID, err := cfg.Dispatcher.Dispatch(ctx, in)
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
func createMessage(app core.App, org string, req types.SendRequest, to, subject, body string) (*core.Record, error) {
	// The Messages collection has a RelationField → Tenants and the
	// relation will fail validation if the tenant row does not yet exist.
	// Autocreate one for first-use of an org so production callers never
	// have to POST /v1/notify/tenants before their first send. Idempotent.
	if err := ensureTenantRow(app, org); err != nil {
		return nil, fmt.Errorf("ensure tenant row: %w", err)
	}
	col, err := app.FindCollectionByNameOrId(schema.Messages)
	if err != nil {
		return nil, fmt.Errorf("find collection: %w", err)
	}
	rec := core.NewRecord(col)
	rec.Set("tenant", org)
	rec.Set("channel", string(req.Channel))
	// Provider is required by the schema (we always know who sent the
	// message in retrospect). When the caller did not pin one, we mark
	// the row "pending" until the activity resolves an actual provider
	// and overwrites the field on its first save.
	provider := req.Provider
	if provider == "" {
		provider = "pending"
	}
	rec.Set("provider", provider)
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

// ensureTenantRow upserts a `tenants` row whose primary key is the IAM
// org slug. Called from createMessage so the first send for any new org
// silently auto-provisions the relation target rather than 500'ing on
// validation_missing_rel_records. The display name defaults to the slug
// — callers can rename later via POST /v1/notify/tenants.
func ensureTenantRow(app core.App, org string) error {
	if rec, _ := app.FindRecordById(schema.Tenants, org); rec != nil {
		return nil
	}
	col, err := app.FindCollectionByNameOrId(schema.Tenants)
	if err != nil {
		return err
	}
	rec := core.NewRecord(col)
	rec.Set("id", org)
	rec.Set("name", org)
	return app.Save(rec)
}

// findByIdempotency returns the existing row for the (tenant, key) pair
// or nil if no match exists.
func findByIdempotency(app core.App, tenant, key string) (*core.Record, error) {
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
