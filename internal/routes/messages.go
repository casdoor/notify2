package routes

import (
	"net/http"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/apis"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/router"
	"github.com/hanzoai/dbx"

	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/pkg/types"
)

// mountMessages installs GET /v1/notify/messages/{id} (single lookup)
// and GET /v1/notify/messages (paginated list).
func mountMessages(r *router.Router[*core.RequestEvent], app *base.Base) {
	r.GET("/v1/notify/messages/{id}", func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		id := e.Request.PathValue("id")
		rec, err := app.FindRecordById(schema.Messages, id)
		if err != nil || rec == nil {
			return apis.NewNotFoundError("message not found", nil)
		}
		if rec.GetString("tenant") != org {
			return apis.NewNotFoundError("message not found", nil) // hide cross-tenant existence
		}
		return jsonOK(e, toMessageDTO(rec))
	})

	r.GET("/v1/notify/messages", func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		records, err := app.FindRecordsByFilter(
			schema.Messages,
			"tenant = {:tenant}",
			"-created", 100, 0,
			dbx.Params{"tenant": org},
		)
		if err != nil {
			return apis.NewInternalServerError("list messages", err)
		}
		out := make([]types.Message, 0, len(records))
		for _, r := range records {
			out = append(out, toMessageDTO(r))
		}
		return e.JSON(http.StatusOK, map[string]any{"items": out})
	})
}

// toMessageDTO collapses a base record into the public types.Message
// wire shape.
func toMessageDTO(r *core.Record) types.Message {
	return types.Message{
		ID:             r.Id,
		TenantSlug:     r.GetString("tenant"),
		Channel:        types.Channel(r.GetString("channel")),
		Provider:       r.GetString("provider"),
		To:             r.GetString("to"),
		Subject:        r.GetString("subject"),
		Body:           r.GetString("body"),
		TemplateID:     r.GetString("template_id"),
		Event:          r.GetString("event"),
		Status:         r.GetString("status"),
		Error:          r.GetString("error"),
		IdempotencyKey: r.GetString("idempotency_key"),
		TaskID:         r.GetString("task_id"),
		Created:        r.GetString("created"),
		Updated:        r.GetString("updated"),
		Sent:           r.GetString("sent"),
		Delivered:      r.GetString("delivered"),
	}
}
