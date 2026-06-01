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

type eventInput struct {
	Name       string   `json:"name"`
	Channels   []string `json:"channels,omitempty"`
	TemplateID string   `json:"template_id,omitempty"`
	RateLimit  int      `json:"rate_limit,omitempty"`
	Enabled    bool     `json:"enabled"`
}

// mountEvents installs CRUD over the event catalog.
func mountEvents(r *router.Router[*core.RequestEvent], app *base.Base) {
	r.GET("/v1/notify/events", func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		rows, err := app.FindRecordsByFilter(
			schema.Events,
			"tenant = {:tenant}",
			"-updated", 200, 0,
			dbx.Params{"tenant": org},
		)
		if err != nil {
			return apis.NewInternalServerError("list events", err)
		}
		out := make([]types.Event, 0, len(rows))
		for _, r := range rows {
			out = append(out, toEventDTO(r))
		}
		return e.JSON(http.StatusOK, map[string]any{"items": out})
	})

	r.POST("/v1/notify/events", func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		var body eventInput
		if err := e.BindBody(&body); err != nil {
			return apis.NewBadRequestError("malformed body", err)
		}
		if body.Name == "" {
			return apis.NewBadRequestError("name is required", nil)
		}
		col, err := app.FindCollectionByNameOrId(schema.Events)
		if err != nil {
			return apis.NewInternalServerError("collection", err)
		}
		rec := core.NewRecord(col)
		rec.Set("tenant", org)
		rec.Set("name", body.Name)
		rec.Set("channels", body.Channels)
		rec.Set("template_id", body.TemplateID)
		rec.Set("rate_limit", body.RateLimit)
		rec.Set("enabled", body.Enabled)
		if err := app.Save(rec); err != nil {
			return apis.NewInternalServerError("save", err)
		}
		return e.JSON(http.StatusCreated, toEventDTO(rec))
	})
}

func toEventDTO(r *core.Record) types.Event {
	chans := []string{}
	if raw := r.GetStringSlice("channels"); len(raw) > 0 {
		chans = raw
	}
	return types.Event{
		ID:         r.Id,
		TenantSlug: r.GetString("tenant"),
		Name:       r.GetString("name"),
		Channels:   chans,
		TemplateID: r.GetString("template_id"),
		RateLimit:  r.GetInt("rate_limit"),
		Enabled:    r.GetBool("enabled"),
		Created:    r.GetString("created"),
		Updated:    r.GetString("updated"),
	}
}
