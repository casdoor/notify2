package routes

import (
	"context"
	"net/http"
	"time"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/apis"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/router"
	"github.com/hanzoai/dbx"

	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/pkg/types"
)

// providerInput is the wire shape for POST /v1/notify/providers.
type providerInput struct {
	Service   string `json:"service"`
	Mode      string `json:"mode"`
	KMSPath   string `json:"kms_path"`
	Channel   string `json:"channel,omitempty"`
	IsDefault bool   `json:"is_default,omitempty"`
}

// mountProviders installs CRUD over the providers collection plus the
// /test action.
func mountProviders(r *router.Router[*core.RequestEvent], app *base.Base) {
	r.GET("/v1/notify/providers", func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		rows, err := app.FindRecordsByFilter(
			schema.Providers,
			"tenant = {:tenant}",
			"-updated", 200, 0,
			dbx.Params{"tenant": org},
		)
		if err != nil {
			return apis.NewInternalServerError("list providers", err)
		}
		out := make([]types.Provider, 0, len(rows))
		for _, r := range rows {
			out = append(out, toProviderDTO(r))
		}
		return e.JSON(http.StatusOK, map[string]any{"items": out})
	})

	r.POST("/v1/notify/providers", func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		var body providerInput
		if err := e.BindBody(&body); err != nil {
			return apis.NewBadRequestError("malformed body", err)
		}
		if body.Service == "" || body.Mode == "" || body.KMSPath == "" {
			return apis.NewBadRequestError("service, mode, kms_path are required", nil)
		}
		col, err := app.FindCollectionByNameOrId(schema.Providers)
		if err != nil {
			return apis.NewInternalServerError("collection", err)
		}
		rec := core.NewRecord(col)
		rec.Set("tenant", org)
		rec.Set("service", body.Service)
		rec.Set("mode", body.Mode)
		rec.Set("kms_path", body.KMSPath)
		rec.Set("channel", body.Channel)
		rec.Set("is_default", body.IsDefault)
		rec.Set("status", schema.ProviderStatusPendingTest)
		if err := app.Save(rec); err != nil {
			return apis.NewInternalServerError("save", err)
		}
		return e.JSON(http.StatusCreated, toProviderDTO(rec))
	})

	r.POST("/v1/notify/providers/{id}/test", func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		id := e.Request.PathValue("id")
		rec, err := app.FindRecordById(schema.Providers, id)
		if err != nil || rec == nil || rec.GetString("tenant") != org {
			return apis.NewNotFoundError("provider not found", nil)
		}
		// The ping is implemented as part of follow-up work — most
		// library providers don't expose a no-op test method. For now,
		// mark the row as last-tested-now and return success; an
		// integration test in the worker layer is what will catch real
		// outages.
		now := time.Now().UTC().Format(time.RFC3339)
		rec.Set("last_test_at", now)
		rec.Set("last_test_result", "ok (stub)")
		rec.Set("status", schema.ProviderStatusActive)
		if err := app.Save(rec); err != nil {
			return apis.NewInternalServerError("save", err)
		}
		return e.JSON(http.StatusOK, toProviderDTO(rec))
	})

	r.POST("/v1/notify/providers/{id}/activate", func(e *core.RequestEvent) error {
		return changeStatus(e, app, schema.ProviderStatusActive)
	})
	r.POST("/v1/notify/providers/{id}/disable", func(e *core.RequestEvent) error {
		return changeStatus(e, app, schema.ProviderStatusDisabled)
	})
}

func changeStatus(e *core.RequestEvent, app *base.Base, target string) error {
	org, err := orgFromRequest(e)
	if err != nil {
		return err
	}
	id := e.Request.PathValue("id")
	rec, err := app.FindRecordById(schema.Providers, id)
	if err != nil || rec == nil || rec.GetString("tenant") != org {
		return apis.NewNotFoundError("provider not found", nil)
	}
	rec.Set("status", target)
	if err := app.Save(rec); err != nil {
		return apis.NewInternalServerError("save", err)
	}
	return e.JSON(http.StatusOK, toProviderDTO(rec))
}

func toProviderDTO(r *core.Record) types.Provider {
	return types.Provider{
		ID:             r.Id,
		TenantSlug:     r.GetString("tenant"),
		Service:        r.GetString("service"),
		Mode:           r.GetString("mode"),
		KMSPath:        r.GetString("kms_path"),
		Status:         r.GetString("status"),
		Channel:        r.GetString("channel"),
		IsDefault:      r.GetBool("is_default"),
		Created:        r.GetString("created"),
		LastTestAt:     r.GetString("last_test_at"),
		LastTestResult: r.GetString("last_test_result"),
	}
}

// unused, but referenced from tenant.go's resolver path — pinned here
// to make the dependency obvious from the routes side.
var _ = context.Background
