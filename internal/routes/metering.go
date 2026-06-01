package routes

import (
	"github.com/hanzoai/base"
	"github.com/hanzoai/base/apis"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/router"

	"github.com/hanzoai/notify/internal/metering"
)

// mountMetering installs GET /v1/notify/metering.
//
// Query params:
//   from — RFC3339 lower bound (inclusive). Optional.
//   to   — RFC3339 upper bound (inclusive). Optional.
//
// The tenant scope comes from X-Org-Id; superadmin override via
// ?tenant= is intentionally not exposed on this surface — the billing
// roll-up runs out-of-cluster against the underlying SQLite directly.
func mountMetering(r *router.Router[*core.RequestEvent], app *base.Base) {
	r.GET("/v1/notify/metering", func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		q := e.Request.URL.Query()
		summary, err := metering.Aggregate(app, org, q.Get("from"), q.Get("to"), 10000)
		if err != nil {
			return apis.NewInternalServerError("aggregate", err)
		}
		return jsonOK(e, summary)
	})
}
