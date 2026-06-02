package routes

import (
	"net/http"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/apis"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/router"

	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/pkg/types"
)

// tenantInput is the wire shape for POST /v1/notify/tenants.
//
// The id (org slug) is the primary key + the relation key every other
// notify table points at. Name is the human-readable display string.
type tenantInput struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// mountTenants installs CRUD over the tenants namespace.
//
// Why this exists: every other collection in notify (templates,
// providers, events, messages, meter) has a `tenant` RelationField
// pointing at `tenants`. The platform plugin propagates X-Org-Id from
// the JWT owner claim, but the relation only validates if the tenants
// row already exists. POST /v1/notify/templates returns
// `validation_missing_rel_records` against a tenant slug that hasn't
// been seeded — until the operator seeds the row here.
//
// One row per IAM org. Idempotent (re-POST is a no-op upsert by id) so
// the operator's seed script can run on every reconcile without churn.
func mountTenants(r *router.Router[*core.RequestEvent], app *base.Base) {
	// List tenants visible to the caller. The org plugin filters down to
	// the X-Org-Id-scoped row; the response is a singleton list shape so
	// callers don't have to special-case it.
	r.GET("/v1/notify/tenants", func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		rec, err := app.FindRecordById(schema.Tenants, org)
		if err != nil || rec == nil {
			return e.JSON(http.StatusOK, map[string]any{"items": []types.Tenant{}})
		}
		return e.JSON(http.StatusOK, map[string]any{
			"items": []types.Tenant{toTenantDTO(rec)},
		})
	})

	// Upsert the X-Org-Id row. We deliberately ignore body.ID — the only
	// id a caller is allowed to write is the slug their JWT says they
	// own. This forecloses one-tenant-creating-another via a forged body.
	r.POST("/v1/notify/tenants", func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		var body tenantInput
		if err := e.BindBody(&body); err != nil {
			return apis.NewBadRequestError("malformed body", err)
		}
		if body.Name == "" {
			return apis.NewBadRequestError("name is required", nil)
		}

		col, err := app.FindCollectionByNameOrId(schema.Tenants)
		if err != nil {
			return apis.NewInternalServerError("collection", err)
		}

		// Upsert: try update first, fall through to create if missing.
		rec, _ := app.FindRecordById(schema.Tenants, org)
		if rec == nil {
			rec = core.NewRecord(col)
			rec.Set("id", org) // pk = slug
		}
		rec.Set("name", body.Name)
		if err := app.Save(rec); err != nil {
			return apis.NewInternalServerError("save", err)
		}
		return e.JSON(http.StatusOK, toTenantDTO(rec))
	})
}

func toTenantDTO(r *core.Record) types.Tenant {
	return types.Tenant{
		ID:      r.Id,
		Name:    r.GetString("name"),
		Created: r.GetString("created"),
		Updated: r.GetString("updated"),
	}
}
