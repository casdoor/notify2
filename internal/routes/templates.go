package routes

import (
	"net/http"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/apis"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/router"
	"github.com/hanzoai/dbx"

	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/internal/template"
	"github.com/hanzoai/notify/pkg/types"
)

type templateInput struct {
	Name    string   `json:"name"`
	Channel string   `json:"channel"`
	Subject string   `json:"subject,omitempty"`
	Body    string   `json:"body"`
	Vars    []string `json:"vars,omitempty"`
}

// mountTemplates installs the template CRUD + lifecycle routes.
func mountTemplates(r *router.Router[*core.RequestEvent], app *base.Base) {
	r.GET("/v1/notify/templates", func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		rows, err := app.FindRecordsByFilter(
			schema.Templates,
			"tenant = {:tenant}",
			"-updated", 200, 0,
			dbx.Params{"tenant": org},
		)
		if err != nil {
			return apis.NewInternalServerError("list templates", err)
		}
		out := make([]types.Template, 0, len(rows))
		for _, r := range rows {
			out = append(out, toTemplateDTO(r))
		}
		return e.JSON(http.StatusOK, map[string]any{"items": out})
	})

	r.POST("/v1/notify/templates", func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		var body templateInput
		if err := e.BindBody(&body); err != nil {
			return apis.NewBadRequestError("malformed body", err)
		}
		if body.Name == "" || body.Body == "" || body.Channel == "" {
			return apis.NewBadRequestError("name, channel, body are required", nil)
		}
		col, err := app.FindCollectionByNameOrId(schema.Templates)
		if err != nil {
			return apis.NewInternalServerError("collection", err)
		}
		rec := core.NewRecord(col)
		rec.Set("tenant", org)
		rec.Set("name", body.Name)
		rec.Set("channel", body.Channel)
		rec.Set("subject", body.Subject)
		rec.Set("body", body.Body)
		rec.Set("vars", body.Vars)
		rec.Set("status", schema.TemplateStatusDraft)
		rec.Set("version", nextVersion(app, org, body.Name))
		if err := app.Save(rec); err != nil {
			return apis.NewInternalServerError("save", err)
		}
		return e.JSON(http.StatusCreated, toTemplateDTO(rec))
	})

	r.POST("/v1/notify/templates/{id}/submit", lifecycleHandler(app, schema.TemplateStatusPendingApproval, ""))
	r.POST("/v1/notify/templates/{id}/approve", lifecycleHandler(app, schema.TemplateStatusApproved, "notify-approver"))
	r.POST("/v1/notify/templates/{id}/publish", lifecycleHandler(app, schema.TemplateStatusPublished, "notify-approver"))
	r.POST("/v1/notify/templates/{id}/archive", lifecycleHandler(app, schema.TemplateStatusArchived, ""))
}

// lifecycleHandler returns a handler that transitions one template to
// `target`. Optional requiredRole gates approval / publish on the
// X-Roles claim from the platform plugin.
func lifecycleHandler(app *base.Base, target, requiredRole string) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		org, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		if requiredRole != "" {
			if !hasRole(e, requiredRole) {
				return apis.NewForbiddenError("role "+requiredRole+" required", nil)
			}
		}
		id := e.Request.PathValue("id")
		rec, err := app.FindRecordById(schema.Templates, id)
		if err != nil || rec == nil || rec.GetString("tenant") != org {
			return apis.NewNotFoundError("template not found", nil)
		}
		if err := template.Transition(app, rec, target); err != nil {
			return apis.NewBadRequestError(err.Error(), nil)
		}
		if target == schema.TemplateStatusApproved && requiredRole != "" {
			rec.Set("approved_by", e.Request.Header.Get("X-User-Id"))
			_ = app.Save(rec)
		}
		return e.JSON(http.StatusOK, toTemplateDTO(rec))
	}
}

// hasRole reads X-Roles (set by the platform plugin) and returns true
// if `want` appears in the comma-separated list.
func hasRole(e *core.RequestEvent, want string) bool {
	roles := e.Request.Header.Get("X-Roles")
	if roles == "" {
		return false
	}
	// Tiny linear scan; X-Roles is rarely more than a handful of entries.
	for _, role := range splitCSV(roles) {
		if role == want {
			return true
		}
	}
	return false
}

func splitCSV(s string) []string {
	out := []string{}
	start := 0
	for i, c := range s {
		if c == ',' {
			out = append(out, trimSpace(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, trimSpace(s[start:]))
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func nextVersion(app *base.Base, tenant, name string) int {
	rows, err := app.FindRecordsByFilter(
		schema.Templates,
		"tenant = {:tenant} && name = {:name}",
		"-version", 1, 0,
		dbx.Params{"tenant": tenant, "name": name},
	)
	if err != nil || len(rows) == 0 {
		return 1
	}
	return rows[0].GetInt("version") + 1
}

func toTemplateDTO(r *core.Record) types.Template {
	vars := []string{}
	if raw := r.GetStringSlice("vars"); len(raw) > 0 {
		vars = raw
	}
	return types.Template{
		ID:         r.Id,
		TenantSlug: r.GetString("tenant"),
		Name:       r.GetString("name"),
		Channel:    types.Channel(r.GetString("channel")),
		Subject:    r.GetString("subject"),
		Body:       r.GetString("body"),
		Vars:       vars,
		Status:     r.GetString("status"),
		Version:    r.GetInt("version"),
		Created:    r.GetString("created"),
		Updated:    r.GetString("updated"),
		ApprovedBy: r.GetString("approved_by"),
	}
}
