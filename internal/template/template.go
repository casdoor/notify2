// Package template renders Notify templates and manages the lifecycle.
//
// Lifecycle: draft → pending_approval → approved → published → archived.
// Only `published` templates can be invoked from a SendRequest. The
// approval transition (pending_approval → approved) requires a privileged
// caller (X-Roles claim contains "notify-approver").
//
// Rendering uses Go's text/template with a small custom function map.
// The library is text/template (not html/template) because notify
// payloads include SMS and voice scripts that have no HTML semantics;
// callers sending email templates with HTML are responsible for
// escaping their inputs.
package template

import (
	"bytes"
	"errors"
	"fmt"
	texttemplate "text/template"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/dbx"

	"github.com/hanzoai/notify/internal/schema"
)

// Resolved is the result of rendering a published Template against a
// caller-supplied variable map.
type Resolved struct {
	Subject string
	Body    string
	Channel string
}

// LoadPublished fetches the latest published version of (tenant, name).
// Returns a "not found" error when no row matches; the routes layer
// maps that to HTTP 404.
func LoadPublished(app core.App, tenant, idOrName string) (*core.Record, error) {
	if tenant == "" || idOrName == "" {
		return nil, errors.New("template: tenant and id are required")
	}
	// Try lookup by row id first (id is short ulid-like in base); fall
	// back to (tenant,name,status=published) for human-readable refs.
	if rec, _ := app.FindRecordById(schema.Templates, idOrName); rec != nil &&
		rec.GetString("tenant") == tenant &&
		rec.GetString("status") == schema.TemplateStatusPublished {
		return rec, nil
	}
	rows, err := app.FindRecordsByFilter(
		schema.Templates,
		"tenant = {:tenant} && name = {:name} && status = {:status}",
		"-version",
		1, 0,
		dbx.Params{
			"tenant": tenant,
			"name":   idOrName,
			"status": schema.TemplateStatusPublished,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("template: lookup: %w", err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("template: no published template %q for tenant %s", idOrName, tenant)
	}
	return rows[0], nil
}

// Render renders the template's subject + body against vars.
func Render(rec *core.Record, vars map[string]any) (*Resolved, error) {
	subject, err := renderText("subject", rec.GetString("subject"), vars)
	if err != nil {
		return nil, fmt.Errorf("template: render subject: %w", err)
	}
	body, err := renderText("body", rec.GetString("body"), vars)
	if err != nil {
		return nil, fmt.Errorf("template: render body: %w", err)
	}
	return &Resolved{
		Subject: subject,
		Body:    body,
		Channel: rec.GetString("channel"),
	}, nil
}

// renderText is the inner Go-template call. Errors surface to the
// route handler as 400 — a template that won't parse is a tenant
// authoring bug, not a server bug.
func renderText(name, src string, vars map[string]any) (string, error) {
	if src == "" {
		return "", nil
	}
	t, err := texttemplate.New(name).
		Option("missingkey=zero").
		Parse(src)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, vars); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Transition moves a template from one lifecycle state to another.
// Returns an error if the transition is not allowed. Callers must check
// authorization separately — this function does not consult X-Roles.
func Transition(app *base.Base, rec *core.Record, next string) error {
	cur := rec.GetString("status")
	if !validTransition(cur, next) {
		return fmt.Errorf("template: invalid transition %s → %s", cur, next)
	}
	rec.Set("status", next)
	if err := app.Save(rec); err != nil {
		return fmt.Errorf("template: save: %w", err)
	}
	return nil
}

// validTransition encodes the legal state machine. Each row is from →
// allowed-to slice. Closed-world: anything not listed is forbidden.
func validTransition(from, to string) bool {
	allowed := map[string][]string{
		schema.TemplateStatusDraft:           {schema.TemplateStatusPendingApproval, schema.TemplateStatusArchived},
		schema.TemplateStatusPendingApproval: {schema.TemplateStatusApproved, schema.TemplateStatusDraft, schema.TemplateStatusArchived},
		schema.TemplateStatusApproved:        {schema.TemplateStatusPublished, schema.TemplateStatusArchived, schema.TemplateStatusDraft},
		schema.TemplateStatusPublished:       {schema.TemplateStatusArchived},
		schema.TemplateStatusArchived:        {schema.TemplateStatusDraft},
	}
	for _, ok := range allowed[from] {
		if ok == to {
			return true
		}
	}
	return false
}
