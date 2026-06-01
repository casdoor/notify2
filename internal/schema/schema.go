// Package schema registers Hanzo Notify's domain collections with the
// underlying hanzoai/base app.
//
// Six collections cover the v1 surface:
//
//	tenants      — IAM-org-slug namespace (one row per org)
//	providers    — per-tenant provider config (KMS path + status)
//	templates    — re-usable message bodies with approval lifecycle
//	events       — event catalog (routing + rate-limit policy)
//	messages     — persisted send records (audit + lookup)
//	meter        — per-send ledger for billing rollup
//
// Each user-data collection scopes by `tenant` (relation to `tenants`,
// whose id is the IAM org slug). Access rules deny anonymous read; the
// route layer narrows further via X-Org-Id from the platform plugin.
package schema

import (
	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/types"
)

// Collection names. Hard-coded; this is the contract between the
// schema, the routes, and the worker.
const (
	Tenants   = "tenants"
	Providers = "providers"
	Templates = "templates"
	Events    = "events"
	Messages  = "messages"
	Meter     = "meter"
)

// Message status values stored in messages.status.
const (
	MessageStatusQueued    = "queued"
	MessageStatusSending   = "sending"
	MessageStatusSent      = "sent"
	MessageStatusDelivered = "delivered"
	MessageStatusFailed    = "failed"
)

// Provider lifecycle values stored in providers.status.
const (
	ProviderStatusPendingTest = "pending_test"
	ProviderStatusActive      = "active"
	ProviderStatusDisabled    = "disabled"
)

// Template lifecycle values stored in templates.status.
const (
	TemplateStatusDraft           = "draft"
	TemplateStatusPendingApproval = "pending_approval"
	TemplateStatusApproved        = "approved"
	TemplateStatusPublished       = "published"
	TemplateStatusArchived        = "archived"
)

// MustRegister wires the notify schema migration into the app.
// Idempotent: subsequent boots find the collections already present
// and skip creation. Panics on registration errors so boot fails loudly.
func MustRegister(_ *base.Base) {
	core.AppMigrations.Register(up, down, "notify_init.go")
}

func up(app core.App) error {
	for _, step := range []func(core.App) error{
		ensureTenants,
		ensureProviders,
		ensureTemplates,
		ensureEvents,
		ensureMessages,
		ensureMeter,
	} {
		if err := step(app); err != nil {
			return err
		}
	}
	return nil
}

func down(app core.App) error {
	for _, name := range []string{Meter, Messages, Events, Templates, Providers, Tenants} {
		c, err := app.FindCollectionByNameOrId(name)
		if err != nil {
			continue
		}
		if err := app.Delete(c); err != nil {
			return err
		}
	}
	return nil
}

func ensureTenants(app core.App) error {
	if existing, _ := app.FindCollectionByNameOrId(Tenants); existing != nil {
		return nil
	}
	c := core.NewBaseCollection(Tenants)
	// Tenant IDs are IAM org slugs (e.g. "hanzo", "liquidity") — the
	// default base 15-char min doesn't fit. Override the system id field.
	c.Fields.Add(&core.TextField{
		Name:       "id",
		System:     true,
		PrimaryKey: true,
		Required:   true,
		Min:        2,
		Max:        64,
		Pattern:    `^[a-z0-9][a-z0-9\-]*$`,
	})
	c.Fields.Add(&core.TextField{Name: "name", Required: true, Max: 200})
	c.Fields.Add(&core.AutodateField{Name: "created", OnCreate: true})
	c.Fields.Add(&core.AutodateField{Name: "updated", OnCreate: true, OnUpdate: true})
	c.ListRule = types.Pointer("@request.auth.id != ''")
	c.ViewRule = types.Pointer("@request.auth.id != ''")
	return app.Save(c)
}

func ensureProviders(app core.App) error {
	if existing, _ := app.FindCollectionByNameOrId(Providers); existing != nil {
		return nil
	}
	tenants, err := app.FindCollectionByNameOrId(Tenants)
	if err != nil {
		return err
	}
	c := core.NewBaseCollection(Providers)
	c.Fields.Add(&core.RelationField{
		Name: "tenant", Required: true, CollectionId: tenants.Id, MaxSelect: 1, CascadeDelete: true,
	})
	c.Fields.Add(&core.TextField{Name: "service", Required: true, Max: 50})
	c.Fields.Add(&core.SelectField{
		Name: "mode", Required: true, MaxSelect: 1,
		Values: []string{"shared", "byo"},
	})
	c.Fields.Add(&core.TextField{Name: "kms_path", Required: true, Max: 500})
	c.Fields.Add(&core.SelectField{
		Name: "status", Required: true, MaxSelect: 1,
		Values: []string{ProviderStatusPendingTest, ProviderStatusActive, ProviderStatusDisabled},
	})
	c.Fields.Add(&core.SelectField{
		Name: "channel", MaxSelect: 1,
		Values: []string{"sms", "email", "voice", "whatsapp", "push", "chat"},
	})
	c.Fields.Add(&core.BoolField{Name: "is_default"})
	c.Fields.Add(&core.DateField{Name: "last_test_at"})
	c.Fields.Add(&core.TextField{Name: "last_test_result", Max: 500})
	c.Fields.Add(&core.AutodateField{Name: "created", OnCreate: true})
	c.Fields.Add(&core.AutodateField{Name: "updated", OnCreate: true, OnUpdate: true})
	c.AddIndex("idx_providers_tenant", false, "tenant", "")
	c.AddIndex("idx_providers_tenant_service", true, "tenant,service,channel", "")
	return app.Save(c)
}

func ensureTemplates(app core.App) error {
	if existing, _ := app.FindCollectionByNameOrId(Templates); existing != nil {
		return nil
	}
	tenants, err := app.FindCollectionByNameOrId(Tenants)
	if err != nil {
		return err
	}
	c := core.NewBaseCollection(Templates)
	c.Fields.Add(&core.RelationField{
		Name: "tenant", Required: true, CollectionId: tenants.Id, MaxSelect: 1, CascadeDelete: true,
	})
	c.Fields.Add(&core.TextField{Name: "name", Required: true, Max: 200})
	c.Fields.Add(&core.SelectField{
		Name: "channel", Required: true, MaxSelect: 1,
		Values: []string{"sms", "email", "voice", "whatsapp", "push", "chat"},
	})
	c.Fields.Add(&core.TextField{Name: "subject", Max: 500})
	c.Fields.Add(&core.TextField{Name: "body", Required: true, Max: 10000})
	c.Fields.Add(&core.JSONField{Name: "vars", MaxSize: 1 << 16})
	c.Fields.Add(&core.SelectField{
		Name: "status", Required: true, MaxSelect: 1,
		Values: []string{
			TemplateStatusDraft,
			TemplateStatusPendingApproval,
			TemplateStatusApproved,
			TemplateStatusPublished,
			TemplateStatusArchived,
		},
	})
	c.Fields.Add(&core.NumberField{Name: "version", Required: true, OnlyInt: true})
	c.Fields.Add(&core.TextField{Name: "approved_by", Max: 200})
	c.Fields.Add(&core.AutodateField{Name: "created", OnCreate: true})
	c.Fields.Add(&core.AutodateField{Name: "updated", OnCreate: true, OnUpdate: true})
	c.AddIndex("idx_templates_tenant", false, "tenant", "")
	c.AddIndex("idx_templates_tenant_name_version", true, "tenant,name,version", "")
	return app.Save(c)
}

func ensureEvents(app core.App) error {
	if existing, _ := app.FindCollectionByNameOrId(Events); existing != nil {
		return nil
	}
	tenants, err := app.FindCollectionByNameOrId(Tenants)
	if err != nil {
		return err
	}
	c := core.NewBaseCollection(Events)
	c.Fields.Add(&core.RelationField{
		Name: "tenant", Required: true, CollectionId: tenants.Id, MaxSelect: 1, CascadeDelete: true,
	})
	c.Fields.Add(&core.TextField{Name: "name", Required: true, Max: 200})
	c.Fields.Add(&core.JSONField{Name: "channels", MaxSize: 1 << 16})
	c.Fields.Add(&core.TextField{Name: "template_id", Max: 200})
	c.Fields.Add(&core.NumberField{Name: "rate_limit", OnlyInt: true})
	c.Fields.Add(&core.BoolField{Name: "enabled"})
	c.Fields.Add(&core.AutodateField{Name: "created", OnCreate: true})
	c.Fields.Add(&core.AutodateField{Name: "updated", OnCreate: true, OnUpdate: true})
	c.AddIndex("idx_events_tenant", false, "tenant", "")
	c.AddIndex("idx_events_tenant_name", true, "tenant,name", "")
	return app.Save(c)
}

func ensureMessages(app core.App) error {
	if existing, _ := app.FindCollectionByNameOrId(Messages); existing != nil {
		return nil
	}
	tenants, err := app.FindCollectionByNameOrId(Tenants)
	if err != nil {
		return err
	}
	c := core.NewBaseCollection(Messages)
	c.Fields.Add(&core.RelationField{
		Name: "tenant", Required: true, CollectionId: tenants.Id, MaxSelect: 1, CascadeDelete: true,
	})
	c.Fields.Add(&core.SelectField{
		Name: "channel", Required: true, MaxSelect: 1,
		Values: []string{"sms", "email", "voice", "whatsapp", "push", "chat"},
	})
	c.Fields.Add(&core.TextField{Name: "provider", Required: true, Max: 50})
	c.Fields.Add(&core.TextField{Name: "to", Required: true, Max: 500})
	c.Fields.Add(&core.TextField{Name: "subject", Max: 500})
	c.Fields.Add(&core.TextField{Name: "body", Max: 20000})
	c.Fields.Add(&core.TextField{Name: "template_id", Max: 200})
	c.Fields.Add(&core.TextField{Name: "event", Max: 200})
	c.Fields.Add(&core.SelectField{
		Name: "status", Required: true, MaxSelect: 1,
		Values: []string{
			MessageStatusQueued,
			MessageStatusSending,
			MessageStatusSent,
			MessageStatusDelivered,
			MessageStatusFailed,
		},
	})
	c.Fields.Add(&core.TextField{Name: "error", Max: 5000})
	c.Fields.Add(&core.TextField{Name: "idempotency_key", Max: 200})
	c.Fields.Add(&core.TextField{Name: "task_id", Max: 200})
	c.Fields.Add(&core.DateField{Name: "sent"})
	c.Fields.Add(&core.DateField{Name: "delivered"})
	c.Fields.Add(&core.JSONField{Name: "metadata", MaxSize: 1 << 16})
	c.Fields.Add(&core.AutodateField{Name: "created", OnCreate: true})
	c.Fields.Add(&core.AutodateField{Name: "updated", OnCreate: true, OnUpdate: true})
	c.AddIndex("idx_messages_tenant", false, "tenant", "")
	c.AddIndex("idx_messages_tenant_status", false, "tenant,status", "")
	c.AddIndex("idx_messages_tenant_idempotency", true, "tenant,idempotency_key", "idempotency_key != ''")
	return app.Save(c)
}

func ensureMeter(app core.App) error {
	if existing, _ := app.FindCollectionByNameOrId(Meter); existing != nil {
		return nil
	}
	tenants, err := app.FindCollectionByNameOrId(Tenants)
	if err != nil {
		return err
	}
	c := core.NewBaseCollection(Meter)
	c.Fields.Add(&core.RelationField{
		Name: "tenant", Required: true, CollectionId: tenants.Id, MaxSelect: 1, CascadeDelete: true,
	})
	c.Fields.Add(&core.TextField{Name: "event", Max: 200})
	c.Fields.Add(&core.TextField{Name: "provider", Required: true, Max: 50})
	c.Fields.Add(&core.SelectField{
		Name: "channel", Required: true, MaxSelect: 1,
		Values: []string{"sms", "email", "voice", "whatsapp", "push", "chat"},
	})
	c.Fields.Add(&core.NumberField{Name: "units", Required: true, OnlyInt: true})
	c.Fields.Add(&core.NumberField{Name: "vendor_cost_micros", Required: true, OnlyInt: true})
	c.Fields.Add(&core.NumberField{Name: "retail_price_micros", Required: true, OnlyInt: true})
	c.Fields.Add(&core.TextField{Name: "message_id", Max: 200})
	c.Fields.Add(&core.AutodateField{Name: "sent_at", OnCreate: true})
	c.AddIndex("idx_meter_tenant_sent", false, "tenant,sent_at", "")
	c.AddIndex("idx_meter_tenant_provider_channel", false, "tenant,provider,channel", "")
	return app.Save(c)
}
