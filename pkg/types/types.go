// Package types is the public wire contract for the Hanzo Notify service.
//
// Both the HTTP routes (internal/routes) and the consumer SDK (pkg/client)
// share these structs so a request body in Go is bit-for-bit the JSON the
// HTTP layer accepts. Nothing else lives here — provider impls live in the
// notify library at the module root; orchestration lives in internal/.
package types

// Channel is one of the canonical delivery channels notifyd supports.
// The set is intentionally small; per-provider customization (e.g. SMS
// short code vs. long code) goes in Options rather than expanding this.
type Channel string

const (
	ChannelSMS      Channel = "sms"
	ChannelEmail    Channel = "email"
	ChannelVoice    Channel = "voice"
	ChannelWhatsApp Channel = "whatsapp"
	ChannelPush     Channel = "push"
	ChannelChat     Channel = "chat" // Slack/Discord/Teams/etc.
)

// SendRequest is the canonical wire shape for POST /v1/notify/send.
//
// At least one of TemplateID + TemplateVars OR Subject+Body must be set.
// When TemplateID is provided the service renders the template against
// TemplateVars before handing off to the provider; when omitted the raw
// Subject/Body are sent through verbatim.
type SendRequest struct {
	// To is the destination address(es). Phone number for SMS/voice/
	// WhatsApp, email for email, device token for push, channel
	// identifier for chat. Multiple recipients fan out into multiple
	// provider calls — one Message row per recipient.
	To []string `json:"to"`

	// Channel selects the delivery channel; the routes layer also exposes
	// per-channel convenience endpoints (/v1/notify/send/sms, etc.) that
	// set this implicitly.
	Channel Channel `json:"channel"`

	// Provider, if set, pins a specific provider service name (e.g.
	// "plivo", "twilio", "sendgrid"). When omitted the service picks the
	// tenant's default for the channel.
	Provider string `json:"provider,omitempty"`

	// Subject + Body are the raw payload when TemplateID is unset.
	Subject string `json:"subject,omitempty"`
	Body    string `json:"body,omitempty"`

	// TemplateID + TemplateVars trigger template rendering. The template
	// must be published and approved for the caller's tenant.
	TemplateID   string         `json:"template_id,omitempty"`
	TemplateVars map[string]any `json:"template_vars,omitempty"`

	// Event is the optional event-catalog identifier. Setting it both
	// tags the resulting Message row and lets the catalog policy apply
	// rate limits and routing overrides.
	Event string `json:"event,omitempty"`

	// Category tags the send with one of the §3.2 marketing buckets
	// (promotional, newsletter, product_update, partner_offer,
	// research) or any transactional/regulatory string. Marketing-class
	// categories trigger List-Unsubscribe header injection and the
	// SES SendRawEmail send path. Empty == treat as transactional.
	//
	// Sender ID is also derived from this field: marketing email goes
	// out via SES + ListUnsubscribe headers per RFC 8058; everything
	// else uses the plain SendEmail path.
	Category string `json:"category,omitempty"`

	// UserID identifies the destination user in IAM. Required when
	// Category names a marketing bucket so the unsubscribe token can
	// be signed for the right principal. Transactional sends accept
	// an empty UserID — they have no unsubscribe link.
	UserID string `json:"user_id,omitempty"`

	// IdempotencyKey scopes deduplication per tenant. Two requests with
	// the same (tenant, idempotency_key) return the same task_id and
	// produce a single Message row.
	IdempotencyKey string `json:"idempotency_key,omitempty"`

	// SendAt, if non-zero, schedules the send via hanzoai/tasks. RFC3339
	// string on the wire.
	SendAt string `json:"send_at,omitempty"`

	// Options is the free-form per-provider knob bag. Each provider
	// reads its own subkey (e.g. options["plivo"]["short_code"]).
	Options map[string]any `json:"options,omitempty"`
}

// SendResponse is the canonical wire shape returned by POST /v1/notify/send
// regardless of sync vs. async mode. In async mode TaskID is the
// hanzoai/tasks workflow id and Status starts at "queued"; in sync mode
// TaskID is empty and Status is the terminal result.
type SendResponse struct {
	// MessageID is the notifyd-generated id used to look up the Message
	// row via GET /v1/notify/messages/{id}.
	MessageID string `json:"message_id"`

	// TaskID is the hanzoai/tasks workflow id when async; empty in sync.
	TaskID string `json:"task_id,omitempty"`

	// Status is one of: queued, sending, sent, delivered, failed.
	Status string `json:"status"`

	// Error is set on terminal failure (sync mode only).
	Error string `json:"error,omitempty"`
}

// Message is the persisted record for one send. Every Send() through the
// library — sync or async, success or failure — writes exactly one
// Message row per recipient.
type Message struct {
	ID             string         `json:"id"`
	TenantSlug     string         `json:"tenant_slug"`
	Channel        Channel        `json:"channel"`
	Provider       string         `json:"provider"`
	To             string         `json:"to"`
	Subject        string         `json:"subject,omitempty"`
	Body           string         `json:"body,omitempty"`
	TemplateID     string         `json:"template_id,omitempty"`
	Event          string         `json:"event,omitempty"`
	Status         string         `json:"status"`
	Error          string         `json:"error,omitempty"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
	TaskID         string         `json:"task_id,omitempty"`
	Created        string         `json:"created"`
	Updated        string         `json:"updated"`
	Sent           string         `json:"sent,omitempty"`
	Delivered      string         `json:"delivered,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// Provider is the persisted per-tenant provider configuration. The actual
// credentials live in KMS at Provider.KMSPath; the row only references
// them. Mode selects between Hanzo's shared subaccount and a tenant BYO.
type Provider struct {
	ID             string `json:"id"`
	TenantSlug     string `json:"tenant_slug"`
	Service        string `json:"service"` // "plivo", "twilio", "sendgrid", …
	Mode           string `json:"mode"`    // "shared" | "byo"
	KMSPath        string `json:"kms_path"`
	Status         string `json:"status"`  // "pending_test" | "active" | "disabled"
	Channel        string `json:"channel,omitempty"`
	IsDefault      bool   `json:"is_default,omitempty"`
	Created        string `json:"created"`
	LastTestAt     string `json:"last_test_at,omitempty"`
	LastTestResult string `json:"last_test_result,omitempty"`
}

// Tenant is the namespace row every other notify table relates to. The
// id is the IAM org slug (e.g. "liquidity"), enforced as a kebab-case
// PRIMARY KEY by the schema migration. One row per organisation. No
// soft-delete; CascadeDelete on the relation cleans up dependents.
type Tenant struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Created string `json:"created"`
	Updated string `json:"updated"`
}

// Template is a re-usable message body keyed by tenant + canonical id.
// Lifecycle: draft → pending_approval → approved → published → archived.
// Lifted from the BD just-shipped design (liquidityio/bd#105).
type Template struct {
	ID         string   `json:"id"`
	TenantSlug string   `json:"tenant_slug"`
	Name       string   `json:"name"`
	Channel    Channel  `json:"channel"`
	Subject    string   `json:"subject,omitempty"`
	Body       string   `json:"body"`
	Vars       []string `json:"vars,omitempty"`
	Status     string   `json:"status"` // draft | pending_approval | approved | published | archived
	Version    int      `json:"version"`
	Created    string   `json:"created"`
	Updated    string   `json:"updated"`
	ApprovedBy string   `json:"approved_by,omitempty"`
}

// Event is an entry in the event catalog. Events drive routing (which
// channel/provider to use), rate-limit policy, and analytics grouping.
type Event struct {
	ID         string   `json:"id"`
	TenantSlug string   `json:"tenant_slug"`
	Name       string   `json:"name"`
	Channels   []string `json:"channels,omitempty"`
	TemplateID string   `json:"template_id,omitempty"`
	RateLimit  int      `json:"rate_limit,omitempty"` // per minute, 0 = no limit
	Enabled    bool     `json:"enabled"`
	Created    string   `json:"created"`
	Updated    string   `json:"updated"`
}

// MeterRow is the per-send ledger entry written for billing. Daily
// rollups aggregate by (tenant_slug, provider, channel, day).
type MeterRow struct {
	ID                string `json:"id"`
	TenantSlug        string `json:"tenant_slug"`
	Event             string `json:"event,omitempty"`
	Provider          string `json:"provider"`
	Channel           Channel `json:"channel"`
	Units             int    `json:"units"`               // sms segments / email count / voice minutes
	VendorCostMicros  int64  `json:"vendor_cost_micros"`  // provider-side cost in USD micros (1e-6)
	RetailPriceMicros int64  `json:"retail_price_micros"` // billed to tenant
	SentAt            string `json:"sent_at"`
}
