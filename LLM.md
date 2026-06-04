# hanzoai/notify

Canonical Hanzo messaging library + standalone service.

The library lives at the module root (`github.com/hanzoai/notify`) and
provides 33 provider impls under `service/{plivo, twilio, sendgrid,
mail, …}`. The service that wraps the library lives in `cmd/notifyd`
and follows the `hanzoai/auto` layout exactly — same `hanzoai/base` +
`hanzoai/tasks` stack, same Docker shape, same K8s envelope.

## Repo layout

```
.                           library — Notify / Notifier / providers
├── service/{plivo,…}       33 provider implementations (untouched)
├── cmd/notifyd/            service binary (main)
├── internal/
│   ├── boot/               KMS facade wiring (via platform plugin)
│   ├── schema/             9 base collections (tenants, providers, templates, events, messages, meter, notification_preferences, notification_consent_log, notification_unsubscribe_tokens)
│   ├── routes/             /v1/notify/* HTTP handlers
│   ├── router/             Phase 1: pure (prefs, category, time) → []channel function
│   ├── preferences/        Phase 1: wire/validate/row-mapper for notification_preferences
│   ├── unsubscribe/        Phase 1: HMAC token sign/verify (one-click email unsubscribe)
│   ├── marketing/          Phase 1: List-Unsubscribe + List-Unsubscribe-Post header builder
│   ├── tenant/             per-tenant Notifier resolver (KMS-backed creds)
│   ├── template/           lifecycle + Go text/template rendering
│   ├── event/              event catalog routing
│   ├── metering/           per-send ledger + aggregation
│   ├── tasks/              hanzoai/tasks workflow + activity for async sends
│   └── zaprpc/             procedure constants (server impl land later)
└── pkg/                    public consumer SDK
    ├── client/             HTTP client → notifyd
    └── types/              wire shapes shared by routes + client
```

## Surface (HTTP, all under `/v1/notify/`)

| Method | Path                              | Owner                |
|--------|-----------------------------------|----------------------|
| GET    | `/health`                         | routes/health.go     |
| POST   | `/send` (+ `/send/{channel}`)     | routes/send.go       |
| GET    | `/messages` + `/messages/{id}`    | routes/messages.go   |
| GET    | `/providers`                      | routes/providers.go  |
| POST   | `/providers` + `/{id}/{test,activate,disable}` | routes/providers.go  |
| GET    | `/templates`                      | routes/templates.go  |
| POST   | `/templates` + `/{id}/{submit,approve,publish,archive}` | routes/templates.go  |
| GET    | `/events`, POST `/events`         | routes/events.go     |
| GET    | `/metering?from=&to=`             | routes/metering.go   |
| GET    | `/brand/plivo`                    | routes/brand_plivo.go (metadata only — no secrets) |
| PUT    | `/brand/plivo`                    | routes/brand_plivo.go (writes KMS) |
| DELETE | `/brand/plivo`                    | routes/brand_plivo.go (clears KMS — falls back to default) |
| POST   | `/brand/plivo/test`               | routes/brand_plivo.go (probe SMS via resolved creds) |
| GET    | `/preferences`                    | routes/preferences.go (user reads own; auto-create defaults) |
| PUT    | `/preferences`                    | routes/preferences.go (user updates own; appends consent log) |
| GET    | `/preferences/audit`              | routes/preferences.go (user's own consent log) |
| GET    | `/admin/preferences/{user_id}/audit`   | routes/preferences.go (admin: read trail; Bearer NOTIFY_ADMIN_KEY) |
| POST   | `/admin/preferences/{user_id}/freeze`  | routes/preferences.go (admin: marketing_globally_muted=true) |
| POST   | `/admin/preferences/{user_id}/unfreeze`| routes/preferences.go (admin: marketing_globally_muted=false) |
| GET    | `/unsubscribe/{token}`            | routes/unsubscribe.go (no-JS confirmation page) |
| POST   | `/unsubscribe/{token}`            | routes/unsubscribe.go (opt-out; token IS auth via HMAC) |
| POST   | `/resubscribe/{token}`            | routes/unsubscribe.go (opt-in mirror) |
| POST   | `/sms-inbound`                    | routes/sms_inbound.go (Plivo + Twilio STOP keyword webhook) |

Tenant scope: every route reads `X-Org-Id` from the platform plugin
(populated from JWT `owner` claim). Cross-tenant access is impossible
at the SQL filter level.

## Provider credentials — KMS layout

```
shared/{service}/{key}                            # Hanzo subaccount (legacy DB-row path)
tenants/{slug}/{service}/{key}                    # BYO per tenant (DB-row path)
brand/{slug}/{provider}/{key-kebab}               # per-brand chain provider creds
brand/liquidity/{provider}/{key-kebab}            # fleet default (fail-closed if missing)
brand/{slug}/notify-chain/{channel}               # JSON array of provider ids — per-channel order override
```

Three resolution paths:

1. **DB-row resolver** (`internal/tenant/tenant.go`) — looks up a row
   in the `providers` collection scoped to X-Org-Id, reads
   `kms_path`, appends the field name, fetches each value from KMS.
   Used by the legacy single-provider `?provider=...` pinning path.

2. **Brand resolver** (`internal/tenant/plivo_resolver.go`) — used
   ONLY for the `/v1/notify/brand/plivo*` endpoints (platform UI's
   "current effective Plivo" indicator). Reads `brand/<slug>/plivo/*`
   directly; on miss falls back to `brand/liquidity/plivo/*`.
   Fail-closed if the Liquidity default is missing — no hard-coded
   fallback.

3. **Chain resolver** (`internal/tenant/chain.go`) — default send
   path. Builds a per-(brand, channel) ordered provider chain
   (primary → fallback1 → fallback2). The order comes from KMS at
   `brand/<slug>/notify-chain/<channel>` (JSON array of provider ids);
   absent → `DefaultChainFor(channel)`:

       sms             → plivo, twilio
       email_txn       → ses_api, ses_smtp
       email_otp       → ses_smtp, ses_api
       email_marketing → sendgrid, ses_api

   Each provider's credentials are read from
   `brand/<slug>/<provider>/<key-kebab>` with brand→liquidity
   fallback on missing fields. Per-attempt deadline 10s, whole-chain
   ceiling 30s. Errors are classified terminal (4xx, invalid
   recipient, blocklist) or retryable (5xx, transport, timeout);
   terminal stops the chain, retryable advances to the next provider.
   The chosen provider id is stored on the message row's `provider`
   field and the per-attempt trace lands in `messages.metadata`.

Why three paths: caller-pinned (path 1) lets the platform UI probe
exactly one provider; brand-Plivo UI (path 2) is a metadata surface
for ops; chain (path 3) is the production send path. The chain
defaults match the legacy "Plivo for SMS, SES for email" behavior
but add automatic failover when the primary is down.

## Send modes

- **Async (default)** — POST returns **202 Accepted** with
  `{message_id, task_id, status:"queued"}`; a hanzoai/tasks worker
  picks up the `NotifySendWorkflow` and runs the same `Deliver`
  activity that powers sync.
- **Sync (`?sync=true`)** — handler runs the activity inline and blocks
  on the provider's response. Returns **200 OK** with the terminal
  `{message_id, status, error?}` shape.
- **Scheduled (`?send_at=<rfc3339>`)** — wire reserved; lands once
  the tasks scheduler API has the matching client surface.

Async fails closed: if the `tasks.Dispatcher` is not configured
(`TASKS_ADDR` empty) or not yet started (tasksd unreachable), the
default async path returns **503 Service Unavailable** with a hint to
retry shortly or call `?sync=true`. There is intentionally no silent
sync fallback — per hanzoai/tasks CONTRACT.md §3, production MUST set
`TASKS_ADDR`.

## hanzoai/tasks wiring

- Namespace: `default` (single shared worker for all tenants in this
  PR — per-org namespacing per CONTRACT.md §6 is the next step once
  the `liquidity` tenant traffic scales).
- Task queue: `notify-send`.
- Workflow: `NotifySendWorkflow` (`internal/tasks/workflow.go`).
- Activity: `Deliver` — idempotent on the message row's terminal
  states (`sent` / `failed`), so tasks-server replays do not re-fire
  the provider.
- Worker lifecycle (Start/Stop) is owned by `cmd/notifyd`; the
  `internal/routes` package only consumes the `tasks.Dispatcher`
  interface.

## Phase 1 — notification preferences (paper: notification-preferences-and-channel-routing)

Substrate only. WhatsApp + push are Phase 2/3 — `wa` and `push` Channel
values declared so the wire shape is forward-compatible but the router
never returns them.

- **Channel router** (`internal/router`) is a pure function:
  `(prefs, category, now) → []channel`. No IO. Table-driven test
  walks every cell in §3 matrix (11 categories × 5 channels = 55
  cells).
- **Transactional categories** (security, legal, money_movement,
  trade_execution, account_status, system) always deliver via email
  per regulation; SMS/Web come along when the user enabled them in
  `realtime_channels` AND the §3 matrix allows it.
- **Marketing categories** (promotional, newsletter, product_update,
  partner_offer, research) deliver only when explicitly opted-in
  AND not globally muted AND outside the user's quiet hours window
  (the latter applies only to promotional + partner_offer).
- **Default state**: every new user starts with every marketing
  category OFF; first GET `/v1/notify/preferences` materialises the
  defaults: `preferred_channels=[email]`, `realtime_channels=[email]`,
  empty `marketing_subscriptions`, quiet hours 21:00–08:00
  America/New_York.
- **One-click unsubscribe** (`internal/unsubscribe`): HMAC-SHA256
  over `user_id|category|expires_at` with 30-day TTL. Token IS auth;
  GET renders no-JS confirmation page, POST flips the bit + writes
  consent log. Mirror POST `/resubscribe/{token}`. Tokens are stored
  with `consumed_at` for idempotency.
- **List-Unsubscribe headers** (`internal/marketing`): RFC 8058 +
  RFC 2369 header builder. `List-Unsubscribe: <https-url>, <mailto>`
  + `List-Unsubscribe-Post: List-Unsubscribe=One-Click`. Per-send
  token, 30-day expiry. Builder is decoupled from the send path so
  callers can adopt it independently of the SES raw-MIME refactor.
- **STOP keyword webhook** (`/v1/notify/sms-inbound`): one route
  accepts Plivo + Twilio (both providers post the same logical
  payload, just different field names). Matches
  `STOP|UNSUBSCRIBE|QUIT|CANCEL|END` case-insensitive on the trimmed
  body; resolves user by `primary_phone` (E.164-normalised), sets
  `marketing_globally_muted=true`, zeros every marketing category,
  writes consent log row (event=opt_out, channel=sms), replies with
  Twilio/Plivo XML confirmation envelope.
- **Boot fail-closed**: `NOTIFY_UNSUBSCRIBE_SECRET` is required;
  empty in production crashes the binary. Test mode
  (`NOTIFY_TEST_MODE=1`) skips the requirement and the unsubscribe
  routes degrade to 503 while the rest of the surface keeps working.
- **Admin auth**: `NOTIFY_ADMIN_KEY` Bearer; empty env →
  fail-closed 401 on every admin route.

## Schema invariants

- One Message row per recipient; multi-recipient `to` fans out.
- `idempotency_key` is unique within a tenant (partial index).
- Templates are versioned per `(tenant, name)`; only the latest
  `published` version is sendable.
- Meter rows are append-only; daily rollup runs out-of-cluster.

## Build / boot

```
GOWORK=off go build ./...
GOWORK=off go test ./...
GOWORK=off go build -o /tmp/notifyd ./cmd/notifyd
TASKS_ADDR="" KMS_ENDPOINT="" /tmp/notifyd serve --http 0.0.0.0:8090 --dir /var/lib/notify
```

`KMS_ENDPOINT=""` runs in env-var credentials mode (local dev).
`TASKS_ADDR=""` disables async — only `?sync=true` works; the default
async path returns 503 until `TASKS_ADDR` is set.

## Tags / versioning

- `v1.0.0` — pre-rename casdoor lineage (historical).
- `v1.6.x` — Hanzo rebrand on top of casdoor/notify2 import path.
- `v1.7.0+` — `github.com/hanzoai/notify` canonical module path.
- `v1.1.0-pre*` — service scaffold (notifyd + internal/ + pkg/).
