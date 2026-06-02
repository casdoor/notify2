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
│   ├── schema/             6 base collections (tenants, providers, templates, events, messages, meter)
│   ├── routes/             /v1/notify/* HTTP handlers
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

Tenant scope: every route reads `X-Org-Id` from the platform plugin
(populated from JWT `owner` claim). Cross-tenant access is impossible
at the SQL filter level.

## Provider credentials — KMS layout

```
shared/{service}/{key}                 # Hanzo subaccount (e.g. shared/plivo/auth-id)
tenants/{slug}/{service}/{key}         # BYO per tenant
```

The `providers` collection row's `kms_path` is the directory
prefix; the resolver appends `/<key>` for each credential field the
provider needs. See `internal/tenant/tenant.go::credKeysForService`.

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
