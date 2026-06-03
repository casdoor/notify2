// Package routes mounts Hanzo Notify's /v1/notify/* HTTP surface on
// top of hanzoai/base's router.
//
// The platform plugin handles auth (IAM JWT validation) and org-header
// injection (X-Org-Id from JWT owner claim). This package adds the
// notify-specific endpoints: send, message lookup, providers, templates,
// events, metering.
package routes

import (
	"net/http"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"

	"github.com/hanzoai/notify/internal/kmsbridge"
	"github.com/hanzoai/notify/internal/tasks"
	"github.com/hanzoai/notify/internal/tenant"
)

// Config wires the routes module to its collaborators.
type Config struct {
	// Resolver constructs per-tenant Notifier instances on demand —
	// the single-provider, pin-an-id path. Kept alive for ?provider=
	// requests and as the local-dev fallback when KMS is unwired.
	Resolver *tenant.Resolver

	// ChainResolver constructs the per-channel multi-provider chain
	// (primary → fallback1 → fallback2). When non-nil and the caller
	// did NOT pin a provider, the sync handler runs through the chain
	// and records the per-attempt trace on the message row.
	ChainResolver *tenant.ChainResolver

	// Dispatcher enqueues async sends. Nil means async dispatch is not
	// available; POST /v1/notify/send without ?sync=true then returns
	// 503. The binary owns the worker's Start/Stop lifecycle; this
	// package only reads the dispatch surface.
	Dispatcher tasks.Dispatcher

	// KMSClient is the KMS facade. Required by the brand override
	// endpoints (/v1/notify/brand/plivo*). Nil → those endpoints return
	// 503 (local-dev path).
	KMSClient *kmsbridge.Client

	// PlivoResolver handles per-brand Plivo credential resolution with
	// fallback to the Liquidity default. Nil → /v1/notify/brand/plivo*
	// returns 503.
	PlivoResolver *tenant.PlivoResolver
}

// MustRegister installs the notify API on app's OnServe hook. The hook
// fires once, when the HTTP server starts.
func MustRegister(app *base.Base, cfg Config) {
	if cfg.Resolver == nil {
		panic("routes: Config.Resolver is required")
	}

	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		mountHealth(e.Router)
		mountSend(e.Router, app, cfg)
		mountMessages(e.Router, app)
		mountProviders(e.Router, app)
		mountTemplates(e.Router, app)
		mountEvents(e.Router, app)
		mountMetering(e.Router, app)
		mountTenants(e.Router, app)
		MountBrandPlivo(e.Router, app, cfg.KMSClient, cfg.PlivoResolver)
		return e.Next()
	})
}

// orgFromRequest reads the X-Org-Id header. The platform plugin sets
// this whenever a JWT is validated; if it's missing the route returns
// 401 since the request is unauthenticated.
func orgFromRequest(e *core.RequestEvent) (string, error) {
	org := e.Request.Header.Get("X-Org-Id")
	if org == "" {
		return "", e.JSON(http.StatusUnauthorized, map[string]string{
			"error": "X-Org-Id header missing — request is unauthenticated",
		})
	}
	return org, nil
}

// jsonOK is a small wrapper that mirrors auto's helper.
func jsonOK(e *core.RequestEvent, body any) error {
	return e.JSON(http.StatusOK, body)
}
