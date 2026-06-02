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

	"github.com/hanzoai/notify/internal/tasks"
	"github.com/hanzoai/notify/internal/tenant"
)

// Config wires the routes module to its collaborators.
type Config struct {
	// Resolver constructs per-tenant Notifier instances on demand.
	Resolver *tenant.Resolver

	// Worker is the durable-execution worker. Nil disables async mode
	// (every send becomes sync). Useful for local-dev / scratch images.
	Worker *tasks.Worker
}

// MustRegister installs the notify API on app's OnServe hook. The hook
// fires once, when the HTTP server starts.
func MustRegister(app *base.Base, cfg Config) {
	if cfg.Resolver == nil {
		panic("routes: Config.Resolver is required")
	}

	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		// Start the worker — failure degrades async sends but the rest
		// of the API stays up so messages and metering remain queryable.
		if cfg.Worker != nil {
			if err := cfg.Worker.Start(); err != nil {
				app.Logger().Warn("notify: worker start failed; async sends disabled",
					"err", err)
			}
		}

		mountHealth(e.Router)
		mountSend(e.Router, app, cfg)
		mountMessages(e.Router, app)
		mountProviders(e.Router, app)
		mountTemplates(e.Router, app)
		mountEvents(e.Router, app)
		mountMetering(e.Router, app)
		mountTenants(e.Router, app)
		return e.Next()
	})

	app.OnTerminate().BindFunc(func(e *core.TerminateEvent) error {
		if cfg.Worker != nil {
			cfg.Worker.Stop()
		}
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
