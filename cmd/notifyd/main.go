// notifyd — Hanzo Notify daemon.
//
// One binary. One process. One listener.
//
//	ingress → gateway → notifyd
//
// Storage + auth + HTTP router come from hanzoai/base. The library at
// the module root (github.com/hanzoai/notify) provides the 33 provider
// impls; this binary wraps it as a per-tenant service with metering,
// templates, an event catalog, and a hanzoai/tasks-backed async path.
package main

import (
	"log"
	"os"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/plugins/platform"

	"github.com/hanzoai/notify/internal/boot"
	"github.com/hanzoai/notify/internal/routes"
	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/internal/tasks"
	"github.com/hanzoai/notify/internal/tenant"
)

func main() {
	app := base.New()

	// Platform plugin: IAM JWT validation, X-Org-Id injection, KMS
	// helpers. Same registration shape as hanzoai/auto.
	platform.MustRegister(app, platform.PlatformConfig{
		IAMEndpoint:     envOr("IAM_ENDPOINT", "https://hanzo.id"),
		KMSEndpoint:     envOr("KMS_ENDPOINT", "https://kms.hanzo.ai"),
		IAMClientID:     os.Getenv("IAM_CLIENT_ID"),
		IAMClientSecret: os.Getenv("IAM_CLIENT_SECRET"),
		IAMApp:          envOr("IAM_APP", "hanzo-notify"),
	})

	schema.MustRegister(app)

	// KMS client. Nil when KMS_ENDPOINT is unset — the resolver then
	// falls back to env-var credentials, which is the local-dev path.
	kmsClient := boot.NewKMSClient()
	resolver := tenant.New(app, kmsClient)
	// Multi-brand Plivo resolver. Only constructed when KMS is wired —
	// the per-brand fallback to the Liquidity default depends on KMS
	// reads. Nil here means the /v1/notify/brand/plivo* surface returns
	// 503 (the routes guard for this) which is the right local-dev
	// behaviour.
	var plivoResolver *tenant.PlivoResolver
	if kmsClient != nil {
		if pr, err := tenant.NewPlivoResolver(kmsClient); err != nil {
			log.Fatalf("notifyd: plivo resolver: %v", err)
		} else {
			plivoResolver = pr
		}
	}
	activities := tasks.NewActivities(app, resolver)

	// Tasks worker. TASKS_ADDR empty → no async — POST /v1/notify/send
	// without ?sync=true then returns 503. This is intentional: per
	// hanzoai/tasks/CONTRACT.md §3, production MUST set TASKS_ADDR; a
	// silent sync fallback would mask the misconfiguration.
	var worker *tasks.Worker
	if addr := os.Getenv("TASKS_ADDR"); addr != "" {
		w, err := tasks.New(tasks.Config{
			Address: addr,
			// CONTRACT.md §6: namespace = per-tenant org slug. Notify is
			// multi-tenant in principle but ships with one shared worker
			// today; per-org namespaces land in the follow-up once the
			// liquidity tenant traffic scales (tracked: hanzoai/notify#TODO).
			Namespace: envOr("TASKS_NAMESPACE", "default"),
			TaskQueue: envOr("TASKS_QUEUE", "notify-send"),
		}, activities)
		if err != nil {
			log.Fatalf("notifyd: worker: %v", err)
		}
		worker = w

		// Lifecycle: Start at serve time (after migrations), Stop at
		// terminate. Failure to start is non-fatal so reads / sync sends
		// keep working; async sends then return 503 until tasksd is back.
		app.OnServe().BindFunc(func(e *core.ServeEvent) error {
			if err := worker.Start(); err != nil {
				app.Logger().Warn("notifyd: worker start failed; async sends will 503",
					"err", err)
			}
			return e.Next()
		})
		app.OnTerminate().BindFunc(func(e *core.TerminateEvent) error {
			worker.Stop()
			return e.Next()
		})
	}

	// dispatcher is the typed interface routes/send.go reads. Passing a
	// (*tasks.Worker)(nil) into an interface field is NOT the same as a
	// nil interface — guard against the typed-nil trap explicitly so the
	// route's `cfg.Dispatcher == nil` check works as intended.
	var dispatcher tasks.Dispatcher
	if worker != nil {
		dispatcher = worker
	}

	routes.MustRegister(app, routes.Config{
		Resolver:      resolver,
		Dispatcher:    dispatcher,
		KMSClient:     kmsClient,
		PlivoResolver: plivoResolver,
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

// envOr returns the env var if set, otherwise the default.
func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
