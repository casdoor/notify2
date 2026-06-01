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
	activities := tasks.NewActivities(app, resolver)

	// Tasks worker. TASKS_ADDR empty → no async — sync sends still work.
	var worker *tasks.Worker
	if addr := os.Getenv("TASKS_ADDR"); addr != "" {
		w, err := tasks.New(tasks.Config{
			Address:   addr,
			Namespace: envOr("TASKS_NAMESPACE", "notify"),
			TaskQueue: envOr("TASKS_QUEUE", "notify-send"),
		}, activities)
		if err != nil {
			log.Fatalf("notifyd: worker: %v", err)
		}
		worker = w
	}

	routes.MustRegister(app, routes.Config{
		Resolver: resolver,
		Worker:   worker,
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
