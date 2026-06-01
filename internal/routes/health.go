package routes

import (
	"net/http"

	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/router"
)

// mountHealth installs the K8s-probe path. Base itself already serves
// /healthz at the root; we add /v1/notify/health as a convenience that
// follows the per-service path convention.
func mountHealth(r *router.Router[*core.RequestEvent]) {
	r.GET("/v1/notify/health", func(e *core.RequestEvent) error {
		return e.JSON(http.StatusOK, map[string]string{
			"status":  "ok",
			"service": "notify",
		})
	})
}
