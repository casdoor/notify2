// Preferences CRUD + consent audit + admin freeze.
//
// Routes (Phase 1 of the notification-preferences paper):
//
//	GET    /v1/notify/preferences                 # user reads own
//	PUT    /v1/notify/preferences                 # user writes own (full doc)
//	GET    /v1/notify/preferences/audit           # user's own consent log
//
//	GET    /v1/notify/admin/preferences/{user_id}/audit    # admin: read trail
//	POST   /v1/notify/admin/preferences/{user_id}/freeze   # admin: bouncing email / dispute
//	POST   /v1/notify/admin/preferences/{user_id}/unfreeze # admin: lift freeze
//
// Auth:
//   - user routes: JWT validated by the platform plugin → X-Org-Id +
//     X-User-Id headers. Missing X-User-Id is 401 (anonymous).
//   - admin routes: `Authorization: Bearer ${NOTIFY_ADMIN_KEY}`. Empty
//     env var → routes always 401 (fail-closed).

package routes

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hanzoai/base/apis"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/router"
	"github.com/hanzoai/dbx"

	"github.com/hanzoai/notify/internal/preferences"
	"github.com/hanzoai/notify/internal/schema"
)

// preferencesAdminKeyEnv is the env var that backs the admin bearer.
// Empty → admin routes always 401, which is the right local-dev posture.
const preferencesAdminKeyEnv = "NOTIFY_ADMIN_KEY"

// mountPreferences installs the preferences surface.
func mountPreferences(r *router.Router[*core.RequestEvent], app core.App) {
	// --- User-scoped routes ---

	r.GET("/v1/notify/preferences", func(e *core.RequestEvent) error {
		org, userID, err := identityFromRequest(e)
		if err != nil {
			return err
		}
		rec, err := loadOrCreatePreferences(app, org, userID, e)
		if err != nil {
			return apis.NewInternalServerError("load preferences", err)
		}
		return jsonOK(e, preferences.ToWire(rec))
	})

	r.PUT("/v1/notify/preferences", func(e *core.RequestEvent) error {
		org, userID, err := identityFromRequest(e)
		if err != nil {
			return err
		}
		var body preferences.Wire
		if err := e.BindBody(&body); err != nil {
			return apis.NewBadRequestError("malformed body", err)
		}
		if err := preferences.Validate(&body); err != nil {
			return apis.NewBadRequestError(err.Error(), nil)
		}
		// Force user_id / org_id to come from the validated headers —
		// never the body. Forecloses one user editing another's prefs
		// via a forged payload.
		body.UserID = userID
		body.OrgID = org

		// Find-or-build (NOT find-or-create): if no prior row exists we
		// allocate the record in memory but don't insert a default — the
		// caller-supplied body is about to be applied on top anyway and a
		// pre-insert with empty required fields would fail validation.
		priorRec, priorExists, err := findOrBuildPreferences(app, org, userID)
		if err != nil {
			return apis.NewInternalServerError("load prior", err)
		}
		var priorWire preferences.Wire
		if priorExists {
			priorWire = preferences.ToWire(priorRec)
		}

		if err := preferences.ApplyWire(priorRec, &body); err != nil {
			return apis.NewBadRequestError(err.Error(), nil)
		}
		if err := app.Save(priorRec); err != nil {
			return apis.NewInternalServerError("save preferences", err)
		}

		// Append a consent-log entry for the mutation. The full prior
		// and new state are dumped to JSON so the audit trail is
		// self-contained even after the prefs row drifts.
		if err := writeConsentLog(app, consentEntry{
			UserID:      userID,
			Org:         org,
			Event:       schema.ConsentEventPrefUpdate,
			PriorState:  priorWire,
			NewState:    body,
			ConsentText: e.Request.Header.Get("X-Consent-Text-Version"),
			IP:          clientIP(e),
			UserAgent:   e.Request.Header.Get("User-Agent"),
		}); err != nil {
			return apis.NewInternalServerError("consent log", err)
		}

		return jsonOK(e, preferences.ToWire(priorRec))
	})

	r.GET("/v1/notify/preferences/audit", func(e *core.RequestEvent) error {
		org, userID, err := identityFromRequest(e)
		if err != nil {
			return err
		}
		rows, err := loadConsentLog(app, org, userID)
		if err != nil {
			return apis.NewInternalServerError("load audit", err)
		}
		return e.JSON(http.StatusOK, map[string]any{"items": rows})
	})

	// --- Admin-scoped routes ---

	r.GET("/v1/notify/admin/preferences/{user_id}/audit", func(e *core.RequestEvent) error {
		org, err := requireAdmin(e)
		if err != nil {
			return err
		}
		userID := strings.TrimSpace(e.Request.PathValue("user_id"))
		if userID == "" {
			return apis.NewBadRequestError("user_id is required", nil)
		}
		rows, err := loadConsentLog(app, org, userID)
		if err != nil {
			return apis.NewInternalServerError("load audit", err)
		}
		return e.JSON(http.StatusOK, map[string]any{"items": rows})
	})

	r.POST("/v1/notify/admin/preferences/{user_id}/freeze", func(e *core.RequestEvent) error {
		org, err := requireAdmin(e)
		if err != nil {
			return err
		}
		return adminSetMute(app, e, org, true)
	})

	r.POST("/v1/notify/admin/preferences/{user_id}/unfreeze", func(e *core.RequestEvent) error {
		org, err := requireAdmin(e)
		if err != nil {
			return err
		}
		return adminSetMute(app, e, org, false)
	})
}

// identityFromRequest returns the (org, user_id) pair from the IAM-
// injected headers. Either missing → 401.
func identityFromRequest(e *core.RequestEvent) (string, string, error) {
	org, err := orgFromRequest(e)
	if err != nil {
		return "", "", err
	}
	userID := strings.TrimSpace(e.Request.Header.Get("X-User-Id"))
	if userID == "" {
		return "", "", e.JSON(http.StatusUnauthorized, map[string]string{
			"error": "X-User-Id header missing — request is unauthenticated",
		})
	}
	return org, userID, nil
}

// requireAdmin validates the Bearer token. The admin key must be set
// in env (NOTIFY_ADMIN_KEY); empty key → fail-closed 401.
//
// Admin requests still carry an X-Org-Id because the prefs row is
// scoped (admin can only freeze a user within an org they control).
func requireAdmin(e *core.RequestEvent) (string, error) {
	want := os.Getenv(preferencesAdminKeyEnv)
	if want == "" {
		return "", e.JSON(http.StatusUnauthorized, map[string]string{
			"error": "admin key not configured",
		})
	}
	hdr := e.Request.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		return "", e.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Bearer token required",
		})
	}
	got := strings.TrimPrefix(hdr, "Bearer ")
	if got != want {
		return "", e.JSON(http.StatusUnauthorized, map[string]string{
			"error": "invalid admin key",
		})
	}
	org := strings.TrimSpace(e.Request.Header.Get("X-Org-Id"))
	if org == "" {
		return "", e.JSON(http.StatusBadRequest, map[string]string{
			"error": "X-Org-Id header required for admin routes",
		})
	}
	return org, nil
}

// adminSetMute toggles marketing_globally_muted on the user's prefs
// row + writes a consent log entry. Used by both freeze and unfreeze.
func adminSetMute(app core.App, e *core.RequestEvent, org string, mute bool) error {
	userID := strings.TrimSpace(e.Request.PathValue("user_id"))
	if userID == "" {
		return apis.NewBadRequestError("user_id is required", nil)
	}
	rec, err := loadOrCreatePreferences(app, org, userID, e)
	if err != nil {
		return apis.NewInternalServerError("load preferences", err)
	}
	priorWire := preferences.ToWire(rec)
	rec.Set("marketing_globally_muted", mute)
	if err := app.Save(rec); err != nil {
		return apis.NewInternalServerError("save preferences", err)
	}
	event := schema.ConsentEventOptOut
	if !mute {
		event = schema.ConsentEventOptIn
	}
	if err := writeConsentLog(app, consentEntry{
		UserID:     userID,
		Org:        org,
		Event:      event,
		PriorState: priorWire,
		NewState:   preferences.ToWire(rec),
		IP:         clientIP(e),
		UserAgent:  e.Request.Header.Get("User-Agent"),
	}); err != nil {
		return apis.NewInternalServerError("consent log", err)
	}
	return jsonOK(e, preferences.ToWire(rec))
}

// findOrBuildPreferences returns (existing-row, true, nil) when a prefs
// row exists or (newly-allocated-but-unsaved-row, false, nil) when none
// does. Used by PUT where the body is about to be applied on top —
// inserting a default row first would fail validation if the body's
// required fields are about to fill in empty columns.
func findOrBuildPreferences(app core.App, org, userID string) (*core.Record, bool, error) {
	if err := ensureTenantRow(app, org); err != nil {
		return nil, false, fmt.Errorf("ensure tenant: %w", err)
	}
	rows, err := app.FindRecordsByFilter(
		schema.Preferences,
		"user_id = {:user_id} && tenant = {:tenant}",
		"-created", 1, 0,
		dbx.Params{"user_id": userID, "tenant": org},
	)
	if err != nil {
		return nil, false, fmt.Errorf("find prefs: %w", err)
	}
	if len(rows) > 0 {
		return rows[0], true, nil
	}
	col, err := app.FindCollectionByNameOrId(schema.Preferences)
	if err != nil {
		return nil, false, fmt.Errorf("find collection: %w", err)
	}
	rec := core.NewRecord(col)
	rec.Set("user_id", userID)
	rec.Set("tenant", org)
	return rec, false, nil
}

// loadOrCreatePreferences returns the user's preference row, creating a
// default row on first read. Defaults match §3.2: every marketing
// category off, transactional via email only. The PrimaryEmail is
// populated from the optional X-User-Email header (set by the platform
// plugin) if present; callers can update via PUT after first read.
func loadOrCreatePreferences(app core.App, org, userID string, e *core.RequestEvent) (*core.Record, error) {
	// Ensure the tenant row exists so the relation field validates. The
	// same pattern that send.go uses.
	if err := ensureTenantRow(app, org); err != nil {
		return nil, fmt.Errorf("ensure tenant: %w", err)
	}
	rows, err := app.FindRecordsByFilter(
		schema.Preferences,
		"user_id = {:user_id} && tenant = {:tenant}",
		"-created", 1, 0,
		dbx.Params{"user_id": userID, "tenant": org},
	)
	if err != nil {
		return nil, fmt.Errorf("find prefs: %w", err)
	}
	if len(rows) > 0 {
		return rows[0], nil
	}
	col, err := app.FindCollectionByNameOrId(schema.Preferences)
	if err != nil {
		return nil, fmt.Errorf("find collection: %w", err)
	}
	rec := core.NewRecord(col)
	rec.Set("user_id", userID)
	rec.Set("tenant", org)
	email := ""
	if e != nil {
		email = strings.TrimSpace(e.Request.Header.Get("X-User-Email"))
	}
	rec.Set("primary_email", email)
	rec.Set("legal_email", email)
	rec.Set("preferred_channels", []string{"email"})
	rec.Set("realtime_channels", []string{"email"})
	rec.Set("marketing_subscriptions", map[string]bool{})
	rec.Set("quiet_hours_start", "21:00")
	rec.Set("quiet_hours_end", "08:00")
	rec.Set("timezone", "America/New_York")
	rec.Set("marketing_globally_muted", false)
	if err := app.Save(rec); err != nil {
		return nil, fmt.Errorf("save default prefs: %w", err)
	}
	return rec, nil
}

// consentEntry is the wire shape for a single consent log mutation.
// Channel + Category are blank for whole-row mutations (PUT prefs);
// the unsubscribe handler fills them in for per-category opt-outs.
type consentEntry struct {
	UserID      string
	Org         string
	Event       string
	Category    string
	Channel     string
	PriorState  any
	NewState    any
	ConsentText string
	IP          string
	UserAgent   string
}

// writeConsentLog appends a single audit row. JSON serialisation
// failures are non-fatal — the row is written with empty state blobs
// rather than refusing the mutation, since the audit row's existence
// is the audit signal.
func writeConsentLog(app core.App, entry consentEntry) error {
	col, err := app.FindCollectionByNameOrId(schema.ConsentLog)
	if err != nil {
		return fmt.Errorf("find consent log: %w", err)
	}
	rec := core.NewRecord(col)
	rec.Set("user_id", entry.UserID)
	rec.Set("tenant", entry.Org)
	rec.Set("event", entry.Event)
	rec.Set("category", entry.Category)
	rec.Set("channel", entry.Channel)
	if entry.PriorState != nil {
		if blob, err := json.Marshal(entry.PriorState); err == nil {
			rec.Set("prior_state", string(blob))
		}
	}
	if entry.NewState != nil {
		if blob, err := json.Marshal(entry.NewState); err == nil {
			rec.Set("new_state", string(blob))
		}
	}
	rec.Set("consent_text_version", entry.ConsentText)
	rec.Set("ip_address", entry.IP)
	rec.Set("user_agent", entry.UserAgent)
	return app.Save(rec)
}

// loadConsentLog returns the user's audit trail, newest first. Capped
// at 500 rows — pagination lands when the trail grows beyond that.
func loadConsentLog(app core.App, org, userID string) ([]map[string]any, error) {
	rows, err := app.FindRecordsByFilter(
		schema.ConsentLog,
		"user_id = {:user_id} && tenant = {:tenant}",
		"-created", 500, 0,
		dbx.Params{"user_id": userID, "tenant": org},
	)
	if err != nil {
		return nil, fmt.Errorf("find audit: %w", err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		var prior, next any
		_ = json.Unmarshal([]byte(r.GetString("prior_state")), &prior)
		_ = json.Unmarshal([]byte(r.GetString("new_state")), &next)
		out = append(out, map[string]any{
			"id":                   r.Id,
			"user_id":              r.GetString("user_id"),
			"org_id":               r.GetString("tenant"),
			"event":                r.GetString("event"),
			"category":             r.GetString("category"),
			"channel":              r.GetString("channel"),
			"prior_state":          prior,
			"new_state":            next,
			"consent_text_version": r.GetString("consent_text_version"),
			"ip_address":           r.GetString("ip_address"),
			"user_agent":           r.GetString("user_agent"),
			"created":              r.GetString("created"),
		})
	}
	return out, nil
}

// clientIP returns the best-guess client IP. Prefers X-Forwarded-For
// (set by the gateway/ingress) and falls back to RemoteAddr.
func clientIP(e *core.RequestEvent) string {
	if e == nil || e.Request == nil {
		return ""
	}
	if xf := e.Request.Header.Get("X-Forwarded-For"); xf != "" {
		// First entry is the originating client.
		if i := strings.Index(xf, ","); i >= 0 {
			return strings.TrimSpace(xf[:i])
		}
		return strings.TrimSpace(xf)
	}
	return e.Request.RemoteAddr
}

// _ keeps time imported even if all uses move out of this file. The
// consent-log timestamp is auto-filled by the AutodateField but having
// the import here documents the intent.
var _ = time.Now
var _ = errors.New
