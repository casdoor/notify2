package routes

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tests"

	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/internal/unsubscribe"
)

// TestPreferences_GetCreatesDefault — first GET creates a default row
// and returns it. Defaults: every marketing category off, transactional
// via email.
func TestPreferences_GetCreatesDefault(t *testing.T) {
	t.Parallel()
	registerSchema()

	scenario := tests.ApiScenario{
		Name:           "GET /v1/notify/preferences (default create)",
		Method:         http.MethodGet,
		URL:            "/v1/notify/preferences",
		Headers: map[string]string{
			"X-Org-Id":      "test-org",
			"X-User-Id":     "user-1",
			"X-User-Email":  "u@example.com",
		},
		ExpectedStatus: http.StatusOK,
		ExpectedContent: []string{
			`"user_id":"user-1"`,
			`"org_id":"test-org"`,
			`"primary_email":"u@example.com"`,
			`"legal_email":"u@example.com"`,
			`"timezone":"America/New_York"`,
			`"quiet_hours_start":"21:00"`,
			`"marketing_globally_muted":false`,
			`"preferred_channels":["email"]`,
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			mountPreferences(e.Router, app)
		},
	}
	scenario.Test(t)
}

// TestPreferences_RequiresUserHeader — missing X-User-Id is 401.
func TestPreferences_RequiresUserHeader(t *testing.T) {
	t.Parallel()
	registerSchema()

	scenario := tests.ApiScenario{
		Name:           "GET /v1/notify/preferences (no X-User-Id)",
		Method:         http.MethodGet,
		URL:            "/v1/notify/preferences",
		Headers:        map[string]string{"X-Org-Id": "test-org"},
		ExpectedStatus: http.StatusUnauthorized,
		ExpectedContent: []string{"X-User-Id"},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			mountPreferences(e.Router, app)
		},
	}
	scenario.Test(t)
}

// TestPreferences_PutPersistsAndLogs — PUT updates the row and appends
// a consent_log entry.
func TestPreferences_PutPersistsAndLogs(t *testing.T) {
	t.Parallel()
	registerSchema()

	body := `{
		"primary_email":"new@example.com",
		"legal_email":"new@example.com",
		"timezone":"America/New_York",
		"preferred_channels":["email","sms"],
		"realtime_channels":["email"],
		"marketing_subscriptions":{"promotional":true,"newsletter":false},
		"quiet_hours_start":"22:00",
		"quiet_hours_end":"07:00",
		"marketing_globally_muted":false
	}`

	scenario := tests.ApiScenario{
		Name:           "PUT /v1/notify/preferences",
		Method:         http.MethodPut,
		URL:            "/v1/notify/preferences",
		Body:           strings.NewReader(body),
		Headers: map[string]string{
			"X-Org-Id":               "test-org",
			"X-User-Id":              "user-1",
			"X-Consent-Text-Version": "v3",
			"User-Agent":             "test-ua",
		},
		ExpectedStatus: http.StatusOK,
		ExpectedContent: []string{
			`"primary_email":"new@example.com"`,
			`"quiet_hours_start":"22:00"`,
			`"promotional":true`,
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			mountPreferences(e.Router, app)
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			// Consent log must have a row for this mutation.
			rows, err := app.FindAllRecords(schema.ConsentLog)
			if err != nil {
				t.Fatalf("find consent log: %v", err)
			}
			if len(rows) == 0 {
				t.Fatalf("expected at least one consent log row")
			}
			var found bool
			for _, r := range rows {
				if r.GetString("event") == schema.ConsentEventPrefUpdate &&
					r.GetString("user_id") == "user-1" &&
					r.GetString("consent_text_version") == "v3" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("no pref_update consent log row with v3 found")
			}
		},
	}
	scenario.Test(t)
}

// TestPreferences_PutRejectsBadInput — bad email format → 400.
func TestPreferences_PutRejectsBadInput(t *testing.T) {
	t.Parallel()
	registerSchema()

	body := `{"primary_email":"not-an-email","legal_email":"x@y.com","timezone":"UTC"}`

	scenario := tests.ApiScenario{
		Name:           "PUT /v1/notify/preferences (bad email)",
		Method:         http.MethodPut,
		URL:            "/v1/notify/preferences",
		Body:           strings.NewReader(body),
		Headers: map[string]string{
			"X-Org-Id":  "test-org",
			"X-User-Id": "user-1",
		},
		ExpectedStatus:  http.StatusBadRequest,
		ExpectedContent: []string{"Primary_email"},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			mountPreferences(e.Router, app)
		},
	}
	scenario.Test(t)
}

// TestPreferences_Audit — GET /audit returns the consent log for the
// user.
func TestPreferences_Audit(t *testing.T) {
	t.Parallel()
	registerSchema()

	scenario := tests.ApiScenario{
		Name:           "GET /v1/notify/preferences/audit",
		Method:         http.MethodGet,
		URL:            "/v1/notify/preferences/audit",
		Headers: map[string]string{
			"X-Org-Id":  "test-org",
			"X-User-Id": "user-1",
		},
		ExpectedStatus: http.StatusOK,
		ExpectedContent: []string{`"items"`},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			seedConsentLog(t, app, "test-org", "user-1")
			mountPreferences(e.Router, app)
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			var body struct {
				Items []map[string]any `json:"items"`
			}
			if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if len(body.Items) != 1 {
				t.Fatalf("want 1 audit row, got %d", len(body.Items))
			}
		},
	}
	scenario.Test(t)
}

// TestPreferences_AdminFreezeRequiresKey — admin route without key → 401.
// No t.Parallel because t.Setenv guards against parallel use.
func TestPreferences_AdminFreezeRequiresKey(t *testing.T) {
	registerSchema()
	t.Setenv("NOTIFY_ADMIN_KEY", "secret-admin-key")

	scenario := tests.ApiScenario{
		Name:            "POST /admin/preferences/{id}/freeze (no bearer)",
		Method:          http.MethodPost,
		URL:             "/v1/notify/admin/preferences/user-1/freeze",
		Headers:         map[string]string{"X-Org-Id": "test-org"},
		ExpectedStatus:  http.StatusUnauthorized,
		ExpectedContent: []string{"Bearer"},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			mountPreferences(e.Router, app)
		},
	}
	scenario.Test(t)
}

// TestPreferences_AdminFreezeUnfreeze — happy path with the bearer.
// No t.Parallel because t.Setenv guards against parallel use.
func TestPreferences_AdminFreezeUnfreeze(t *testing.T) {
	registerSchema()
	t.Setenv("NOTIFY_ADMIN_KEY", "secret-admin-key")

	scenario := tests.ApiScenario{
		Name:           "POST /admin/preferences/{id}/freeze",
		Method:         http.MethodPost,
		URL:            "/v1/notify/admin/preferences/user-1/freeze",
		Headers: map[string]string{
			"X-Org-Id":      "test-org",
			"Authorization": "Bearer secret-admin-key",
		},
		ExpectedStatus: http.StatusOK,
		ExpectedContent: []string{`"marketing_globally_muted":true`},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			seedPreferences(t, app, "test-org", "user-1", false)
			mountPreferences(e.Router, app)
		},
	}
	scenario.Test(t)
}

// TestUnsubscribe_RoundTrip — sign a token, hit POST, verify the prefs
// row gets opt_out + the consent log records it.
func TestUnsubscribe_RoundTrip(t *testing.T) {
	t.Parallel()
	registerSchema()

	signer, err := unsubscribe.NewSigner("test-secret")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := signer.SignWithTTL("user-1", "promotional", nowUTC(), unsubscribe.Default30Days)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	scenario := tests.ApiScenario{
		Name:           "POST /v1/notify/unsubscribe/{token}",
		Method:         http.MethodPost,
		URL:            "/v1/notify/unsubscribe/" + tok,
		ExpectedStatus: http.StatusOK,
		ExpectedContent: []string{
			"unsubscribed from",
			"promotional",
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			seedPreferences(t, app, "test-org", "user-1", true /*pretendOpted*/)
			mountUnsubscribe(e.Router, app, signer)
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			// Pref row's promotional flag is false now.
			rows, err := app.FindAllRecords(schema.Preferences)
			if err != nil {
				t.Fatalf("find prefs: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("expected 1 prefs row, got %d", len(rows))
			}
			subs := rows[0].GetString("marketing_subscriptions")
			if !strings.Contains(subs, `"promotional":false`) {
				t.Fatalf("marketing_subscriptions did not flip promotional → false: %s", subs)
			}
			// Consent log has an opt_out row.
			cl, err := app.FindAllRecords(schema.ConsentLog)
			if err != nil {
				t.Fatalf("find consent log: %v", err)
			}
			var found bool
			for _, r := range cl {
				if r.GetString("event") == schema.ConsentEventOptOut &&
					r.GetString("category") == "promotional" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("no opt_out consent log row for promotional")
			}
			// Token marked consumed.
			tokRow, err := app.FindRecordById(schema.UnsubscribeTokens, tok)
			if err != nil || tokRow == nil {
				t.Fatalf("token row missing: %v", err)
			}
			if tokRow.GetString("consumed_at") == "" {
				t.Fatalf("token consumed_at not set")
			}
		},
	}
	scenario.Test(t)
}

// TestUnsubscribe_RejectsInvalidToken — bad HMAC → 400 page.
func TestUnsubscribe_RejectsInvalidToken(t *testing.T) {
	t.Parallel()
	registerSchema()

	signer, _ := unsubscribe.NewSigner("test-secret")

	scenario := tests.ApiScenario{
		Name:           "POST /v1/notify/unsubscribe/{bad-token}",
		Method:         http.MethodPost,
		URL:            "/v1/notify/unsubscribe/notavalidtokenatall",
		ExpectedStatus: http.StatusBadRequest,
		ExpectedContent: []string{"no longer valid"},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			mountUnsubscribe(e.Router, app, signer)
		},
	}
	scenario.Test(t)
}

// TestUnsubscribe_NoSignerDegrades — nil signer → 503.
func TestUnsubscribe_NoSignerDegrades(t *testing.T) {
	t.Parallel()
	registerSchema()

	scenario := tests.ApiScenario{
		Name:            "POST /v1/notify/unsubscribe/{token} (no signer)",
		Method:          http.MethodPost,
		URL:             "/v1/notify/unsubscribe/anything",
		ExpectedStatus:  http.StatusServiceUnavailable,
		ExpectedContent: []string{"NOTIFY_UNSUBSCRIBE_SECRET"},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			mountUnsubscribe(e.Router, app, nil)
		},
	}
	scenario.Test(t)
}

// TestSMSInbound_StopMutesAndAcks — STOP keyword opts the user out
// and writes the consent log.
func TestSMSInbound_StopMutesAndAcks(t *testing.T) {
	t.Parallel()
	registerSchema()

	scenario := tests.ApiScenario{
		Name:   "POST /v1/notify/sms-inbound (STOP)",
		Method: http.MethodPost,
		URL:    "/v1/notify/sms-inbound",
		Body:   strings.NewReader(`{"from":"+15555550100","body":"STOP"}`),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		ExpectedStatus: http.StatusOK,
		ExpectedContent: []string{
			"You have unsubscribed from Liquidity.io marketing SMS",
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			seedPreferences(t, app, "test-org", "user-1", true)
			mountSMSInbound(e.Router, app)
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			rows, err := app.FindAllRecords(schema.Preferences)
			if err != nil {
				t.Fatalf("find prefs: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("expected 1 prefs row")
			}
			if !rows[0].GetBool("marketing_globally_muted") {
				t.Fatalf("marketing_globally_muted not set after STOP")
			}
			cl, err := app.FindAllRecords(schema.ConsentLog)
			if err != nil {
				t.Fatalf("find consent log: %v", err)
			}
			var found bool
			for _, r := range cl {
				if r.GetString("event") == schema.ConsentEventOptOut &&
					r.GetString("channel") == "sms" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("no opt_out SMS consent log row")
			}
		},
	}
	scenario.Test(t)
}

// TestSMSInbound_NonKeywordIgnored — non-STOP body is acked silently.
func TestSMSInbound_NonKeywordIgnored(t *testing.T) {
	t.Parallel()
	registerSchema()

	scenario := tests.ApiScenario{
		Name:   "POST /v1/notify/sms-inbound (chitchat)",
		Method: http.MethodPost,
		URL:    "/v1/notify/sms-inbound",
		Body:   strings.NewReader(`{"from":"+15555550100","body":"thanks"}`),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		ExpectedStatus: http.StatusOK,
		ExpectedContent: []string{`"status":"ignored"`},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedTenant(t, app, "test-org")
			mountSMSInbound(e.Router, app)
		},
	}
	scenario.Test(t)
}

// --- Helpers ---

func nowUTC() time.Time { return time.Now().UTC() }

// seedPreferences inserts a single prefs row for the user. opted=true
// flips promotional ON so the unsubscribe round-trip has something to
// turn off.
func seedPreferences(t testing.TB, app core.App, org, userID string, opted bool) {
	t.Helper()
	col, err := app.FindCollectionByNameOrId(schema.Preferences)
	if err != nil {
		t.Fatalf("find prefs collection: %v", err)
	}
	rec := core.NewRecord(col)
	rec.Set("user_id", userID)
	rec.Set("tenant", org)
	rec.Set("primary_email", "u@example.com")
	rec.Set("primary_phone", "+15555550100")
	rec.Set("legal_email", "u@example.com")
	rec.Set("preferred_channels", []string{"email"})
	rec.Set("realtime_channels", []string{"email"})
	subs := map[string]bool{}
	if opted {
		subs["promotional"] = true
	}
	rec.Set("marketing_subscriptions", subs)
	rec.Set("quiet_hours_start", "21:00")
	rec.Set("quiet_hours_end", "08:00")
	rec.Set("timezone", "America/New_York")
	rec.Set("marketing_globally_muted", false)
	if err := app.Save(rec); err != nil {
		t.Fatalf("save prefs: %v", err)
	}
}

// seedConsentLog inserts a single log row so the audit endpoint has
// something to return.
func seedConsentLog(t testing.TB, app core.App, org, userID string) {
	t.Helper()
	col, err := app.FindCollectionByNameOrId(schema.ConsentLog)
	if err != nil {
		t.Fatalf("find consent log collection: %v", err)
	}
	rec := core.NewRecord(col)
	rec.Set("user_id", userID)
	rec.Set("tenant", org)
	rec.Set("event", schema.ConsentEventOptIn)
	rec.Set("category", "promotional")
	rec.Set("channel", "email")
	if err := app.Save(rec); err != nil {
		t.Fatalf("save consent log: %v", err)
	}
}
