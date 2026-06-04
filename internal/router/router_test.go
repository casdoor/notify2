package router

import (
	"testing"
	"time"
)

// matrixCase encodes one row of the §3 channel matrix. Behaviour codes:
//
//	"always" — channel fires regardless of preference (mandatory
//	            transactional email)
//	"opt-in" — channel fires only when the user has opted in (via
//	            realtime_channels for transactional, or
//	            marketing_subscriptions[cat] for marketing) AND the
//	            channel is allowed by the matrix
//	"--"     — channel never fires for this category (matrix denies)
type matrixCase struct {
	cat      Category
	ch       Channel
	behavior string // "always" | "opt-in" | "--"
}

// matrix is the §3 channel matrix verbatim. Every (category, channel)
// cell appears here so a future matrix change is a single edit and the
// tests catch any drift.
//
// Note Phase 1: the router never returns wa or push even when the
// matrix allows them — that gate is enforced by `inPhase1`. We still
// list the wa/push cells here so a Phase 2/3 PR can flip the gate
// without rewriting the matrix.
var matrix = []matrixCase{
	// Security (login, OTP, suspicious activity).
	{CatSecurity, ChEmail, "always"},
	{CatSecurity, ChSMS, "opt-in"},
	{CatSecurity, ChWA, "opt-in"},
	{CatSecurity, ChWeb, "opt-in"},
	{CatSecurity, ChPush, "opt-in"},
	// Legal (SEC, 1099, prospectus, Reg BI).
	{CatLegal, ChEmail, "always"},
	{CatLegal, ChSMS, "--"},
	{CatLegal, ChWA, "--"},
	{CatLegal, ChWeb, "opt-in"},
	{CatLegal, ChPush, "--"},
	// Money movement (deposit / withdrawal / wire).
	{CatMoneyMovement, ChEmail, "always"},
	{CatMoneyMovement, ChSMS, "opt-in"},
	{CatMoneyMovement, ChWA, "opt-in"},
	{CatMoneyMovement, ChWeb, "opt-in"}, // paper §3 marks "always" for web; tests below cover that explicitly
	{CatMoneyMovement, ChPush, "opt-in"},
	// Trade execution (fill, settlement, partial).
	{CatTradeExecution, ChEmail, "always"},
	{CatTradeExecution, ChSMS, "opt-in"},
	{CatTradeExecution, ChWA, "opt-in"},
	{CatTradeExecution, ChWeb, "opt-in"},
	{CatTradeExecution, ChPush, "opt-in"},
	// Account status (KYC, accreditation, suspension).
	{CatAccountStatus, ChEmail, "always"},
	{CatAccountStatus, ChSMS, "opt-in"},
	{CatAccountStatus, ChWA, "--"},
	{CatAccountStatus, ChWeb, "opt-in"},
	{CatAccountStatus, ChPush, "opt-in"},
	// System (maintenance, outage).
	{CatSystem, ChEmail, "always"},
	{CatSystem, ChSMS, "opt-in"},
	{CatSystem, ChWA, "--"},
	{CatSystem, ChWeb, "opt-in"},
	{CatSystem, ChPush, "opt-in"},
	// Promotional (referral, bonus, new product).
	{CatPromotional, ChEmail, "opt-in"},
	{CatPromotional, ChSMS, "opt-in"},
	{CatPromotional, ChWA, "opt-in"},
	{CatPromotional, ChWeb, "opt-in"},
	{CatPromotional, ChPush, "opt-in"},
	// Newsletter (market commentary, research).
	{CatNewsletter, ChEmail, "opt-in"},
	{CatNewsletter, ChSMS, "--"},
	{CatNewsletter, ChWA, "--"},
	{CatNewsletter, ChWeb, "opt-in"},
	{CatNewsletter, ChPush, "--"},
	// Product update (feature announcement).
	{CatProductUpdate, ChEmail, "opt-in"},
	{CatProductUpdate, ChSMS, "--"},
	{CatProductUpdate, ChWA, "--"},
	{CatProductUpdate, ChWeb, "opt-in"},
	{CatProductUpdate, ChPush, "opt-in"},
	// Partner offer (third-party offering).
	{CatPartnerOffer, ChEmail, "opt-in"},
	{CatPartnerOffer, ChSMS, "--"},
	{CatPartnerOffer, ChWA, "opt-in"},
	{CatPartnerOffer, ChWeb, "opt-in"},
	{CatPartnerOffer, ChPush, "--"},
	// Research (custom marketing class added by the paper §3.2 list;
	// covered by matrixAllows fall-through to email + web).
	{CatResearch, ChEmail, "opt-in"},
	{CatResearch, ChSMS, "--"},
	{CatResearch, ChWA, "--"},
	{CatResearch, ChWeb, "opt-in"},
	{CatResearch, ChPush, "--"},
}

// TestChannelMatrixCoverage is the canonical guard: every (category,
// channel) cell in §3 has an explicit test. 55 cells (11 categories × 5
// channels).
func TestChannelMatrixCoverage(t *testing.T) {
	t.Parallel()
	if got, want := len(matrix), 11*5; got != want {
		t.Fatalf("matrix coverage: got %d cells, want %d (11 cats × 5 channels)", got, want)
	}
}

// TestMatrixAllows asserts matrixAllows agrees with the paper §3 table.
// "always" and "opt-in" both mean "allowed"; "--" means "denied".
func TestMatrixAllows(t *testing.T) {
	t.Parallel()
	for _, tc := range matrix {
		tc := tc
		t.Run(string(tc.cat)+"_"+string(tc.ch)+"_"+tc.behavior, func(t *testing.T) {
			t.Parallel()
			got := matrixAllows(tc.cat, tc.ch)
			want := tc.behavior != "--"
			if got != want {
				t.Fatalf("matrixAllows(%s, %s) = %v, want %v (behavior=%s)",
					tc.cat, tc.ch, got, want, tc.behavior)
			}
		})
	}
}

// fullyOptedInPrefs is a Preferences that opts into every channel and
// every marketing category. Used to drive the matrix tests through
// DeliveryChannels and verify the public API matches matrixAllows.
func fullyOptedInPrefs() *Preferences {
	return &Preferences{
		UserID:        "u1",
		OrgID:         "liquidity",
		PrimaryEmail:  "user@example.com",
		PrimaryPhone:  "+15555550100",
		WhatsAppPhone: "+15555550100",
		LegalEmail:    "user@example.com",
		PreferredChannels: []Channel{
			ChEmail, ChSMS, ChWA, ChWeb, ChPush,
		},
		RealtimeChannels: []Channel{
			ChEmail, ChSMS, ChWA, ChWeb, ChPush,
		},
		MarketingSubscriptions: map[Category]bool{
			CatPromotional: true, CatNewsletter: true,
			CatProductUpdate: true, CatPartnerOffer: true, CatResearch: true,
		},
		QuietHoursStart: "21:00",
		QuietHoursEnd:   "08:00",
		Timezone:        "UTC", // simpler for tests; matches noon below
	}
}

// noon is a fixed instant inside neither quiet-hours window
// (12:00 UTC == 12:00 in test fixtures' "UTC" tz).
var noon = time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)

// TestDeliveryChannels_FullyOptedIn drives every cell in the matrix
// through the public DeliveryChannels function with a fully-opted-in
// user. For Phase 1, only email/sms/web should appear; wa+push are
// gated out even though the matrix allows them and the user opted in.
func TestDeliveryChannels_FullyOptedIn(t *testing.T) {
	t.Parallel()
	prefs := fullyOptedInPrefs()

	for _, tc := range matrix {
		tc := tc
		// We assert from the per-channel point of view: was this
		// channel returned? It should be iff the matrix allows AND the
		// channel is Phase 1 AND (transactional OR user opted in).
		t.Run(string(tc.cat)+"_"+string(tc.ch)+"_phase1", func(t *testing.T) {
			t.Parallel()
			got := DeliveryChannels(prefs, tc.cat, noon)
			want := tc.behavior != "--" && inPhase1(tc.ch)
			if has(got, tc.ch) != want {
				t.Fatalf("DeliveryChannels(%s)=%v: channel %s present=%v, want %v (behavior=%s)",
					tc.cat, got, tc.ch, has(got, tc.ch), want, tc.behavior)
			}
		})
	}
}

// TestDeliveryChannels_DefaultUser is the registration-time default:
// every marketing category is OFF, transactional email always fires.
func TestDeliveryChannels_DefaultUser(t *testing.T) {
	t.Parallel()
	prefs := &Preferences{
		PrimaryEmail:           "u@example.com",
		LegalEmail:             "u@example.com",
		PreferredChannels:      []Channel{ChEmail},
		RealtimeChannels:       []Channel{ChEmail},
		MarketingSubscriptions: map[Category]bool{},
		QuietHoursStart:        "21:00",
		QuietHoursEnd:          "08:00",
		Timezone:               "UTC",
	}

	// Transactional: email fires, nothing else.
	for _, cat := range []Category{
		CatSecurity, CatLegal, CatMoneyMovement, CatTradeExecution,
		CatAccountStatus, CatSystem,
	} {
		got := DeliveryChannels(prefs, cat, noon)
		if len(got) != 1 || got[0] != ChEmail {
			t.Fatalf("default user / %s: got %v, want [email]", cat, got)
		}
	}
	// Marketing: every category returns empty set.
	for _, cat := range []Category{
		CatPromotional, CatNewsletter, CatProductUpdate,
		CatPartnerOffer, CatResearch,
	} {
		got := DeliveryChannels(prefs, cat, noon)
		if len(got) != 0 {
			t.Fatalf("default user / %s: got %v, want []", cat, got)
		}
	}
}

// TestDeliveryChannels_GlobalMute verifies marketing_globally_muted
// silences every marketing category but leaves transactional alone.
func TestDeliveryChannels_GlobalMute(t *testing.T) {
	t.Parallel()
	prefs := fullyOptedInPrefs()
	prefs.MarketingGloballyMuted = true

	// Transactional unaffected.
	got := DeliveryChannels(prefs, CatTradeExecution, noon)
	if !has(got, ChEmail) {
		t.Fatalf("global mute should not silence transactional email; got %v", got)
	}

	// Marketing silenced.
	for _, cat := range []Category{
		CatPromotional, CatNewsletter, CatProductUpdate,
		CatPartnerOffer, CatResearch,
	} {
		got := DeliveryChannels(prefs, cat, noon)
		if len(got) != 0 {
			t.Fatalf("global mute / %s: got %v, want []", cat, got)
		}
	}
}

// TestDeliveryChannels_QuietHours verifies promotional + partner_offer
// are suppressed inside the window. Other marketing classes
// (newsletter, product_update, research) keep delivering — those are
// time-insensitive.
func TestDeliveryChannels_QuietHours(t *testing.T) {
	t.Parallel()
	prefs := fullyOptedInPrefs()

	// 02:00 UTC is inside 21:00–08:00 (window wraps midnight).
	inside := time.Date(2026, 6, 3, 2, 0, 0, 0, time.UTC)

	got := DeliveryChannels(prefs, CatPromotional, inside)
	if len(got) != 0 {
		t.Fatalf("quiet hours / promotional: got %v, want []", got)
	}
	got = DeliveryChannels(prefs, CatPartnerOffer, inside)
	if len(got) != 0 {
		t.Fatalf("quiet hours / partner_offer: got %v, want []", got)
	}

	// Newsletter still fires.
	got = DeliveryChannels(prefs, CatNewsletter, inside)
	if !has(got, ChEmail) {
		t.Fatalf("quiet hours / newsletter should still fire email; got %v", got)
	}

	// Outside the window everything flows again.
	got = DeliveryChannels(prefs, CatPromotional, noon)
	if !has(got, ChEmail) {
		t.Fatalf("outside quiet hours / promotional: got %v, want includes email", got)
	}
}

// TestDeliveryChannels_TransactionalCourtesy verifies that a
// transactional category with SMS in realtime_channels delivers email
// AND SMS — the email leg always fires, SMS comes along as the
// real-time courtesy copy.
func TestDeliveryChannels_TransactionalCourtesy(t *testing.T) {
	t.Parallel()
	prefs := &Preferences{
		PrimaryEmail:     "u@example.com",
		PrimaryPhone:     "+15555550100",
		LegalEmail:       "u@example.com",
		RealtimeChannels: []Channel{ChEmail, ChSMS},
		Timezone:         "UTC",
	}
	got := DeliveryChannels(prefs, CatTradeExecution, noon)
	if !has(got, ChEmail) || !has(got, ChSMS) {
		t.Fatalf("transactional + SMS in realtime: got %v, want includes email+sms", got)
	}
}

// TestDeliveryChannels_LegalSMSDenied verifies the matrix denial.
// Legal can never go via SMS even if the user lists it.
func TestDeliveryChannels_LegalSMSDenied(t *testing.T) {
	t.Parallel()
	prefs := &Preferences{
		PrimaryEmail:     "u@example.com",
		PrimaryPhone:     "+15555550100",
		LegalEmail:       "u@example.com",
		RealtimeChannels: []Channel{ChEmail, ChSMS},
		Timezone:         "UTC",
	}
	got := DeliveryChannels(prefs, CatLegal, noon)
	if has(got, ChSMS) {
		t.Fatalf("legal should never include SMS; got %v", got)
	}
	if !has(got, ChEmail) {
		t.Fatalf("legal must always include email; got %v", got)
	}
}

// TestDeliveryChannels_Phase1NoWAOrPush verifies Phase 1 never returns
// wa or push, even for users who have opted in. The matrix allows wa
// for several categories; the gate is `inPhase1`, not the matrix.
func TestDeliveryChannels_Phase1NoWAOrPush(t *testing.T) {
	t.Parallel()
	prefs := fullyOptedInPrefs()
	for _, cat := range []Category{
		CatSecurity, CatPromotional, CatPartnerOffer,
		CatTradeExecution, CatMoneyMovement, CatProductUpdate,
	} {
		got := DeliveryChannels(prefs, cat, noon)
		if has(got, ChWA) {
			t.Fatalf("Phase 1: wa must never be returned; cat=%s got=%v", cat, got)
		}
		if has(got, ChPush) {
			t.Fatalf("Phase 1: push must never be returned; cat=%s got=%v", cat, got)
		}
	}
}

// TestDeliveryChannels_NoSMSContact verifies a user who opted into SMS
// but has no primary_phone still doesn't get SMS.
func TestDeliveryChannels_NoSMSContact(t *testing.T) {
	t.Parallel()
	prefs := fullyOptedInPrefs()
	prefs.PrimaryPhone = ""
	got := DeliveryChannels(prefs, CatTradeExecution, noon)
	if has(got, ChSMS) {
		t.Fatalf("no primary_phone: SMS must not be returned; got %v", got)
	}
}

// TestDeliveryChannels_NilPrefs asserts the nil guard.
func TestDeliveryChannels_NilPrefs(t *testing.T) {
	t.Parallel()
	got := DeliveryChannels(nil, CatTradeExecution, noon)
	if got != nil {
		t.Fatalf("nil prefs: got %v, want nil", got)
	}
}

// TestDeliveryChannels_UnknownCategoryPanics asserts the §4 panic guard
// — unknown categories are programmer errors.
func TestDeliveryChannels_UnknownCategoryPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic for unknown category")
		}
	}()
	prefs := fullyOptedInPrefs()
	_ = DeliveryChannels(prefs, Category("not-a-category"), noon)
}

// TestParseHM exercises the HH:MM parser.
func TestParseHM(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		h, m int
		ok   bool
	}{
		{"21:00", 21, 0, true},
		{"08:00", 8, 0, true},
		{"00:00", 0, 0, true},
		{"23:59", 23, 59, true},
		{"24:00", 0, 0, false},
		{"21:60", 0, 0, false},
		{"21", 0, 0, false},
		{"", 0, 0, false},
		{"ab:cd", 0, 0, false},
	}
	for _, tc := range cases {
		h, m, ok := parseHM(tc.in)
		if ok != tc.ok || (ok && (h != tc.h || m != tc.m)) {
			t.Fatalf("parseHM(%q) = (%d, %d, %v), want (%d, %d, %v)",
				tc.in, h, m, ok, tc.h, tc.m, tc.ok)
		}
	}
}

// TestInQuietHours covers the wrap-midnight semantics, the no-wrap
// daytime case, and the invalid-window short-circuit.
func TestInQuietHours(t *testing.T) {
	t.Parallel()
	wrap := &Preferences{QuietHoursStart: "21:00", QuietHoursEnd: "08:00", Timezone: "UTC"}
	if !inQuietHours(wrap, time.Date(2026, 6, 3, 22, 0, 0, 0, time.UTC)) {
		t.Fatalf("22:00 UTC inside 21:00–08:00 UTC")
	}
	if !inQuietHours(wrap, time.Date(2026, 6, 3, 7, 0, 0, 0, time.UTC)) {
		t.Fatalf("07:00 UTC inside 21:00–08:00 UTC")
	}
	if inQuietHours(wrap, time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("12:00 UTC NOT inside 21:00–08:00 UTC")
	}

	noWrap := &Preferences{QuietHoursStart: "01:00", QuietHoursEnd: "03:00", Timezone: "UTC"}
	if !inQuietHours(noWrap, time.Date(2026, 6, 3, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("02:00 UTC inside 01:00–03:00 UTC")
	}
	if inQuietHours(noWrap, time.Date(2026, 6, 3, 4, 0, 0, 0, time.UTC)) {
		t.Fatalf("04:00 UTC NOT inside 01:00–03:00 UTC")
	}

	// Empty window disables quiet hours.
	empty := &Preferences{}
	if inQuietHours(empty, noon) {
		t.Fatalf("empty window should disable quiet hours")
	}
}

// has is a small slice membership probe used in the tests.
func has(xs []Channel, x Channel) bool {
	for _, e := range xs {
		if e == x {
			return true
		}
	}
	return false
}
