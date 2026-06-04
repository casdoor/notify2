// Package router implements the pure channel-routing function from the
// notification-preferences paper §4. Given a user's resolved
// preferences and a notification category, it returns the destination
// channel set for a single send.
//
// The function is pure: no IO, no DB reads, no clock except the
// caller-supplied `now`. Composability over inheritance — the caller
// resolves prefs (via the preferences CRUD) and then invokes
// DeliveryChannels.
//
// Phase 1 returns Email / SMS / Web only. The Channel type still
// declares WA + Push so the wire shape is forward-compatible, but the
// router never returns them — they are Phase 2 / Phase 3.
package router

import (
	"strings"
	"time"
)

// Category is one of the canonical notification categories from §3 of
// the paper. Categories split into two regulatory regimes:
//
//   - transactional (security, legal, money_movement, trade_execution,
//     account_status, system) — email always fires; SMS/WA/web/push
//     opt-in for real-time courtesy.
//   - marketing (promotional, newsletter, product_update,
//     partner_offer, research) — per-category opt-in required by
//     CAN-SPAM + GDPR + TCPA.
type Category string

const (
	CatSecurity       Category = "security"
	CatLegal          Category = "legal"
	CatMoneyMovement  Category = "money_movement"
	CatTradeExecution Category = "trade_execution"
	CatAccountStatus  Category = "account_status"
	CatSystem         Category = "system"

	CatPromotional   Category = "promotional"
	CatNewsletter    Category = "newsletter"
	CatProductUpdate Category = "product_update"
	CatPartnerOffer  Category = "partner_offer"
	CatResearch      Category = "research"
)

// Channel is one of the canonical destination channels. Email + SMS +
// Web are wired in Phase 1; WA + Push are declared so the wire shape is
// stable but the router never returns them in Phase 1.
type Channel string

const (
	ChEmail Channel = "email"
	ChSMS   Channel = "sms"
	ChWA    Channel = "wa"   // Phase 2 — never returned by Phase 1 router
	ChWeb   Channel = "web"
	ChPush  Channel = "push" // Phase 3 — never returned by Phase 1 router
)

// Preferences is the resolved per-(user, org) state the router reads.
// The CRUD layer materialises this from the notification_preferences
// row; the router itself never touches a database.
type Preferences struct {
	UserID string
	OrgID  string

	PrimaryEmail  string
	BackupEmail   string
	PrimaryPhone  string
	WhatsAppPhone string
	LegalEmail    string

	// PreferredChannels — ordered list the user prefers for non-
	// mandatory notifications.
	PreferredChannels []Channel
	// RealtimeChannels — real-time courtesy channels for transactional
	// categories. The email leg is implicit and always fires for
	// mandatory-email categories regardless of this field.
	RealtimeChannels []Channel
	// MarketingSubscriptions — per-category opt-in. Missing key = false.
	MarketingSubscriptions map[Category]bool

	QuietHoursStart string // "21:00"
	QuietHoursEnd   string // "08:00"
	Timezone        string // IANA, e.g. "America/New_York"

	MarketingGloballyMuted bool
}

// DeliveryChannels picks the destination channel set for a single send.
// Pure: no IO, no DB reads. `now` is the wall-clock instant used to
// evaluate quiet hours; callers pass time.Now().UTC() in production and
// a fixed instant in tests.
//
// Behaviour from §4:
//
//   - Mandatory-email categories: always include email. For real-time
//     transactional categories, additionally include any
//     prefs.RealtimeChannels the matrix allows AND the user has contact
//     for.
//   - Marketing categories: empty set unless the user has explicitly
//     opted in. Respect quiet hours for promotional/partner_offer.
//   - Unknown categories: panic. The paper §4 footer is explicit —
//     "every category must be classed transactional or marketing".
func DeliveryChannels(prefs *Preferences, cat Category, now time.Time) []Channel {
	if prefs == nil {
		return nil
	}
	if isMandatoryEmail(cat) {
		out := []Channel{ChEmail}
		// Real-time courtesy copies. We always include every realtime
		// channel the matrix allows for this category and the user has
		// configured. Email itself is already in the set.
		for _, ch := range dedupe(prefs.RealtimeChannels) {
			if ch == ChEmail {
				continue
			}
			if !matrixAllows(cat, ch) {
				continue
			}
			if !hasContact(prefs, ch) {
				continue
			}
			if !inPhase1(ch) {
				continue
			}
			out = appendUnique(out, ch)
		}
		return out
	}
	if isMarketing(cat) {
		if prefs.MarketingGloballyMuted {
			return nil
		}
		if !prefs.MarketingSubscriptions[cat] {
			return nil
		}
		if inQuietHours(prefs, now) {
			// Promotional + partner_offer are suppressed during quiet
			// hours. Other marketing classes (newsletter, product_update,
			// research) are time-insensitive and continue to deliver.
			if cat == CatPromotional || cat == CatPartnerOffer {
				return nil
			}
		}
		out := make([]Channel, 0, len(prefs.PreferredChannels))
		for _, ch := range dedupe(prefs.PreferredChannels) {
			if !matrixAllows(cat, ch) {
				continue
			}
			if !hasContact(prefs, ch) {
				continue
			}
			if !inPhase1(ch) {
				continue
			}
			out = appendUnique(out, ch)
		}
		return out
	}
	// Defensive: §4 says every category MUST be classed; an unknown
	// one is a programmer error and should crash loudly so it gets
	// fixed before reaching prod.
	panic("router: uncategorised notification: " + string(cat))
}

// isMandatoryEmail returns true for the six transactional categories
// where the email leg always fires (paper §3.1).
func isMandatoryEmail(c Category) bool {
	switch c {
	case CatSecurity, CatLegal, CatMoneyMovement,
		CatTradeExecution, CatAccountStatus, CatSystem:
		return true
	}
	return false
}

// isMarketing returns true for the five marketing categories (paper
// §3.2). isMandatoryEmail + isMarketing partition every Category.
func isMarketing(c Category) bool {
	switch c {
	case CatPromotional, CatNewsletter, CatProductUpdate,
		CatPartnerOffer, CatResearch:
		return true
	}
	return false
}

// matrixAllows encodes the channel matrix from §3 verbatim. The
// (category, channel) pairs marked "--" return false; "always" and
// "opt-in" both return true (callers separately gate on
// preferences/contact). Phase 1 columns: email, sms, web. The wa + push
// columns are encoded too so the matrix stays correct when those
// channels light up in Phase 2/3.
func matrixAllows(cat Category, ch Channel) bool {
	switch cat {
	case CatSecurity:
		switch ch {
		case ChEmail, ChSMS, ChWA, ChWeb, ChPush:
			return true
		}
	case CatLegal:
		switch ch {
		case ChEmail, ChWeb:
			return true
		}
	case CatMoneyMovement:
		switch ch {
		case ChEmail, ChSMS, ChWA, ChWeb, ChPush:
			return true
		}
	case CatTradeExecution:
		switch ch {
		case ChEmail, ChSMS, ChWA, ChWeb, ChPush:
			return true
		}
	case CatAccountStatus:
		switch ch {
		case ChEmail, ChSMS, ChWeb, ChPush:
			return true
		}
	case CatSystem:
		switch ch {
		case ChEmail, ChSMS, ChWeb, ChPush:
			return true
		}
	case CatPromotional:
		switch ch {
		case ChEmail, ChSMS, ChWA, ChWeb, ChPush:
			return true
		}
	case CatNewsletter:
		switch ch {
		case ChEmail, ChWeb:
			return true
		}
	case CatProductUpdate:
		switch ch {
		case ChEmail, ChWeb, ChPush:
			return true
		}
	case CatPartnerOffer:
		switch ch {
		case ChEmail, ChWA, ChWeb:
			return true
		}
	case CatResearch:
		switch ch {
		case ChEmail, ChWeb:
			return true
		}
	}
	return false
}

// hasContact returns true when the user has configured a destination
// for the channel.
func hasContact(p *Preferences, ch Channel) bool {
	switch ch {
	case ChEmail:
		return strings.TrimSpace(p.PrimaryEmail) != ""
	case ChSMS:
		return strings.TrimSpace(p.PrimaryPhone) != ""
	case ChWA:
		return strings.TrimSpace(p.WhatsAppPhone) != ""
	case ChWeb:
		// In-app inbox is always reachable for an authenticated user.
		// The web channel is zero-cost-of-delivery and has no compliance
		// surface (paper §3).
		return true
	case ChPush:
		// Phase 3 — no contact field today.
		return false
	}
	return false
}

// inPhase1 keeps Phase 2 (WhatsApp) and Phase 3 (push) channels out of
// the returned set even when prefs reference them. The matrix still
// encodes those columns so the router stays correct when later phases
// flip the gate.
func inPhase1(ch Channel) bool {
	switch ch {
	case ChEmail, ChSMS, ChWeb:
		return true
	}
	return false
}

// inQuietHours evaluates whether `now` falls inside the user's quiet
// hours window (TCPA: 8am–9pm recipient local). Empty fields disable
// the window — paper default is 21:00 → 08:00 in America/New_York,
// which the CRUD layer fills in on first create.
func inQuietHours(p *Preferences, now time.Time) bool {
	startH, startM, ok := parseHM(p.QuietHoursStart)
	if !ok {
		return false
	}
	endH, endM, ok := parseHM(p.QuietHoursEnd)
	if !ok {
		return false
	}
	loc := loadTZ(p.Timezone)
	local := now.In(loc)
	startMin := startH*60 + startM
	endMin := endH*60 + endM
	nowMin := local.Hour()*60 + local.Minute()

	// Window may wrap midnight (e.g. 21:00 → 08:00).
	if startMin == endMin {
		return false
	}
	if startMin < endMin {
		return nowMin >= startMin && nowMin < endMin
	}
	return nowMin >= startMin || nowMin < endMin
}

// parseHM parses "HH:MM" into 0..23 / 0..59. ok=false on bad input —
// caller treats that as "no quiet hours window".
func parseHM(s string) (int, int, bool) {
	s = strings.TrimSpace(s)
	if len(s) != 4 && len(s) != 5 {
		return 0, 0, false
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	h, ok1 := atoi(parts[0])
	m, ok2 := atoi(parts[1])
	if !ok1 || !ok2 || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

// atoi is a tiny non-allocating decimal parser; strconv.Atoi pulls in
// reflect via strconv.IntSize on some toolchains and we want this loop
// to stay allocation-free at the hot quiet-hours check.
func atoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// loadTZ resolves a tz name to a *time.Location. Falls back to
// America/New_York (paper default) and then UTC so a bad tz never
// crashes the router.
func loadTZ(tz string) *time.Location {
	if tz == "" {
		tz = "America/New_York"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.UTC
	}
	return loc
}

// dedupe collapses a channel slice, preserving order. Defensive against
// caller-supplied duplicates without rewriting the input.
func dedupe(xs []Channel) []Channel {
	if len(xs) <= 1 {
		return xs
	}
	out := make([]Channel, 0, len(xs))
	seen := make(map[Channel]struct{}, len(xs))
	for _, x := range xs {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

// appendUnique keeps the result slice unique without re-allocating a
// map on every call (the result set is small — at most 5 channels).
func appendUnique(xs []Channel, x Channel) []Channel {
	for _, e := range xs {
		if e == x {
			return xs
		}
	}
	return append(xs, x)
}
