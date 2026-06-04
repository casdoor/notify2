// Package preferences holds the wire shape + validation + row-mapper
// for the notification_preferences collection.
//
// This package is intentionally separate from internal/router/ because
// the router is a pure function operating on a resolved Preferences
// struct, while this package owns the persistence + JSON marshalling
// boilerplate. Keeping them apart preserves the router's
// no-dependencies-but-time discipline.
package preferences

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/hanzoai/base/core"

	"github.com/hanzoai/notify/internal/router"
)

// Wire is the JSON shape returned by GET /v1/notify/preferences and
// accepted by PUT /v1/notify/preferences. Field order + names match
// §2.1 of the notification-preferences paper.
type Wire struct {
	ID     string `json:"id,omitempty"`
	UserID string `json:"user_id"`
	OrgID  string `json:"org_id"`

	PrimaryEmail  string `json:"primary_email"`
	BackupEmail   string `json:"backup_email,omitempty"`
	PrimaryPhone  string `json:"primary_phone,omitempty"`
	WhatsAppPhone string `json:"whatsapp_phone,omitempty"`
	LegalEmail    string `json:"legal_email"`

	PreferredChannels      []string        `json:"preferred_channels"`
	RealtimeChannels       []string        `json:"realtime_channels"`
	MarketingSubscriptions map[string]bool `json:"marketing_subscriptions"`

	QuietHoursStart string `json:"quiet_hours_start"`
	QuietHoursEnd   string `json:"quiet_hours_end"`
	Timezone        string `json:"timezone"`

	MarketingGloballyMuted bool `json:"marketing_globally_muted"`

	Created string `json:"created,omitempty"`
	Updated string `json:"updated,omitempty"`
}

// Validate enforces the structural rules from §2: required emails,
// HH:MM format, known channel ids, known marketing category ids. Bad
// input is rejected at the API boundary — the persistence layer trusts
// what it stores.
func Validate(w *Wire) error {
	if w == nil {
		return errors.New("preferences: nil body")
	}
	if strings.TrimSpace(w.PrimaryEmail) == "" {
		return errors.New("primary_email is required")
	}
	if _, err := mail.ParseAddress(w.PrimaryEmail); err != nil {
		return fmt.Errorf("primary_email invalid: %w", err)
	}
	if w.BackupEmail != "" {
		if _, err := mail.ParseAddress(w.BackupEmail); err != nil {
			return fmt.Errorf("backup_email invalid: %w", err)
		}
	}
	if strings.TrimSpace(w.LegalEmail) == "" {
		return errors.New("legal_email is required")
	}
	if _, err := mail.ParseAddress(w.LegalEmail); err != nil {
		return fmt.Errorf("legal_email invalid: %w", err)
	}
	if w.PrimaryPhone != "" && !looksLikeE164(w.PrimaryPhone) {
		return errors.New("primary_phone must be E.164 (e.g. +15555550100)")
	}
	if w.WhatsAppPhone != "" && !looksLikeE164(w.WhatsAppPhone) {
		return errors.New("whatsapp_phone must be E.164")
	}
	if w.QuietHoursStart != "" && !looksLikeHM(w.QuietHoursStart) {
		return errors.New("quiet_hours_start must be HH:MM")
	}
	if w.QuietHoursEnd != "" && !looksLikeHM(w.QuietHoursEnd) {
		return errors.New("quiet_hours_end must be HH:MM")
	}
	if strings.TrimSpace(w.Timezone) == "" {
		return errors.New("timezone is required")
	}
	for _, ch := range w.PreferredChannels {
		if !knownChannel(ch) {
			return fmt.Errorf("unknown channel in preferred_channels: %q", ch)
		}
	}
	for _, ch := range w.RealtimeChannels {
		if !knownChannel(ch) {
			return fmt.Errorf("unknown channel in realtime_channels: %q", ch)
		}
	}
	for cat := range w.MarketingSubscriptions {
		if !knownMarketingCategory(cat) {
			return fmt.Errorf("unknown marketing category: %q", cat)
		}
	}
	return nil
}

// ApplyWire writes the Wire fields into the *core.Record. user_id /
// tenant are forced by the caller so this only writes the mutable
// columns.
func ApplyWire(rec *core.Record, w *Wire) error {
	if rec == nil || w == nil {
		return errors.New("preferences: nil record or wire")
	}
	rec.Set("user_id", w.UserID)
	rec.Set("tenant", w.OrgID)
	rec.Set("primary_email", w.PrimaryEmail)
	rec.Set("backup_email", w.BackupEmail)
	rec.Set("primary_phone", w.PrimaryPhone)
	rec.Set("whatsapp_phone", w.WhatsAppPhone)
	rec.Set("legal_email", w.LegalEmail)
	rec.Set("preferred_channels", nonNilStrings(w.PreferredChannels))
	rec.Set("realtime_channels", nonNilStrings(w.RealtimeChannels))
	rec.Set("marketing_subscriptions", nonNilMarketing(w.MarketingSubscriptions))
	rec.Set("quiet_hours_start", w.QuietHoursStart)
	rec.Set("quiet_hours_end", w.QuietHoursEnd)
	rec.Set("timezone", w.Timezone)
	rec.Set("marketing_globally_muted", w.MarketingGloballyMuted)
	return nil
}

// ToWire materialises a Wire from a *core.Record. JSON blobs are
// parsed defensively — a corrupt blob falls back to an empty slice/map
// rather than failing the read.
func ToWire(rec *core.Record) Wire {
	if rec == nil {
		return Wire{}
	}
	return Wire{
		ID:                     rec.Id,
		UserID:                 rec.GetString("user_id"),
		OrgID:                  rec.GetString("tenant"),
		PrimaryEmail:           rec.GetString("primary_email"),
		BackupEmail:            rec.GetString("backup_email"),
		PrimaryPhone:           rec.GetString("primary_phone"),
		WhatsAppPhone:          rec.GetString("whatsapp_phone"),
		LegalEmail:             rec.GetString("legal_email"),
		PreferredChannels:      parseStringSlice(rec.GetString("preferred_channels")),
		RealtimeChannels:       parseStringSlice(rec.GetString("realtime_channels")),
		MarketingSubscriptions: parseSubscriptions(rec.GetString("marketing_subscriptions")),
		QuietHoursStart:        rec.GetString("quiet_hours_start"),
		QuietHoursEnd:          rec.GetString("quiet_hours_end"),
		Timezone:               rec.GetString("timezone"),
		MarketingGloballyMuted: rec.GetBool("marketing_globally_muted"),
		Created:                rec.GetString("created"),
		Updated:                rec.GetString("updated"),
	}
}

// ToRouterPreferences converts a Wire into the router's Preferences
// struct. Caller of router.DeliveryChannels uses this to bridge the
// persistence and routing layers.
func ToRouterPreferences(w Wire) *router.Preferences {
	pc := make([]router.Channel, 0, len(w.PreferredChannels))
	for _, c := range w.PreferredChannels {
		pc = append(pc, router.Channel(c))
	}
	rc := make([]router.Channel, 0, len(w.RealtimeChannels))
	for _, c := range w.RealtimeChannels {
		rc = append(rc, router.Channel(c))
	}
	ms := make(map[router.Category]bool, len(w.MarketingSubscriptions))
	for k, v := range w.MarketingSubscriptions {
		ms[router.Category(k)] = v
	}
	return &router.Preferences{
		UserID:                 w.UserID,
		OrgID:                  w.OrgID,
		PrimaryEmail:           w.PrimaryEmail,
		BackupEmail:            w.BackupEmail,
		PrimaryPhone:           w.PrimaryPhone,
		WhatsAppPhone:          w.WhatsAppPhone,
		LegalEmail:             w.LegalEmail,
		PreferredChannels:      pc,
		RealtimeChannels:       rc,
		MarketingSubscriptions: ms,
		QuietHoursStart:        w.QuietHoursStart,
		QuietHoursEnd:          w.QuietHoursEnd,
		Timezone:               w.Timezone,
		MarketingGloballyMuted: w.MarketingGloballyMuted,
	}
}

// knownChannel filters PUT input to the set Phase 1+ understands.
// wa+push are accepted on the wire (so the API survives the Phase 2
// flip) but the router gates them off.
func knownChannel(c string) bool {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "email", "sms", "wa", "web", "push":
		return true
	}
	return false
}

// knownMarketingCategory enumerates the §3.2 marketing set. Transactional
// categories MUST NOT appear in marketing_subscriptions; the matrix
// already forces them on by regulation.
func knownMarketingCategory(c string) bool {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "promotional", "newsletter", "product_update", "partner_offer", "research":
		return true
	}
	return false
}

// looksLikeHM checks "HH:MM". The router parser is the actual truth
// source for quiet-hours math; this is a fast input gate.
func looksLikeHM(s string) bool {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
	if len(parts) != 2 {
		return false
	}
	h, m := parts[0], parts[1]
	if len(h) != 2 || len(m) != 2 {
		return false
	}
	for _, c := range h + m {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// e164 matches the canonical international phone number shape.
var e164 = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

func looksLikeE164(s string) bool {
	return e164.MatchString(strings.TrimSpace(s))
}

// nonNilStrings collapses nil to empty slice so the JSON encoder emits
// `[]` rather than `null` — matches the schema's default.
func nonNilStrings(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

// nonNilMarketing mirrors nonNilStrings for the marketing map.
func nonNilMarketing(m map[string]bool) map[string]bool {
	if m == nil {
		return map[string]bool{}
	}
	return m
}

// parseStringSlice decodes the JSON blob stored in preferred_channels /
// realtime_channels. Empty / corrupt → empty slice.
func parseStringSlice(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	var xs []string
	if err := json.Unmarshal([]byte(raw), &xs); err != nil {
		return []string{}
	}
	return xs
}

// parseSubscriptions decodes the JSON map stored in
// marketing_subscriptions. Empty / corrupt → empty map.
func parseSubscriptions(raw string) map[string]bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]bool{}
	}
	var m map[string]bool
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return map[string]bool{}
	}
	return m
}
