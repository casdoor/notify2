package preferences

import (
	"strings"
	"testing"
)

// TestValidateRequiredEmails — primary + legal email required.
func TestValidateRequiredEmails(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mut  func(*Wire)
		bad  string
	}{
		{"missing primary", func(w *Wire) { w.PrimaryEmail = "" }, "primary_email"},
		{"bad primary", func(w *Wire) { w.PrimaryEmail = "not-an-email" }, "primary_email"},
		{"missing legal", func(w *Wire) { w.LegalEmail = "" }, "legal_email"},
		{"bad backup", func(w *Wire) { w.BackupEmail = "@@" }, "backup_email"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := goodWire()
			tc.mut(w)
			err := Validate(w)
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.bad) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.bad)
			}
		})
	}
}

// TestValidatePhones — phones must be E.164 when present.
func TestValidatePhones(t *testing.T) {
	t.Parallel()
	w := goodWire()
	w.PrimaryPhone = "555-0100"
	if err := Validate(w); err == nil {
		t.Fatalf("expected E.164 rejection for primary_phone")
	}
	w = goodWire()
	w.WhatsAppPhone = "555-0100"
	if err := Validate(w); err == nil {
		t.Fatalf("expected E.164 rejection for whatsapp_phone")
	}
	w = goodWire()
	w.PrimaryPhone = "+15555550100"
	w.WhatsAppPhone = "+15555550100"
	if err := Validate(w); err != nil {
		t.Fatalf("E.164 phones should pass: %v", err)
	}
}

// TestValidateChannels — unknown channel names are rejected.
func TestValidateChannels(t *testing.T) {
	t.Parallel()
	w := goodWire()
	w.PreferredChannels = []string{"email", "carrier-pigeon"}
	if err := Validate(w); err == nil {
		t.Fatalf("unknown channel must be rejected")
	}
	w = goodWire()
	w.PreferredChannels = []string{"email", "sms", "wa", "web", "push"}
	if err := Validate(w); err != nil {
		t.Fatalf("known channels should pass: %v", err)
	}
}

// TestValidateMarketingCategories — unknown marketing categories are
// rejected; transactional category names are NOT accepted in
// marketing_subscriptions (they get on by regulation, not opt-in).
func TestValidateMarketingCategories(t *testing.T) {
	t.Parallel()
	w := goodWire()
	w.MarketingSubscriptions = map[string]bool{"trade_execution": true}
	if err := Validate(w); err == nil {
		t.Fatalf("transactional category in marketing must be rejected")
	}
	w = goodWire()
	w.MarketingSubscriptions = map[string]bool{
		"promotional":    true,
		"newsletter":     true,
		"product_update": true,
		"partner_offer":  false,
		"research":       true,
	}
	if err := Validate(w); err != nil {
		t.Fatalf("known marketing categories should pass: %v", err)
	}
}

// TestValidateQuietHoursFormat — empty allowed; bad format rejected.
func TestValidateQuietHoursFormat(t *testing.T) {
	t.Parallel()
	w := goodWire()
	w.QuietHoursStart = "9pm"
	if err := Validate(w); err == nil {
		t.Fatalf("bad quiet_hours_start format must be rejected")
	}
	w = goodWire()
	w.QuietHoursStart = "21:00"
	w.QuietHoursEnd = "08:00"
	if err := Validate(w); err != nil {
		t.Fatalf("HH:MM quiet hours should pass: %v", err)
	}
	w = goodWire()
	w.QuietHoursStart = ""
	w.QuietHoursEnd = ""
	if err := Validate(w); err != nil {
		t.Fatalf("empty quiet hours allowed: %v", err)
	}
}

// TestToRouterPreferences — the bridge to the router package preserves
// every field.
func TestToRouterPreferences(t *testing.T) {
	t.Parallel()
	w := goodWire()
	w.PreferredChannels = []string{"email", "sms"}
	w.RealtimeChannels = []string{"email"}
	w.MarketingSubscriptions = map[string]bool{"promotional": true}
	rp := ToRouterPreferences(*w)
	if rp.PrimaryEmail != w.PrimaryEmail || rp.LegalEmail != w.LegalEmail {
		t.Fatalf("emails not preserved")
	}
	if len(rp.PreferredChannels) != 2 || string(rp.PreferredChannels[0]) != "email" {
		t.Fatalf("preferred channels not preserved: %v", rp.PreferredChannels)
	}
	if !rp.MarketingSubscriptions["promotional"] {
		t.Fatalf("marketing_subscriptions not preserved")
	}
}

// goodWire returns a valid Wire for tests to mutate.
func goodWire() *Wire {
	return &Wire{
		UserID:                 "u1",
		OrgID:                  "liquidity",
		PrimaryEmail:           "u@example.com",
		LegalEmail:             "u@example.com",
		Timezone:               "America/New_York",
		PreferredChannels:      []string{"email"},
		RealtimeChannels:       []string{"email"},
		MarketingSubscriptions: map[string]bool{},
	}
}
