// Package metering writes per-send ledger rows and exposes a query for
// the billing surface. Rows land in the `meter` collection synchronously
// (one INSERT per send); the optional rollup goroutine sweeps them
// daily into S3 prefixed by tenant.
//
// Two cost numbers per row:
//
//	vendor_cost_micros — what the provider charged Hanzo (Plivo, Twilio, …)
//	retail_price_micros — what Hanzo charges the tenant
//
// The markup factor lives in the catalog, not here — metering only
// persists the snapshot the caller passes in.
package metering

import (
	"errors"
	"fmt"

	"github.com/hanzoai/base/core"
	"github.com/hanzoai/dbx"

	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/pkg/types"
)

// Record is the input shape callers pass to Write — a flat, pre-priced
// row ready for insertion.
type Record struct {
	TenantSlug        string
	Event             string
	Provider          string
	Channel           types.Channel
	Units             int
	VendorCostMicros  int64
	RetailPriceMicros int64
	MessageID         string
}

// Write inserts one meter row. Returns the persisted record id or an
// error. Idempotency must be handled at the caller layer — the meter
// is append-only and does not dedup.
func Write(app core.App, rec Record) (string, error) {
	if rec.TenantSlug == "" || rec.Provider == "" || rec.Channel == "" {
		return "", errors.New("metering: tenant, provider, channel are required")
	}
	col, err := app.FindCollectionByNameOrId(schema.Meter)
	if err != nil {
		return "", fmt.Errorf("metering: find collection: %w", err)
	}
	row := core.NewRecord(col)
	row.Set("tenant", rec.TenantSlug)
	row.Set("event", rec.Event)
	row.Set("provider", rec.Provider)
	row.Set("channel", string(rec.Channel))
	row.Set("units", rec.Units)
	row.Set("vendor_cost_micros", rec.VendorCostMicros)
	row.Set("retail_price_micros", rec.RetailPriceMicros)
	row.Set("message_id", rec.MessageID)
	if err := app.Save(row); err != nil {
		return "", fmt.Errorf("metering: save: %w", err)
	}
	return row.Id, nil
}

// Summary aggregates meter rows for one tenant in a time window. Used
// by GET /v1/notify/metering. The from/to params are ISO-8601 strings;
// empty means open-ended.
type Summary struct {
	TenantSlug         string                  `json:"tenant_slug"`
	TotalUnits         int                     `json:"total_units"`
	TotalVendorMicros  int64                   `json:"total_vendor_cost_micros"`
	TotalRetailMicros  int64                   `json:"total_retail_price_micros"`
	ByProviderChannel  map[string]ProviderRoll `json:"by_provider_channel"`
}

// ProviderRoll is the per-(provider,channel) breakdown.
type ProviderRoll struct {
	Units        int   `json:"units"`
	VendorMicros int64 `json:"vendor_cost_micros"`
	RetailMicros int64 `json:"retail_price_micros"`
}

// Aggregate scans meter rows for the tenant and returns a roll-up. It
// loads up to maxRows records — callers that need windowed billing
// should pass a tight (from,to) and a high cap; the daily-rollup job
// uses streaming reads via the underlying dbx connection directly.
func Aggregate(app core.App, tenant, from, to string, maxRows int) (*Summary, error) {
	if tenant == "" {
		return nil, errors.New("metering: tenant is required")
	}
	if maxRows <= 0 {
		maxRows = 5000
	}
	filter := "tenant = {:tenant}"
	params := dbx.Params{"tenant": tenant}
	if from != "" {
		filter += " && sent_at >= {:from}"
		params["from"] = from
	}
	if to != "" {
		filter += " && sent_at <= {:to}"
		params["to"] = to
	}
	rows, err := app.FindRecordsByFilter(schema.Meter, filter, "-sent_at", maxRows, 0, params)
	if err != nil {
		return nil, fmt.Errorf("metering: aggregate: %w", err)
	}
	out := &Summary{
		TenantSlug:        tenant,
		ByProviderChannel: map[string]ProviderRoll{},
	}
	for _, r := range rows {
		key := r.GetString("provider") + "/" + r.GetString("channel")
		roll := out.ByProviderChannel[key]
		units := r.GetInt("units")
		vendor := int64(r.GetInt("vendor_cost_micros"))
		retail := int64(r.GetInt("retail_price_micros"))
		roll.Units += units
		roll.VendorMicros += vendor
		roll.RetailMicros += retail
		out.ByProviderChannel[key] = roll
		out.TotalUnits += units
		out.TotalVendorMicros += vendor
		out.TotalRetailMicros += retail
	}
	return out, nil
}
