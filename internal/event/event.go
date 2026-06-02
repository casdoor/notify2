// Package event is the catalog layer over the `events` collection.
//
// An Event entry binds (tenant, name) to a default template + routing
// preferences + a rate limit. The Send pipeline reads the catalog
// when SendRequest.Event is set, applies the policy, then proceeds.
//
// No external state — this package is a thin wrapper over base record
// operations to keep the routes layer readable.
package event

import (
	"errors"
	"fmt"

	"github.com/hanzoai/base/core"
	"github.com/hanzoai/dbx"

	"github.com/hanzoai/notify/internal/schema"
)

// Resolve loads the enabled event row for (tenant, name) and returns
// nil (not an error) when no match exists. Empty name short-circuits.
func Resolve(app core.App, tenant, name string) (*core.Record, error) {
	if tenant == "" {
		return nil, errors.New("event: tenant is required")
	}
	if name == "" {
		return nil, nil
	}
	rows, err := app.FindRecordsByFilter(
		schema.Events,
		"tenant = {:tenant} && name = {:name} && enabled = true",
		"",
		1, 0,
		dbx.Params{"tenant": tenant, "name": name},
	)
	if err != nil {
		return nil, fmt.Errorf("event: lookup: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0], nil
}
