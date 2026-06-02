// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package tenant

// Multi-brand Plivo resolution.
//
// IAM lives at hanzo.id / lux.id / zoo.id / pars.id / liquidity.id; each
// hostname maps to a brand slug (the JWT owner claim → X-Org-Id header).
// Notify reads that brand slug and resolves which Plivo account sends the
// SMS / WhatsApp / Voice message for that brand's user.
//
// One way, two outcomes:
//
//   1. Brand-override path. The brand admin used the platform UI to wire
//      a per-brand Plivo account. KMS holds the credentials at
//      `kms.hanzo.ai → brand/<slug>/plivo/{auth-id, auth-token, sender-id, from-email}`.
//      ResolvePlivoConfig returns those values.
//
//   2. Liquidity-default path. The brand has not wired its own Plivo.
//      KMS still holds `kms.hanzo.ai → brand/liquidity/plivo/*` — that's
//      Liquidity's fleet-shared account. ResolvePlivoConfig returns
//      those.
//
// Fail-closed: if the default Liquidity record is missing or unreachable,
// the resolver returns an error and the caller surfaces 503. No hard-
// coded fallback (the rest of CLAUDE.md is loud about this — secrets
// only ever live in KMS).
//
// This file is the ONE place that knows about brand fallback. The
// existing Resolver (tenant.go) keeps owning per-tenant Provider rows
// for non-Plivo services (mail, sendgrid, twilio, …). Plivo is special
// because every Hanzo brand is a Plivo customer by default, so the
// row-driven discovery would be needless ceremony.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hanzoai/base/plugins/platform"
)

// DefaultBrand is the brand slug whose KMS credentials are used when the
// caller's brand has not configured an override. Lives in KMS at
// `brand/liquidity/plivo/*`.
const DefaultBrand = "liquidity"

// PlivoBrandKMSPathPrefix is the KMS path under which per-brand Plivo
// credentials live. Combined with brand slug:
//
//	brand/<slug>/plivo/auth-id
//	brand/<slug>/plivo/auth-token
//	brand/<slug>/plivo/sender-id
//	brand/<slug>/plivo/from-email
const PlivoBrandKMSPathPrefix = "brand"

// Plivo credential field names. Hard-coded; this is the KMS contract.
//
// from-email is included because the platform UI lets a brand set both
// SMS sender + email From in one form. notify reads the email value via
// the same resolver when channel=email and the brand uses Plivo's email
// product (or, more commonly, when the brand's email provider is wired
// alongside the SMS override).
const (
	plivoFieldAuthID    = "auth-id"
	plivoFieldAuthToken = "auth-token"
	plivoFieldSenderID  = "sender-id"
	plivoFieldFromEmail = "from-email"
)

// PlivoConfig is the resolved per-brand Plivo configuration. The
// SenderID doubles as the Plivo "Source" — either an E.164 number or a
// Powerpack UUID.
type PlivoConfig struct {
	// Brand is the slug whose credentials produced this config. When a
	// brand override exists, Brand == the requested brand. When the
	// resolver fell back to the Liquidity default, Brand == "liquidity".
	// Callers use this to log which Plivo account actually sent.
	Brand string

	// AuthID is the Plivo Auth ID (account-level credential).
	AuthID string

	// AuthToken is the Plivo Auth Token (account-level credential).
	AuthToken string

	// SenderID is the source number / shortcode / alphanumeric ID that
	// will appear as the From on the SMS.
	SenderID string

	// FromEmail is the email address the brand sends from when notify
	// channel=email is wired to the same per-brand config. Optional.
	FromEmail string

	// Override is true when this config came from the requested brand's
	// own KMS entries (not the Liquidity default). Used by the platform
	// UI's "current effective provider" indicator.
	Override bool
}

// PlivoResolver resolves per-brand Plivo configuration via KMS. One
// instance per process is enough — the underlying KMSClient already
// memoizes secrets for 1m TTL.
type PlivoResolver struct {
	kms *platform.KMSClient
}

// NewPlivoResolver returns a PlivoResolver bound to the given KMS
// client. A nil KMS client is rejected at boot — fail-closed.
func NewPlivoResolver(kms *platform.KMSClient) (*PlivoResolver, error) {
	if kms == nil {
		return nil, errors.New("plivo resolver: KMS client is required (multi-brand fallback cannot run without KMS)")
	}
	return &PlivoResolver{kms: kms}, nil
}

// ResolvePlivoConfig returns the Plivo credentials that should be used
// when sending for brand. The lookup order is:
//
//  1. brand/<requested>/plivo/* — the brand's own override.
//  2. brand/liquidity/plivo/*   — the Liquidity default.
//
// On step 1 the resolver does NOT short-circuit on any non-EOF error: a
// KMS access error against the requested brand falls through to the
// default ONLY when the error indicates "secret not found". Any other
// error (auth fail, transport, 5xx) is surfaced — silently degrading to
// the Liquidity creds for someone else's transient KMS outage would
// risk sending the wrong brand's SMS during the outage window.
//
// On step 2 the resolver fail-closes: a missing or unreachable
// Liquidity default returns an error. notify callers surface 503.
//
// The empty string for `brand` is rejected as a programming error —
// the platform plugin always injects X-Org-Id before this fires.
func (r *PlivoResolver) ResolvePlivoConfig(ctx context.Context, brand string) (*PlivoConfig, error) {
	brand = strings.TrimSpace(brand)
	if brand == "" {
		return nil, errors.New("plivo resolver: brand is required")
	}

	// Step 1 — try the brand's own override.
	if brand != DefaultBrand {
		cfg, err := r.fetchBrand(ctx, brand)
		if err == nil {
			cfg.Override = true
			return cfg, nil
		}
		if !isMissingSecret(err) {
			return nil, fmt.Errorf("plivo resolver: brand %q lookup failed: %w", brand, err)
		}
		// Fall through to the Liquidity default.
	}

	// Step 2 — Liquidity default. Errors here are fatal.
	cfg, err := r.fetchBrand(ctx, DefaultBrand)
	if err != nil {
		return nil, fmt.Errorf("plivo resolver: default brand %q lookup failed (fail-closed, no hard-coded fallback): %w", DefaultBrand, err)
	}
	cfg.Override = brand == DefaultBrand
	return cfg, nil
}

// fetchBrand reads the four KMS fields for a brand slug. auth-id +
// auth-token are required; sender-id is required for SMS so we error if
// blank; from-email is optional.
func (r *PlivoResolver) fetchBrand(_ context.Context, brand string) (*PlivoConfig, error) {
	base := PlivoBrandKMSPathPrefix + "/" + brand + "/plivo"

	authID, err := r.kms.GetSecret(brand, base+"/"+plivoFieldAuthID)
	if err != nil {
		return nil, err
	}
	authToken, err := r.kms.GetSecret(brand, base+"/"+plivoFieldAuthToken)
	if err != nil {
		return nil, err
	}
	senderID, err := r.kms.GetSecret(brand, base+"/"+plivoFieldSenderID)
	if err != nil {
		return nil, err
	}
	// from-email is optional. Missing or empty → from-email == "".
	fromEmail, _ := r.kms.GetSecret(brand, base+"/"+plivoFieldFromEmail)

	if strings.TrimSpace(authID) == "" || strings.TrimSpace(authToken) == "" {
		return nil, fmt.Errorf("plivo resolver: brand %q has KMS rows but auth-id or auth-token is blank", brand)
	}
	if strings.TrimSpace(senderID) == "" {
		return nil, fmt.Errorf("plivo resolver: brand %q has KMS rows but sender-id is blank (required for SMS)", brand)
	}

	return &PlivoConfig{
		Brand:     brand,
		AuthID:    authID,
		AuthToken: authToken,
		SenderID:  senderID,
		FromEmail: fromEmail,
	}, nil
}

// isMissingSecret returns true when err looks like "the requested
// secret does not exist". The KMS facade does not export a typed error
// for this — we match on the message substring KMS returns ("not
// found"). This is the only place that pattern-matches; if KMS adds a
// typed error later, swap this implementation in one place.
func isMissingSecret(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found"),
		strings.Contains(msg, "no such secret"),
		strings.Contains(msg, "secret does not exist"),
		strings.Contains(msg, "404"):
		return true
	}
	return false
}
