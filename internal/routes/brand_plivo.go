// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package routes

// Brand-scoped Plivo override surface (/v1/notify/brand/plivo).
//
// The platform UI ("SMS/Email Provider Override") talks to these
// endpoints. The flow:
//
//   GET    /v1/notify/brand/plivo        — read effective config (metadata only)
//   PUT    /v1/notify/brand/plivo        — upsert brand override (writes KMS)
//   DELETE /v1/notify/brand/plivo        — remove override (falls back to default)
//   POST   /v1/notify/brand/plivo/test   — send a probe SMS / email
//
// Secret hygiene:
//   - GET never returns auth-id / auth-token. Only sender-id / from-email
//     plus a flag indicating whether an override exists.
//   - PUT/DELETE write to KMS via the platform KMS facade; raw values
//     never land in notify's database.
//   - Test uses tenant.PlivoResolver to pick the same creds a real send
//     would use, so the probe is identical to the production code path.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/apis"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/plugins/platform"
	"github.com/hanzoai/base/tools/router"

	"github.com/hanzoai/notify/internal/tenant"
	"github.com/hanzoai/notify/service/plivo"
)

// brandPlivoConfig describes the wire shape the platform UI sends on
// PUT. Only the four override fields; everything else (brand, KMS path)
// is derived server-side from X-Org-Id.
type brandPlivoConfig struct {
	AuthID    string `json:"auth_id"`
	AuthToken string `json:"auth_token"`
	SenderID  string `json:"sender_id"`
	FromEmail string `json:"from_email,omitempty"`
}

// brandPlivoConfigOut is the GET response shape. Secrets are NEVER
// included — only metadata.
type brandPlivoConfigOut struct {
	Brand          string `json:"brand"`
	EffectiveBrand string `json:"effectiveBrand"`
	HasOverride    bool   `json:"hasOverride"`
	SenderID       string `json:"senderId,omitempty"`
	FromEmail      string `json:"fromEmail,omitempty"`
}

type brandPlivoTestInput struct {
	Channel   string `json:"channel"`
	Recipient string `json:"recipient"`
}

type brandPlivoTestOut struct {
	Status         string `json:"status"`
	MessageID      string `json:"message_id,omitempty"`
	Error          string `json:"error,omitempty"`
	EffectiveBrand string `json:"effective_brand"`
}

// MountBrandPlivo installs the /v1/notify/brand/plivo* routes. Bound
// when the binary has both a KMS facade and a PlivoResolver. In local
// dev (no KMS) the routes return 503 — the override surface is
// production-only.
func MountBrandPlivo(r *router.Router[*core.RequestEvent], app *base.Base, kms *platform.KMSClient, resolver *tenant.PlivoResolver) {
	r.GET("/v1/notify/brand/plivo", handleBrandPlivoGet(kms, resolver))
	r.PUT("/v1/notify/brand/plivo", handleBrandPlivoPut(kms))
	r.DELETE("/v1/notify/brand/plivo", handleBrandPlivoDelete(kms))
	r.POST("/v1/notify/brand/plivo/test", handleBrandPlivoTest(resolver))
}

func handleBrandPlivoGet(kms *platform.KMSClient, resolver *tenant.PlivoResolver) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		brand, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		if resolver == nil {
			return apis.NewApiError(http.StatusServiceUnavailable, "plivo resolver not configured", nil)
		}
		ctx, cancel := context.WithTimeout(e.Request.Context(), 5*time.Second)
		defer cancel()

		cfg, err := resolver.ResolvePlivoConfig(ctx, brand)
		if err != nil {
			return apis.NewInternalServerError("resolve plivo config", err)
		}

		// Override status comes from whether the requested brand had its
		// own creds, NOT from cfg.Override alone (which is also true when
		// the brand IS the default brand). Probe the brand-specific path.
		hasOverride := false
		if kms != nil && brand != tenant.DefaultBrand {
			path := tenant.PlivoBrandKMSPathPrefix + "/" + brand + "/plivo/auth-id"
			if _, kerr := kms.GetSecret(brand, path); kerr == nil {
				hasOverride = true
			}
		}

		return e.JSON(http.StatusOK, brandPlivoConfigOut{
			Brand:          brand,
			EffectiveBrand: cfg.Brand,
			HasOverride:    hasOverride,
			SenderID:       cfg.SenderID,
			FromEmail:      cfg.FromEmail,
		})
	}
}

func handleBrandPlivoPut(kms *platform.KMSClient) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		brand, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		if kms == nil {
			return apis.NewApiError(http.StatusServiceUnavailable, "KMS not configured — cannot write brand override", nil)
		}

		var body brandPlivoConfig
		if err := e.BindBody(&body); err != nil {
			return apis.NewBadRequestError("malformed body", err)
		}
		if strings.TrimSpace(body.AuthID) == "" ||
			strings.TrimSpace(body.AuthToken) == "" ||
			strings.TrimSpace(body.SenderID) == "" {
			return apis.NewBadRequestError("auth_id, auth_token, and sender_id are required", nil)
		}

		base := tenant.PlivoBrandKMSPathPrefix + "/" + brand + "/plivo"
		writes := []struct{ key, value string }{
			{base + "/auth-id", body.AuthID},
			{base + "/auth-token", body.AuthToken},
			{base + "/sender-id", body.SenderID},
		}
		if strings.TrimSpace(body.FromEmail) != "" {
			writes = append(writes, struct{ key, value string }{base + "/from-email", body.FromEmail})
		}
		for _, w := range writes {
			if err := kms.SetSecret(brand, w.key, w.value); err != nil {
				return apis.NewInternalServerError("kms write "+w.key, err)
			}
		}
		return e.JSON(http.StatusOK, map[string]any{
			"ok":    true,
			"brand": brand,
		})
	}
}

func handleBrandPlivoDelete(kms *platform.KMSClient) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		brand, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		if kms == nil {
			return apis.NewApiError(http.StatusServiceUnavailable, "KMS not configured", nil)
		}
		if brand == tenant.DefaultBrand {
			return apis.NewBadRequestError("cannot clear override on the default brand", nil)
		}
		basePath := tenant.PlivoBrandKMSPathPrefix + "/" + brand + "/plivo"
		// Best-effort delete; "not found" is not an error from the
		// caller's perspective.
		for _, key := range []string{"auth-id", "auth-token", "sender-id", "from-email"} {
			_ = kms.DeleteSecret(brand, basePath+"/"+key)
		}
		return e.JSON(http.StatusOK, map[string]any{"ok": true})
	}
}

func handleBrandPlivoTest(resolver *tenant.PlivoResolver) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		brand, err := orgFromRequest(e)
		if err != nil {
			return err
		}
		if resolver == nil {
			return apis.NewApiError(http.StatusServiceUnavailable, "plivo resolver not configured", nil)
		}

		var body brandPlivoTestInput
		if err := e.BindBody(&body); err != nil {
			return apis.NewBadRequestError("malformed body", err)
		}
		if body.Channel != "sms" && body.Channel != "email" {
			return apis.NewBadRequestError("channel must be sms or email", nil)
		}
		if strings.TrimSpace(body.Recipient) == "" {
			return apis.NewBadRequestError("recipient is required", nil)
		}

		ctx, cancel := context.WithTimeout(e.Request.Context(), 10*time.Second)
		defer cancel()

		cfg, err := resolver.ResolvePlivoConfig(ctx, brand)
		if err != nil {
			return apis.NewInternalServerError("resolve plivo config", err)
		}

		switch body.Channel {
		case "sms":
			messageID, err := sendBrandPlivoTestSMS(ctx, cfg, body.Recipient)
			if err != nil {
				return e.JSON(http.StatusOK, brandPlivoTestOut{
					Status:         "failed",
					Error:          err.Error(),
					EffectiveBrand: cfg.Brand,
				})
			}
			return e.JSON(http.StatusOK, brandPlivoTestOut{
				Status:         "sent",
				MessageID:      messageID,
				EffectiveBrand: cfg.Brand,
			})
		default:
			// Email test is intentionally not implemented here — the
			// brand's email provider may not be Plivo Email; the SMS
			// test is the canonical KMS-round-trip probe.
			return apis.NewBadRequestError("email test not yet implemented (run an SMS test to verify the KMS round-trip)", nil)
		}
	}
}

// sendBrandPlivoTestSMS constructs a one-shot Plivo notifier with the
// brand's resolved creds and sends a fixed probe message. Returns the
// Plivo message ID on success.
func sendBrandPlivoTestSMS(ctx context.Context, cfg *tenant.PlivoConfig, recipient string) (string, error) {
	if cfg == nil {
		return "", errors.New("nil plivo config")
	}
	svc, err := plivo.New(
		&plivo.ClientOptions{AuthID: cfg.AuthID, AuthToken: cfg.AuthToken},
		&plivo.MessageOptions{Source: cfg.SenderID},
	)
	if err != nil {
		return "", fmt.Errorf("plivo new: %w", err)
	}
	svc.AddReceivers(recipient)
	if err := svc.Send(ctx, "", fmt.Sprintf("Test from Hanzo Notify (brand=%s)", cfg.Brand)); err != nil {
		return "", err
	}
	// The library's Send does not surface the per-message ID; we return
	// a synthetic marker. A future refactor can plumb it through.
	return "ok", nil
}
