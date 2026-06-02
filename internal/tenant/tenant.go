// Package tenant resolves per-tenant Notifier instances on demand.
//
// On every Send, the routes layer asks the resolver for a Notifier
// configured for (tenant, channel). The resolver looks up the active
// Provider row, fetches credentials from KMS, and constructs the
// matching provider impl from the library. No cache — credentials may
// rotate, and provider rows may change at runtime; the cost of one
// extra KMS Get per send is the price of correctness.
//
// Phase 1: plivo (SMS/WhatsApp/Voice) + mail (SMTP). Other providers
// land as small functions that follow the same shape — the library
// already exposes 33 implementations; this package wraps them.
package tenant

import (
	"context"
	"errors"
	"fmt"
	"net/smtp"
	"os"
	"strings"

	"github.com/hanzoai/base/core"
	"github.com/hanzoai/dbx"

	"github.com/hanzoai/notify"
	"github.com/hanzoai/notify/internal/kmsbridge"
	"github.com/hanzoai/notify/internal/schema"
	"github.com/hanzoai/notify/service/mail"
	"github.com/hanzoai/notify/service/plivo"
	"github.com/hanzoai/notify/pkg/types"
)

// Resolver is the entry point routes call. It owns the base app
// (to look up provider rows) and the KMS bridge (to fetch credentials).
type Resolver struct {
	app core.App
	kms *kmsbridge.Client
}

// New returns a Resolver bound to the given app + KMS client. A nil
// KMS client is allowed; in that mode the resolver falls back to env
// var credentials, which is the local-dev / scratch-image path.
func New(app core.App, kms *kmsbridge.Client) *Resolver {
	return &Resolver{app: app, kms: kms}
}

// Resolve returns a notifier wired with credentials for (tenant, channel).
// service may be empty to take the tenant's default provider for the
// channel. The returned notifier targets `to` so caller can call Send
// directly — providers in the library are constructed with a fixed
// recipient list per the casdoor/nikoksr design.
func (r *Resolver) Resolve(ctx context.Context, tenant, channel, service string, to []string) (notify.Notifier, string, error) {
	row, err := r.selectProvider(tenant, channel, service)
	if err != nil {
		return nil, "", err
	}
	creds, err := r.fetchCreds(ctx, row)
	if err != nil {
		return nil, "", fmt.Errorf("tenant: fetch creds for %s/%s: %w", tenant, row.GetString("service"), err)
	}
	n, err := constructProvider(row.GetString("service"), creds, to)
	if err != nil {
		return nil, "", err
	}
	return n, row.GetString("service"), nil
}

// selectProvider picks the matching providers row. service != "" forces
// a specific provider; otherwise the first is_default=true row for the
// channel wins, then any active row for the channel as fallback.
func (r *Resolver) selectProvider(tenant, channel, service string) (*core.Record, error) {
	filter := "tenant = {:tenant} && status = {:status}"
	params := dbx.Params{
		"tenant": tenant,
		"status": schema.ProviderStatusActive,
	}
	if service != "" {
		filter += " && service = {:service}"
		params["service"] = service
	}
	if channel != "" {
		filter += " && (channel = {:channel} || channel = '')"
		params["channel"] = channel
	}
	rows, err := r.app.FindRecordsByFilter(schema.Providers, filter, "-is_default,-updated", 5, 0, params)
	if err != nil {
		return nil, fmt.Errorf("tenant: list providers: %w", err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("tenant: no active provider for tenant=%s channel=%s service=%s", tenant, channel, service)
	}
	return rows[0], nil
}

// Credentials is the flat key/value bag the library providers consume.
// The KMS values land here as plain strings; envelope decoding happens
// inside kmsclient.
type Credentials map[string]string

// fetchCreds dispatches to KMS or env vars depending on whether a KMS
// client is configured. The KMS path is the only one that runs in
// production; env vars exist for local dev / scratch images.
//
// Layout: per-secret. The provider row's kms_path is a directory; the
// resolver appends one field-name segment per credential. Example:
//
//	kms_path = "tenants/liquidity/plivo"
//	fetched  = tenants/liquidity/plivo/auth-id, …/auth-token, …/from-number
//
// The platform plugin's KMS facade returns one string per call.
func (r *Resolver) fetchCreds(_ context.Context, row *core.Record) (Credentials, error) {
	if r.kms == nil {
		return credsFromEnv(row.GetString("service")), nil
	}
	tenant := row.GetString("tenant")
	base := strings.TrimRight(row.GetString("kms_path"), "/")
	keys := credKeysForService(row.GetString("service"))
	out := make(Credentials, len(keys))
	for _, k := range keys {
		path := base + "/" + k
		v, err := r.kms.GetSecret(tenant, path)
		if err != nil {
			return nil, fmt.Errorf("kms get %s: %w", path, err)
		}
		out[k] = v
	}
	return out, nil
}

// credsFromEnv reads provider creds from env vars. Only the providers
// likely to be used standalone (plivo + mail) have env fallbacks; the
// rest hard-require KMS.
func credsFromEnv(service string) Credentials {
	switch service {
	case "plivo":
		return Credentials{
			"auth-id":     os.Getenv("PLIVO_AUTH_ID"),
			"auth-token":  os.Getenv("PLIVO_AUTH_TOKEN"),
			"from-number": os.Getenv("PLIVO_FROM_NUMBER"),
		}
	case "mail":
		return Credentials{
			"smtp-host":     os.Getenv("SMTP_HOST"),
			"smtp-port":     os.Getenv("SMTP_PORT"),
			"smtp-user":     os.Getenv("SMTP_USER"),
			"smtp-password": os.Getenv("SMTP_PASSWORD"),
			"sender-email":  os.Getenv("SENDER_EMAIL"),
			"sender-name":   os.Getenv("SENDER_NAME"),
		}
	}
	return Credentials{}
}

// credKeysForService returns the list of secret keys that must be
// fetched out of KMS for the given provider service.
func credKeysForService(service string) []string {
	switch service {
	case "plivo":
		return []string{"auth-id", "auth-token", "from-number"}
	case "twilio":
		return []string{"account-sid", "auth-token", "from-number"}
	case "sendgrid":
		return []string{"api-key", "sender-email", "sender-name"}
	case "mailgun":
		return []string{"domain", "api-key", "sender-email", "sender-name"}
	case "ses":
		return []string{"access-key-id", "secret-access-key", "region", "sender-email", "sender-name"}
	case "mail":
		return []string{"smtp-host", "smtp-port", "smtp-user", "smtp-password", "sender-email", "sender-name"}
	default:
		// Library providers we haven't wired explicitly land here; their
		// boot.go entry must define the key list.
		return []string{"key", "secret"}
	}
}

// constructProvider builds the library notifier for one provider service.
// Each branch follows the same shape: read creds, validate required,
// call the provider's New, AddReceivers(to...). The set of supported
// services here is the launch slice; expanding it is a small mechanical
// edit per the library's 33 providers.
func constructProvider(service string, c Credentials, to []string) (notify.Notifier, error) {
	switch service {
	case "plivo":
		if c["auth-id"] == "" || c["auth-token"] == "" {
			return nil, errors.New("tenant: plivo requires auth-id and auth-token")
		}
		p, err := plivo.New(
			&plivo.ClientOptions{
				AuthID:    c["auth-id"],
				AuthToken: c["auth-token"],
			},
			&plivo.MessageOptions{Source: c["from-number"]},
		)
		if err != nil {
			return nil, err
		}
		p.AddReceivers(to...)
		return p, nil

	case "mail":
		if c["smtp-host"] == "" || c["sender-email"] == "" {
			return nil, errors.New("tenant: mail requires smtp-host and sender-email")
		}
		port := c["smtp-port"]
		if port == "" {
			port = "587"
		}
		m := mail.New(c["sender-email"], c["smtp-host"]+":"+port)
		m.AuthenticateSMTP("", c["smtp-user"], c["smtp-password"], c["smtp-host"])
		m.AddReceivers(to...)
		// Ensure we satisfy the Notifier interface; smtp.PlainAuth is
		// imported to keep the dep set explicit (mail.AuthenticateSMTP
		// internally wraps smtp.PlainAuth — referenced here so a future
		// move to a TLS-only path notices the package).
		_ = smtp.PlainAuth
		return m, nil
	}
	return nil, fmt.Errorf("tenant: provider %q not yet wired (library has the impl — add a constructProvider branch)", service)
}

// Channel narrows a string to a known types.Channel or returns "".
// Used by the routes layer when reading the body's channel field.
func Channel(s string) types.Channel {
	switch types.Channel(s) {
	case types.ChannelSMS, types.ChannelEmail, types.ChannelVoice,
		types.ChannelWhatsApp, types.ChannelPush, types.ChannelChat:
		return types.Channel(s)
	}
	return ""
}
