// Package boot wires the shared dependencies notifyd needs at startup.
//
// In particular the KMS client: notifyd reads per-tenant provider
// credentials out of Hanzo KMS via internal/kmsbridge — an HTTP client
// targeting canonical `/v1/kms/orgs/{org}/secrets/{path}/{name}` routes.
//
// Boot is intentionally tiny: one constructor + an env reader. The
// rest of the wiring lives in main.go.
package boot

import (
	"log"
	"os"

	"github.com/hanzoai/notify/internal/kmsbridge"
)

// KMSEndpoint returns the configured KMS endpoint or empty. Empty means
// "KMS disabled" — the resolver then falls back to env-var credentials.
func KMSEndpoint() string {
	return envOr("KMS_ENDPOINT", "")
}

// IAMEndpoint returns the configured IAM endpoint or empty. Required
// for the IAM client_credentials grant unless KMS_AUTH_TOKEN is set.
func IAMEndpoint() string {
	return envOr("IAM_ENDPOINT", "https://hanzo.id")
}

// KMSAuthToken returns the optional static bearer token for KMS. In
// production this stays empty and the bridge runs the IAM
// client_credentials exchange. Tests use a static token to
// short-circuit IAM.
func KMSAuthToken() string {
	return os.Getenv("KMS_AUTH_TOKEN")
}

// NewKMSClient builds a kmsbridge.Client from env. Returns nil when
// KMS_ENDPOINT is unset — callers must handle that case (nil is the
// well-defined "no KMS" mode, not an error).
//
// Misconfiguration (e.g. KMS_ENDPOINT set but IAM_CLIENT_ID missing) is
// a fatal log; we want pods to crashloop loudly rather than silently
// run with broken KMS and fail every OTP send at request time.
func NewKMSClient() *kmsbridge.Client {
	ep := KMSEndpoint()
	if ep == "" {
		return nil
	}
	cfg := kmsbridge.Config{
		KMSEndpoint:  ep,
		IAMEndpoint:  IAMEndpoint(),
		ClientID:     os.Getenv("IAM_CLIENT_ID"),
		ClientSecret: os.Getenv("IAM_CLIENT_SECRET"),
		StaticBearer: KMSAuthToken(),
	}
	c, err := kmsbridge.New(cfg)
	if err != nil {
		log.Fatalf("boot: kmsbridge.New: %v", err)
	}
	return c
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
