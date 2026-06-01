// Package boot wires the shared dependencies notifyd needs at startup.
//
// In particular the KMS client: notifyd reads per-tenant provider
// credentials out of Hanzo KMS, but it does NOT speak kmsclient
// directly — instead it borrows the platform plugin's KMS facade
// (github.com/hanzoai/base/plugins/platform.KMSClient) which already
// handles the IAM client_credentials exchange, transport selection
// (HTTP vs. ZAP), and a thin secret cache.
//
// Boot is intentionally tiny: one constructor + an env reader. The
// rest of the wiring lives in main.go.
package boot

import (
	"os"

	"github.com/hanzoai/base/plugins/platform"
)

// KMSEndpoint returns the configured KMS endpoint or the canonical
// in-cluster default. The platform plugin treats an empty endpoint as
// "KMS disabled" — the resolver then falls back to env-var credentials.
func KMSEndpoint() string {
	return envOr("KMS_ENDPOINT", "")
}

// KMSAuthToken returns the optional static bearer token for KMS. In
// production this stays empty and kmsclient runs the IAM
// client_credentials exchange via the platform plugin's IAM
// configuration. Tests use a static token to short-circuit IAM.
func KMSAuthToken() string {
	return os.Getenv("KMS_AUTH_TOKEN")
}

// NewKMSClient is a thin wrapper over platform.NewKMSClient. Returns
// nil when KMS_ENDPOINT is unset — callers must handle that case
// (nil is the well-defined "no KMS" mode, not an error).
func NewKMSClient() *platform.KMSClient {
	ep := KMSEndpoint()
	if ep == "" {
		return nil
	}
	return platform.NewKMSClient(ep, KMSAuthToken())
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
