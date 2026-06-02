// Tests for kmsbridge.Client. The bridge has two outbound dialogs (IAM
// token exchange + KMS secret read/write/delete); we drive both with
// httptest.NewServer mocks and assert on the URL shape, headers, and
// caching behaviour. No external services touched.
//
// The point of these tests is to lock the canonical URL shapes that
// the deployed liquid-kms (luxfi/kms@v1.9.11) and liquid-iam
// (hanzoai/iam@v1.18.7) actually serve, so a future refactor cannot
// silently regress to the legacy Infisical paths the way base v1.3.0
// did.
package kmsbridge

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestGetSecret_CanonicalURL asserts the bridge hits the
// /v1/kms/orgs/{org}/secrets/{path}/{name} route and parses both wire
// shapes the server returns.
func TestGetSecret_CanonicalURL(t *testing.T) {
	var gotPath atomic.Value
	var gotAuth atomic.Value

	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iam/oauth/access_token" {
			t.Errorf("iam: unexpected path %s", r.URL.Path)
			http.Error(w, "wrong path", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-jwt","expires_in":3600}`))
	}))
	defer iam.Close()

	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		gotAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secret":{"value":"plivo-auth-id-123"}}`))
	}))
	defer kms.Close()

	c, err := New(Config{
		KMSEndpoint:  kms.URL,
		IAMEndpoint:  iam.URL,
		ClientID:     "notify",
		ClientSecret: "secret",
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	val, err := c.GetSecret("liquidity", "brand/liquidity/plivo/auth-id")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if val != "plivo-auth-id-123" {
		t.Errorf("got value %q, want plivo-auth-id-123", val)
	}
	if got := gotPath.Load().(string); got != "/v1/kms/orgs/liquidity/secrets/brand/liquidity/plivo/auth-id" {
		t.Errorf("kms URL: got %q, want canonical /v1/kms/orgs/liquidity/secrets/brand/liquidity/plivo/auth-id", got)
	}
	if got := gotAuth.Load().(string); got != "Bearer test-jwt" {
		t.Errorf("kms auth: got %q, want Bearer test-jwt", got)
	}
}

// TestGetSecret_FlatValueShape covers the older wire shape (no
// "secret" wrapper) so the bridge stays compatible with both.
func TestGetSecret_FlatValueShape(t *testing.T) {
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"jwt","expires_in":3600}`))
	}))
	defer iam.Close()
	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value":"flat-value"}`))
	}))
	defer kms.Close()

	c, err := New(Config{KMSEndpoint: kms.URL, IAMEndpoint: iam.URL, ClientID: "x", ClientSecret: "y"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	got, err := c.GetSecret("org", "p/n")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != "flat-value" {
		t.Errorf("got %q, want flat-value", got)
	}
}

// TestGetSecret_Cache asserts hot reads do not redial KMS.
func TestGetSecret_Cache(t *testing.T) {
	var hits int32
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"jwt","expires_in":3600}`))
	}))
	defer iam.Close()
	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"value":"cached"}`))
	}))
	defer kms.Close()

	c, _ := New(Config{KMSEndpoint: kms.URL, IAMEndpoint: iam.URL, ClientID: "x", ClientSecret: "y"})
	for i := 0; i < 5; i++ {
		if _, err := c.GetSecret("org", "p/n"); err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("kms hits: got %d, want 1 (cache miss + 4 cache hits)", got)
	}
}

// TestSetSecret_UpsertBody verifies the POST body shape — KMS needs
// {path, name, value} so it can split the upsert by (path, name).
func TestSetSecret_UpsertBody(t *testing.T) {
	var gotBody atomic.Value
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"jwt","expires_in":3600}`))
	}))
	defer iam.Close()
	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kms/orgs/liquidity/secrets" {
			t.Errorf("kms put path: got %q, want /v1/kms/orgs/liquidity/secrets", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		gotBody.Store(string(b))
		w.WriteHeader(http.StatusCreated)
	}))
	defer kms.Close()

	c, _ := New(Config{KMSEndpoint: kms.URL, IAMEndpoint: iam.URL, ClientID: "x", ClientSecret: "y"})
	if err := c.SetSecret("liquidity", "brand/liquidity/plivo/auth-id", "ABCDEF"); err != nil {
		t.Fatalf("set: %v", err)
	}
	var got struct {
		Path  string `json:"path"`
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(gotBody.Load().(string)), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Path != "brand/liquidity/plivo" || got.Name != "auth-id" || got.Value != "ABCDEF" {
		t.Errorf("upsert body wrong: %+v", got)
	}
}

// TestDeleteSecret_404IsSuccess locks the idempotent-delete contract.
func TestDeleteSecret_404IsSuccess(t *testing.T) {
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"jwt","expires_in":3600}`))
	}))
	defer iam.Close()
	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer kms.Close()
	c, _ := New(Config{KMSEndpoint: kms.URL, IAMEndpoint: iam.URL, ClientID: "x", ClientSecret: "y"})
	if err := c.DeleteSecret("org", "p/n"); err != nil {
		t.Fatalf("delete: got %v, want nil (404 is idempotent success)", err)
	}
}

// TestInvalidateCache drops cached values so the next read redials.
func TestInvalidateCache(t *testing.T) {
	var hits int32
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"jwt","expires_in":3600}`))
	}))
	defer iam.Close()
	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"value":"v"}`))
	}))
	defer kms.Close()
	c, _ := New(Config{KMSEndpoint: kms.URL, IAMEndpoint: iam.URL, ClientID: "x", ClientSecret: "y"})
	_, _ = c.GetSecret("org", "p/n")
	c.InvalidateCache("org")
	_, _ = c.GetSecret("org", "p/n")
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("kms hits: got %d, want 2 (no cache after invalidate)", got)
	}
}

// TestStaticBearer skips IAM exchange when the override is set.
func TestStaticBearer(t *testing.T) {
	var iamCalls int32
	iam := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&iamCalls, 1)
	}))
	defer iam.Close()

	var gotAuth atomic.Value
	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"value":"v"}`))
	}))
	defer kms.Close()

	c, err := New(Config{KMSEndpoint: kms.URL, StaticBearer: "fixed-token"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := c.GetSecret("org", "p/n"); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := atomic.LoadInt32(&iamCalls); got != 0 {
		t.Errorf("iam calls: got %d, want 0 (StaticBearer suppresses exchange)", got)
	}
	if got := gotAuth.Load().(string); got != "Bearer fixed-token" {
		t.Errorf("auth header: got %q, want Bearer fixed-token", got)
	}
}

// TestSecretURL_Escaping covers the URL builder for the boring-but-easy
// to break case: a path with multiple segments, all of which need to
// keep their slashes as path separators (not %2F).
func TestSecretURL_Escaping(t *testing.T) {
	c := &Client{kmsEndpoint: "http://kms.test"}
	got := c.secretURL("liquidity", "brand/liquidity/plivo/auth-id")
	want := "http://kms.test/v1/kms/orgs/liquidity/secrets/brand/liquidity/plivo/auth-id"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestNew_Validation covers the required-field error cases.
func TestNew_Validation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no kms endpoint", Config{IAMEndpoint: "x", ClientID: "x", ClientSecret: "x"}, "KMSEndpoint is required"},
		{"no iam endpoint", Config{KMSEndpoint: "x", ClientID: "x", ClientSecret: "x"}, "IAMEndpoint is required"},
		{"no client id", Config{KMSEndpoint: "x", IAMEndpoint: "x", ClientSecret: "x"}, "ClientID is required"},
		{"no client secret", Config{KMSEndpoint: "x", IAMEndpoint: "x", ClientID: "x"}, "ClientSecret is required"},
		{"static bearer skips iam fields", Config{KMSEndpoint: "x", StaticBearer: "tok"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if tc.want == "" {
				if err != nil {
					t.Errorf("got err=%v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got err=%v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestTokenRefresh_OnExpiry asserts that an expiring token triggers a
// fresh IAM call. We feed a 1-second token, sleep past it, then expect
// a second IAM call.
func TestTokenRefresh_OnExpiry(t *testing.T) {
	var iamCalls int32
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&iamCalls, 1)
		// Below the 60s skew → bridge treats as already-near-expiry,
		// refreshing on every call.
		_, _ = w.Write([]byte(`{"access_token":"jwt","expires_in":1}`))
	}))
	defer iam.Close()
	kms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value":"v"}`))
	}))
	defer kms.Close()
	c, _ := New(Config{KMSEndpoint: kms.URL, IAMEndpoint: iam.URL, ClientID: "x", ClientSecret: "y"})
	// Two distinct secret paths to bypass the secret cache; the token
	// cache is what we are testing here.
	if _, err := c.GetSecret("org", "p/n1"); err != nil {
		t.Fatalf("get1: %v", err)
	}
	if _, err := c.GetSecret("org", "p/n2"); err != nil {
		t.Fatalf("get2: %v", err)
	}
	if got := atomic.LoadInt32(&iamCalls); got != 2 {
		t.Errorf("iam calls: got %d, want 2 (expires_in=1 forces refresh on every read)", got)
	}
}

// Compile-time guard: ensure the time import stays used in case we
// remove a test that touches it.
var _ = time.Second
