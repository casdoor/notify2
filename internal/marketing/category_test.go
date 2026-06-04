package marketing

import (
	"strings"
	"testing"
)

func TestIsMarketing(t *testing.T) {
	t.Parallel()
	in := []string{
		"promotional", "newsletter", "product_update", "partner_offer", "research",
		"Promotional", " newsletter ", "PARTNER_OFFER",
	}
	for _, c := range in {
		if !IsMarketing(c) {
			t.Errorf("IsMarketing(%q) = false, want true", c)
		}
	}
	out := []string{
		"", "transactional", "regulatory", "alert", "trade_confirmation",
		"otp", "iam.otp_sent",
	}
	for _, c := range out {
		if IsMarketing(c) {
			t.Errorf("IsMarketing(%q) = true, want false", c)
		}
	}
}

func TestAppendHTMLFooter(t *testing.T) {
	t.Parallel()
	got := AppendHTMLFooter("<p>hi</p>", "https://notify.dev.satschel.com/v1/notify/unsubscribe/TOK")
	if !strings.Contains(got, "<p>hi</p>") {
		t.Fatalf("original body lost: %s", got)
	}
	if !strings.Contains(got, `<a href="https://notify.dev.satschel.com/v1/notify/unsubscribe/TOK">click here</a>`) {
		t.Fatalf("HTML link missing: %s", got)
	}
	if !strings.Contains(got, "<hr>") {
		t.Fatalf("hr separator missing: %s", got)
	}
	if !strings.Contains(got, `color: #666`) {
		t.Fatalf("muted style missing: %s", got)
	}
}

func TestAppendPlainFooter(t *testing.T) {
	t.Parallel()
	got := AppendPlainFooter("hello", "https://notify.satschel.com/v1/notify/unsubscribe/TOK")
	if !strings.Contains(got, "hello") {
		t.Fatalf("original body lost: %s", got)
	}
	if !strings.Contains(got, "--\nUnsubscribe: https://notify.satschel.com/v1/notify/unsubscribe/TOK") {
		t.Fatalf("plain footer missing or malformed: %s", got)
	}
}

func TestAppendFooter_EmptyURLNoOps(t *testing.T) {
	t.Parallel()
	if AppendHTMLFooter("<p>hi</p>", "") != "<p>hi</p>" {
		t.Fatal("empty URL should leave HTML body unchanged")
	}
	if AppendPlainFooter("hi", "  ") != "hi" {
		t.Fatal("whitespace URL should leave plain body unchanged")
	}
}

func TestAppendFooter_EmptyBody(t *testing.T) {
	t.Parallel()
	got := AppendHTMLFooter("", "https://x/T")
	if !strings.HasPrefix(got, "<hr>") {
		t.Fatalf("empty body should yield footer-only: %s", got)
	}
	got = AppendPlainFooter("", "https://x/T")
	if !strings.HasPrefix(got, "--") {
		t.Fatalf("empty body should yield footer-only: %s", got)
	}
}
