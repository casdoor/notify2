// category.go — the marketing-category predicate + body-footer
// injection helpers. The category set is the union of the five
// marketing buckets defined in §3.2 of the notification-preferences
// paper. Keeping IsMarketing and footer-injection together with the
// header builder makes "what does this package own?" one answer:
// everything about composing a marketing-class email.

package marketing

import "strings"

// Category is the canonical marketing-class identifier as it appears
// on SendRequest.Category. Non-marketing categories (transactional,
// regulatory, alerts) do not get headers or footers — the router emits
// them as plain transactional sends through the existing path.
//
// Source of truth: internal/preferences.knownMarketingCategory matches
// the same five values. Any addition there MUST land here too.
const (
	CategoryPromotional   = "promotional"
	CategoryNewsletter    = "newsletter"
	CategoryProductUpdate = "product_update"
	CategoryPartnerOffer  = "partner_offer"
	CategoryResearch      = "research"
)

// IsMarketing reports whether the given category is one of the
// marketing buckets. The check is case-insensitive + trim-tolerant so
// callers can pass values straight off the wire without normalising.
func IsMarketing(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case CategoryPromotional, CategoryNewsletter, CategoryProductUpdate, CategoryPartnerOffer, CategoryResearch:
		return true
	}
	return false
}

// HTMLFooter is the unsubscribe block appended to marketing-class HTML
// emails. Inline styles keep the rendering predictable in clients that
// strip <style> blocks; the link target is the same HTTPS URL as the
// List-Unsubscribe header so a click in the body and a click in the
// native unsubscribe UI both reach the same endpoint.
func HTMLFooter(url string) string {
	return `<hr>
<p style="color: #666; font-size: 12px;">
  Unsubscribe: <a href="` + url + `">click here</a>
</p>`
}

// PlainFooter is the equivalent for text/plain bodies. The "--" prefix
// is the conventional signature delimiter (RFC 3676) so mail clients
// that show signatures collapsed still render the link.
func PlainFooter(url string) string {
	return "--\nUnsubscribe: " + url
}

// AppendHTMLFooter returns body + "\n" + HTMLFooter(url). When url is
// empty we return body unchanged — callers that already injected the
// footer don't double-up.
func AppendHTMLFooter(body, url string) string {
	if strings.TrimSpace(url) == "" {
		return body
	}
	if body == "" {
		return HTMLFooter(url)
	}
	return body + "\n" + HTMLFooter(url)
}

// AppendPlainFooter is the text/plain counterpart of AppendHTMLFooter.
func AppendPlainFooter(body, url string) string {
	if strings.TrimSpace(url) == "" {
		return body
	}
	if body == "" {
		return PlainFooter(url)
	}
	return body + "\n\n" + PlainFooter(url)
}
