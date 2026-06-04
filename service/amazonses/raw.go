// raw.go — SendRaw is the SES SendRawEmail path that lets callers
// inject custom MIME headers the higher-level SendEmail API cannot
// express. The motivating use case is RFC 8058 List-Unsubscribe +
// List-Unsubscribe-Post pair, required by Gmail and Outlook bulk-sender
// policy (2024+) for every marketing-class email.
//
// SendEmail and SendRaw coexist: SendEmail stays the simple-path API
// for transactional sends (the SDK builds the MIME envelope itself);
// SendRaw is opt-in for marketing where the caller controls every
// header. There is no shared mutable state — each call constructs its
// own envelope so concurrent sends on the same AmazonSES instance are
// safe.

package amazonses

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
)

// SendRaw assembles a minimal RFC 5322 MIME message with the requested
// extra headers (e.g. List-Unsubscribe) and ships it via SES
// SendRawEmail. isHTML toggles between text/html and text/plain in the
// Content-Type header; the body is included verbatim — callers are
// expected to have already appended any footer they want visible.
//
// extraHeaders order is sorted alphabetically for byte-stable output
// (test assertions and any potential receiver-side DKIM hashing both
// benefit). Header values must be CRLF-free; we reject any value
// containing a CR or LF rather than silently letting it inject extra
// headers ("header smuggling" prevention).
func (a AmazonSES) SendRaw(ctx context.Context, subject, body string, isHTML bool, extraHeaders map[string]string) error {
	raw, err := a.buildRawMessage(subject, body, isHTML, extraHeaders, time.Now().UTC())
	if err != nil {
		return err
	}
	input := &ses.SendRawEmailInput{
		RawMessage: &types.RawMessage{Data: raw},
	}
	if _, err := a.client.SendRawEmail(ctx, input); err != nil {
		return fmt.Errorf("send raw mail using Amazon SES service: %w", err)
	}
	return nil
}

// buildRawMessage assembles the MIME bytes. Exposed at package scope so
// tests can assert envelope shape without paying the SDK round-trip.
//
// Envelope shape (CRLF line endings, RFC 5322 / RFC 5321 1000-char hard
// cap respected by short header values; long bodies are not folded
// because SES accepts them as-is):
//
//	From: <sender>
//	To: <r1>, <r2>, …
//	Subject: <subject>
//	Date: <RFC1123Z>
//	MIME-Version: 1.0
//	Content-Type: text/{html,plain}; charset=UTF-8
//	List-Unsubscribe: <https://…>, <mailto:…>     ← extraHeaders
//	List-Unsubscribe-Post: List-Unsubscribe=One-Click
//
//	<body>
func (a AmazonSES) buildRawMessage(subject, body string, isHTML bool, extraHeaders map[string]string, now time.Time) ([]byte, error) {
	sender := ""
	if a.senderAddress != nil {
		sender = *a.senderAddress
	}
	if strings.TrimSpace(sender) == "" {
		return nil, errors.New("amazonses: sender address is required for SendRaw")
	}
	if len(a.receiverAddresses) == 0 {
		return nil, errors.New("amazonses: at least one receiver address is required for SendRaw")
	}

	// Reject header values that would smuggle extra headers via CR/LF.
	// Subject is RFC 2047 encoded so a literal newline in the subject is
	// already neutralised; the extras need an explicit check.
	for k, v := range extraHeaders {
		if strings.ContainsAny(k, "\r\n") {
			return nil, fmt.Errorf("amazonses: header name %q contains CR/LF", k)
		}
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("amazonses: header %q value contains CR/LF", k)
		}
	}

	contentType := "text/plain; charset=UTF-8"
	if isHTML {
		contentType = "text/html; charset=UTF-8"
	}

	var buf bytes.Buffer
	writeHeader := func(name, value string) {
		buf.WriteString(name)
		buf.WriteString(": ")
		buf.WriteString(value)
		buf.WriteString("\r\n")
	}

	writeHeader("From", sender)
	writeHeader("To", strings.Join(a.receiverAddresses, ", "))
	// Subject may contain non-ASCII; encoded-word it per RFC 2047.
	writeHeader("Subject", mime.QEncoding.Encode("UTF-8", subject))
	writeHeader("Date", now.Format(time.RFC1123Z))
	writeHeader("MIME-Version", "1.0")
	writeHeader("Content-Type", contentType)

	// Sort extra headers so output is byte-stable for tests and any
	// DKIM-style signing experiments.
	if len(extraHeaders) > 0 {
		names := make([]string, 0, len(extraHeaders))
		for k := range extraHeaders {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			writeHeader(name, extraHeaders[name])
		}
	}

	// Blank line between headers and body, then body verbatim.
	buf.WriteString("\r\n")
	buf.WriteString(body)
	return buf.Bytes(), nil
}
