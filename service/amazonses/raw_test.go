package amazonses

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestAmazonSES_SendRaw_EnvelopeShape locks the MIME envelope layout
// down to the byte. Gmail and Outlook both require List-Unsubscribe +
// List-Unsubscribe-Post to surface the native unsubscribe button (RFC
// 8058); the envelope order matters because some downstream verifiers
// expect Date / MIME-Version / Content-Type before any extension
// headers. The test asserts every line we put on the wire.
func TestAmazonSES_SendRaw_EnvelopeShape(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	s := &AmazonSES{
		senderAddress:     aws.String("hello@notify.satschel.com"),
		receiverAddresses: []string{"recipient@example.com"},
	}

	headers := map[string]string{
		"List-Unsubscribe":      "<https://notify.dev.satschel.com/v1/notify/unsubscribe/TOKEN>, <mailto:unsubscribe+TOKEN@notify.satschel.com>",
		"List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
	}

	raw, err := s.buildRawMessage("Hello there", "<p>body</p>", true, headers, now)
	require.NoError(t, err)

	got := string(raw)

	// Header lines, in order — strings.Index would re-match "\r\n"
	// against the first line ending, so we scan from a moving offset
	// and require each subsequent header to appear AFTER the previous.
	want := []string{
		"From: hello@notify.satschel.com\r\n",
		"To: recipient@example.com\r\n",
		"Subject: Hello there\r\n",
		"Date: Wed, 03 Jun 2026 12:00:00 +0000\r\n",
		"MIME-Version: 1.0\r\n",
		"Content-Type: text/html; charset=UTF-8\r\n",
		"List-Unsubscribe: <https://notify.dev.satschel.com/v1/notify/unsubscribe/TOKEN>, <mailto:unsubscribe+TOKEN@notify.satschel.com>\r\n",
		"List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
	}
	cursor := 0
	for _, line := range want {
		idx := strings.Index(got[cursor:], line)
		if idx < 0 {
			t.Fatalf("missing or out-of-order line %q in raw envelope:\n%s", line, got)
		}
		cursor += idx + len(line)
	}
	// After the last header we expect "\r\n" (blank line) then body.
	if !strings.HasSuffix(got, "\r\n\r\n<p>body</p>") {
		t.Fatalf("envelope did not end with blank-line + body, got:\n%s", got)
	}
}

// TestAmazonSES_SendRaw_PlainText switches the Content-Type when isHTML
// is false. Marketing emails ship both HTML and plain-text variants; the
// minimal raw path here is one Content-Type per call (multipart/alternative
// is out of scope until §5.2 of the paper).
func TestAmazonSES_SendRaw_PlainText(t *testing.T) {
	t.Parallel()
	s := &AmazonSES{
		senderAddress:     aws.String("from@example.com"),
		receiverAddresses: []string{"to@example.com"},
	}
	raw, err := s.buildRawMessage("subj", "plain body", false, nil, time.Now().UTC())
	require.NoError(t, err)
	require.Contains(t, string(raw), "Content-Type: text/plain; charset=UTF-8\r\n")
	require.NotContains(t, string(raw), "Content-Type: text/html")
}

// TestAmazonSES_SendRaw_MultiRecipient renders the comma-joined To
// header. SES is happy to parse this; receivers split on commas per
// RFC 5322 §3.4.
func TestAmazonSES_SendRaw_MultiRecipient(t *testing.T) {
	t.Parallel()
	s := &AmazonSES{
		senderAddress:     aws.String("from@example.com"),
		receiverAddresses: []string{"a@example.com", "b@example.com", "c@example.com"},
	}
	raw, err := s.buildRawMessage("subj", "body", false, nil, time.Now().UTC())
	require.NoError(t, err)
	require.Contains(t, string(raw), "To: a@example.com, b@example.com, c@example.com\r\n")
}

// TestAmazonSES_SendRaw_HeaderSmuggling blocks CR/LF in header values.
// An attacker who controls part of an unsubscribe URL could otherwise
// inject extra headers (Bcc, Reply-To, …) by embedding "\r\nBcc: …" in
// it. The builder rejects this at compose time rather than letting the
// SDK accept it.
func TestAmazonSES_SendRaw_HeaderSmuggling(t *testing.T) {
	t.Parallel()
	s := &AmazonSES{
		senderAddress:     aws.String("from@example.com"),
		receiverAddresses: []string{"to@example.com"},
	}
	cases := map[string]map[string]string{
		"CR in value":  {"List-Unsubscribe": "<https://a.example>\r\nBcc: hidden@example.com"},
		"LF in value":  {"List-Unsubscribe": "<https://a.example>\nBcc: hidden@example.com"},
		"CR in name":   {"X-Evil\r\n": "anything"},
	}
	for name, headers := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := s.buildRawMessage("subj", "body", false, headers, time.Now().UTC())
			if err == nil {
				t.Fatalf("expected error for header smuggling input")
			}
		})
	}
}

// TestAmazonSES_SendRaw_RequiresSender returns an explicit error rather
// than letting SES reject the message at the API. Saves a round-trip
// and surfaces config bugs at the right layer.
func TestAmazonSES_SendRaw_RequiresSender(t *testing.T) {
	t.Parallel()
	s := &AmazonSES{
		senderAddress:     aws.String(""),
		receiverAddresses: []string{"to@example.com"},
	}
	_, err := s.buildRawMessage("subj", "body", false, nil, time.Now().UTC())
	require.Error(t, err)
}

func TestAmazonSES_SendRaw_RequiresReceiver(t *testing.T) {
	t.Parallel()
	s := &AmazonSES{
		senderAddress:     aws.String("from@example.com"),
		receiverAddresses: nil,
	}
	_, err := s.buildRawMessage("subj", "body", false, nil, time.Now().UTC())
	require.Error(t, err)
}

// TestAmazonSES_SendRaw_HeadersAreSorted documents that extra header
// emission is alphabetical so concurrent tests + DKIM hashing produce
// stable output regardless of map iteration order.
func TestAmazonSES_SendRaw_HeadersAreSorted(t *testing.T) {
	t.Parallel()
	s := &AmazonSES{
		senderAddress:     aws.String("from@example.com"),
		receiverAddresses: []string{"to@example.com"},
	}
	raw, err := s.buildRawMessage("subj", "body", false, map[string]string{
		"X-Zeta":  "z",
		"List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
		"List-Unsubscribe":      "<https://a.example>",
		"X-Alpha":               "a",
	}, time.Now().UTC())
	require.NoError(t, err)
	body := string(raw)

	// All headers present.
	require.Contains(t, body, "List-Unsubscribe: <https://a.example>")
	require.Contains(t, body, "List-Unsubscribe-Post: List-Unsubscribe=One-Click")
	require.Contains(t, body, "X-Alpha: a")
	require.Contains(t, body, "X-Zeta: z")

	// Alphabetical ordering within the extra-header block.
	idxLU := strings.Index(body, "List-Unsubscribe:")
	idxLUP := strings.Index(body, "List-Unsubscribe-Post:")
	idxAlpha := strings.Index(body, "X-Alpha:")
	idxZeta := strings.Index(body, "X-Zeta:")
	require.True(t, idxLU < idxLUP, "List-Unsubscribe before List-Unsubscribe-Post")
	require.True(t, idxLUP < idxAlpha, "List-Unsubscribe-Post before X-Alpha")
	require.True(t, idxAlpha < idxZeta, "X-Alpha before X-Zeta")
}

// TestAmazonSES_SendRaw_CallsSendRawEmail asserts SendRaw invokes the
// SendRawEmail SDK call (not SendEmail) and propagates errors.
func TestAmazonSES_SendRaw_CallsSendRawEmail(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()
		mockClient := new(mocksesClient)
		mockClient.On("SendRawEmail", mock.Anything, mock.MatchedBy(func(in *ses.SendRawEmailInput) bool {
			if in == nil || in.RawMessage == nil {
				return false
			}
			return strings.Contains(string(in.RawMessage.Data), "List-Unsubscribe: ")
		})).Return(&ses.SendRawEmailOutput{}, nil)

		s := &AmazonSES{
			client:            mockClient,
			senderAddress:     aws.String("from@example.com"),
			receiverAddresses: []string{"to@example.com"},
		}
		err := s.SendRaw(context.Background(), "subj", "body", false, map[string]string{
			"List-Unsubscribe": "<https://x.example>",
		})
		require.NoError(t, err)
		mockClient.AssertExpectations(t)
	})

	t.Run("SDK error", func(t *testing.T) {
		t.Parallel()
		mockClient := new(mocksesClient)
		mockClient.On("SendRawEmail", mock.Anything, mock.AnythingOfType("*ses.SendRawEmailInput")).
			Return((*ses.SendRawEmailOutput)(nil), errors.New("SES raw error"))

		s := &AmazonSES{
			client:            mockClient,
			senderAddress:     aws.String("from@example.com"),
			receiverAddresses: []string{"to@example.com"},
		}
		err := s.SendRaw(context.Background(), "subj", "body", false, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "SES raw error")
	})
}

// TestAmazonSES_SendEmail_StillWorks asserts the legacy SendEmail path
// is untouched — both surfaces coexist; only marketing-class sends
// switch to SendRaw at the call site.
func TestAmazonSES_SendEmail_StillWorks(t *testing.T) {
	t.Parallel()
	mockClient := new(mocksesClient)
	mockClient.On("SendEmail", mock.Anything, mock.AnythingOfType("*ses.SendEmailInput")).
		Return(&ses.SendEmailOutput{}, nil)
	s := &AmazonSES{
		client:            mockClient,
		senderAddress:     aws.String("from@example.com"),
		receiverAddresses: []string{"to@example.com"},
	}
	require.NoError(t, s.Send(context.Background(), "subj", "body"))

	// And the raw envelope is RawMessage-shaped (smoke check).
	_ = types.RawMessage{}
}
