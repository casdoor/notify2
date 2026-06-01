// notifyd — Hanzo Notify daemon.
//
// HTTP service that exposes the `/v1/notify/*` surface (see the Liquid
// Notify OpenAPI spec at openapi/notify.yaml) on top of the
// github.com/hanzoai/notify library. White-label consumers
// (liquidityio/notify, mlcclub/notify, etc.) ship a thin Docker
// wrapper around this binary; they pin a tag of hanzoai/notify and
// inherit the routes + provider plumbing without forking any Go code.
//
// Provider selection is env-driven; see the README for the canonical
// taxonomy. Plivo is the default for SMS/WhatsApp/Voice; SMTP relay is
// the default for email until Plivo Email is provisioned.
//
// Durable substrate: subscribes to a hanzoai/tasks queue when
// TASKS_URL is set; otherwise runs HTTP-only (callers POST directly).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/hanzoai/notify"
	"github.com/hanzoai/notify/service/mail"
	"github.com/hanzoai/notify/service/plivo"
)

// version is stamped at build time via -ldflags.
var version = "dev"

const (
	envPort = "PORT"

	envProvider      = "NOTIFY_PROVIDER" // "plivo" | "mail" | "plivo,mail" (comma list)
	envPlivoAuthID   = "PLIVO_AUTH_ID"
	envPlivoToken    = "PLIVO_AUTH_TOKEN"
	envPlivoFrom     = "PLIVO_FROM_NUMBER"
	envSMTPHost      = "SMTP_HOST"
	envSMTPPort      = "SMTP_PORT"
	envSMTPUser      = "SMTP_USER"
	envSMTPPass      = "SMTP_PASSWORD"
	envSenderEmail   = "SENDER_EMAIL"
	envSenderName    = "SENDER_NAME"
	envServiceName   = "NOTIFY_SERVICE_NAME"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	n, err := buildNotifier(logger)
	if err != nil {
		logger.Error("build notifier", "error", err)
		os.Exit(2)
	}

	srv := newServer(logger, n)

	port := envOr(envPort, "8090")
	hs := &http.Server{
		Addr:              ":" + port,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	go func() {
		logger.Info("notifyd listening",
			"port", port,
			"version", version,
			"service", envOr(envServiceName, "hanzoai/notify"))
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http serve", "error", err)
			os.Exit(2)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	logger.Info("notifyd shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = hs.Shutdown(ctx)
}

// buildNotifier constructs the *notify.Notify with the providers selected
// by NOTIFY_PROVIDER. Empty / unknown defaults to "plivo,mail".
func buildNotifier(logger *slog.Logger) (*notify.Notify, error) {
	want := envOr(envProvider, "plivo,mail")
	chosen := splitCSV(want)

	n := notify.New()
	for _, p := range chosen {
		switch strings.ToLower(p) {
		case "plivo":
			svc, err := buildPlivo()
			if err != nil {
				logger.Warn("plivo provider unavailable", "error", err)
				continue
			}
			n.UseServices(svc)
			logger.Info("provider registered", "kind", "plivo")
		case "mail", "smtp":
			svc, err := buildMail()
			if err != nil {
				logger.Warn("mail provider unavailable", "error", err)
				continue
			}
			n.UseServices(svc)
			logger.Info("provider registered", "kind", "mail")
		default:
			logger.Warn("unknown NOTIFY_PROVIDER entry", "entry", p)
		}
	}
	return n, nil
}

func buildPlivo() (*plivo.Service, error) {
	authID := os.Getenv(envPlivoAuthID)
	token := os.Getenv(envPlivoToken)
	from := os.Getenv(envPlivoFrom)
	if authID == "" || token == "" {
		return nil, fmt.Errorf("PLIVO_AUTH_ID and PLIVO_AUTH_TOKEN are required")
	}
	if from == "" {
		return nil, fmt.Errorf("PLIVO_FROM_NUMBER is required (E.164, e.g. +12062598397)")
	}
	return plivo.New(
		&plivo.ClientOptions{AuthID: authID, AuthToken: token},
		&plivo.MessageOptions{Source: from},
	)
}

func buildMail() (*mail.Mail, error) {
	host := os.Getenv(envSMTPHost)
	if host == "" {
		return nil, fmt.Errorf("SMTP_HOST is required for mail provider")
	}
	port := envOr(envSMTPPort, "25")
	sender := envOr(envSenderEmail, "noreply@localhost")
	m := mail.New(sender, host+":"+port)
	if u := os.Getenv(envSMTPUser); u != "" {
		m.AuthenticateSMTP("", u, os.Getenv(envSMTPPass), host)
	}
	return m, nil
}

// ── HTTP surface ─────────────────────────────────────────────────────

type sendReq struct {
	Recipients []string `json:"recipients"`
	Subject    string   `json:"subject"`
	Body       string   `json:"body"`
	Channel    string   `json:"channel,omitempty"` // optional: sms | email | whatsapp
}

type sendResp struct {
	Sent       bool   `json:"sent"`
	Recipients int    `json:"recipients"`
	Error      string `json:"error,omitempty"`
}

func newServer(logger *slog.Logger, n *notify.Notify) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	r.Get("/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"version": version,
			"service": envOr(envServiceName, "hanzoai/notify"),
		})
	})

	r.Route("/v1/notify", func(r chi.Router) {
		// POST /v1/notify/send — generic dispatch. All registered
		// providers are notified.
		r.Post("/send", func(w http.ResponseWriter, req *http.Request) {
			var body sendReq
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, sendResp{Error: "invalid JSON: " + err.Error()})
				return
			}
			if len(body.Recipients) == 0 {
				writeJSON(w, http.StatusBadRequest, sendResp{Error: "recipients required"})
				return
			}
			ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
			defer cancel()

			// notify.Notify.Send accepts a single subject + message
			// and dispatches to every registered service. Per-recipient
			// fan-out is the provider's responsibility (e.g. plivo Service
			// keeps a destinations slice). To target a specific set of
			// recipients on demand we rebuild a transient *Notify with
			// receivers set on each provider — keeps the daemon stateless.
			tn := notify.New()
			for _, p := range body.Recipients {
				_ = p // recipients fed into the providers via their AddReceivers
			}

			// Rebuild providers scoped to this request's recipients.
			if svc, err := buildPlivo(); err == nil {
				svc.AddReceivers(body.Recipients...)
				tn.UseServices(svc)
			}
			if svc, err := buildMail(); err == nil {
				svc.AddReceivers(body.Recipients...)
				tn.UseServices(svc)
			}
			if err := tn.Send(ctx, body.Subject, body.Body); err != nil {
				logger.Error("send", "error", err, "recipients", len(body.Recipients))
				writeJSON(w, http.StatusBadGateway, sendResp{
					Error:      err.Error(),
					Recipients: len(body.Recipients),
				})
				return
			}
			writeJSON(w, http.StatusOK, sendResp{Sent: true, Recipients: len(body.Recipients)})
		})
	})

	return r
}

// ── helpers ─────────────────────────────────────────────────────────

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
