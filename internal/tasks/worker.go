// Package tasks wires Hanzo Notify into hanzoai/tasks as a durable
// execution substrate.
//
// One workflow type, NotifySendWorkflow, takes a SendRequest and walks
// the same code path the sync HTTP handler does:
//
//	resolve provider → render template → call library Send →
//	write message row → write meter row → set status
//
// The worker registers itself on a single task queue ("notify-send").
// Async POST /v1/notify/send Dispatch hands off to ExecuteWorkflow; the
// sync path calls the same internal SendOnce function directly.
package tasks

import (
	"context"
	"errors"
	"fmt"

	"github.com/hanzoai/tasks/pkg/sdk/client"
	"github.com/hanzoai/tasks/pkg/sdk/worker"
	luxlog "github.com/luxfi/log"
)

// Config is the worker's runtime configuration. Mirrors auto's engine.Config.
type Config struct {
	// Address is the tasks server ZAP endpoint (host:port).
	Address string

	// Namespace is the tasks namespace this worker serves.
	Namespace string

	// TaskQueue is the queue both the workflow and activities sit on.
	TaskQueue string
}

// Worker owns the tasks client + worker lifecycle. Mirrors auto's
// engine.Worker (we deliberately copy the shape because they're siblings).
type Worker struct {
	cfg     Config
	logger  luxlog.Logger
	cli     client.Client
	wk      worker.Worker
	started bool
	// activities is the type-checked closure surface the workflow calls;
	// kept as a pointer so registration sites and callers refer to the
	// same instance.
	activities *Activities
}

// New validates config and returns an un-started worker. The ZAP
// connection happens in Start so `--help`, `migrate`, and any non-serve
// command runs without a live tasks server.
func New(cfg Config, acts *Activities) (*Worker, error) {
	if cfg.Address == "" {
		return nil, errors.New("tasks: TASKS_ADDR is required")
	}
	if acts == nil {
		return nil, errors.New("tasks: Activities is required")
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "notify"
	}
	if cfg.TaskQueue == "" {
		cfg.TaskQueue = "notify-send"
	}
	return &Worker{
		cfg:        cfg,
		logger:     luxlog.New("module", "notify.tasks"),
		activities: acts,
	}, nil
}

// Start dials the tasks server, registers the workflow + activities,
// and starts the poll loop. Idempotent.
func (w *Worker) Start() error {
	if w.started {
		return nil
	}
	cli, err := client.Dial(client.Options{
		HostPort:  w.cfg.Address,
		Namespace: w.cfg.Namespace,
	})
	if err != nil {
		return fmt.Errorf("tasks: dial: %w", err)
	}
	wk := worker.New(cli, w.cfg.TaskQueue, worker.Options{Logger: w.logger})
	wk.RegisterWorkflow(NotifySendWorkflow)
	wk.RegisterActivity(w.activities.Deliver)
	if err := wk.Start(); err != nil {
		return err
	}
	w.cli = cli
	w.wk = wk
	w.started = true
	return nil
}

// Stop unblocks poll loops and tears down subscriptions.
func (w *Worker) Stop() {
	if !w.started {
		return
	}
	w.wk.Stop()
	w.started = false
}

// Started reports whether the worker is connected and active.
// Routes use this to decide async dispatch vs. 503.
func (w *Worker) Started() bool { return w.started }

// Dispatch enqueues a NotifySendWorkflow execution; returns the task id.
// The workflow runs asynchronously; clients poll via GET /v1/notify/
// messages/{id} (the workflow updates that record).
func (w *Worker) Dispatch(ctx context.Context, req SendInput) (string, error) {
	if !w.started {
		return "", errors.New("tasks: worker not started")
	}
	run, err := w.cli.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:        "notify-send-" + req.MessageID,
		TaskQueue: w.cfg.TaskQueue,
	}, "NotifySendWorkflow", req)
	if err != nil {
		return "", fmt.Errorf("tasks: dispatch: %w", err)
	}
	return run.GetID(), nil
}
