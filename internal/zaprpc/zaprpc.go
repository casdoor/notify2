// Package zaprpc is a stub for the native ZAP RPC surface that mirrors
// the HTTP /v1/notify/* routes.
//
// In the launch slice we ship HTTP only. ZAP procedures (notify.Send,
// notify.Message, notify.Providers, …) land once the corresponding
// hanzoai/zap server-side helpers stabilize in hanzoai/base or as a
// separate hanzoai/zap-server module. This file pins the package
// identifier so the structure compiles and consumers can import the
// Procedure constants today.
package zaprpc

// Procedure names follow the dot-prefixed convention used elsewhere in
// the Hanzo stack (kms.Get, tasks.ExecuteWorkflow, …). One opcode per
// HTTP verb-path; the routes/* package is the authoritative
// implementation, and ZAP procedures dispatch to the same handlers.
const (
	ProcedureSend          = "notify.Send"
	ProcedureMessage       = "notify.Message"
	ProcedureMessages      = "notify.Messages"
	ProcedureProviders     = "notify.Providers"
	ProcedureTemplates     = "notify.Templates"
	ProcedureEvents        = "notify.Events"
	ProcedureMetering      = "notify.Metering"
)
