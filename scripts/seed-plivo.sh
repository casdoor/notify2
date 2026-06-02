#!/usr/bin/env bash
# Seed brand/liquidity/plivo/* in kms.hanzo.ai.
#
# This is the fleet default every brand falls back to when it has not
# wired its own Plivo override via the platform UI. Without these four
# rows, /v1/notify/brand/plivo returns "fail-closed" for any brand
# without its own creds — the multi-brand resolver REFUSES to invent a
# hard-coded fallback.
#
# Required env (no hard-coded values in this repo):
#   KMS_ENDPOINT       — kms.hanzo.ai (or dev URL)
#   IAM_ENDPOINT       — hanzo.id    (or dev URL)
#   KMS_CLIENT_ID      — service account client_id
#   KMS_CLIENT_SECRET  — service account client_secret
#
# Interactive: prompts for each Plivo value. Values are read from stdin
# and piped to `kms put --stdin`, so they never appear in `ps`,
# /proc/cmdline, or your shell history.
#
# Usage:
#   make seed-plivo
# or:
#   ./scripts/seed-plivo.sh

set -euo pipefail

ORG="${SEED_BRAND:-liquidity}"

if ! command -v kms >/dev/null; then
	echo "kms: CLI not found on PATH. Build it from ~/work/hanzo/kms/cmd/kms or 'go install github.com/hanzoai/kms/cmd/kms@latest'." >&2
	exit 1
fi

: "${KMS_ENDPOINT:?KMS_ENDPOINT is required (e.g. https://kms.hanzo.ai)}"
: "${IAM_ENDPOINT:?IAM_ENDPOINT is required (e.g. https://hanzo.id)}"
: "${KMS_CLIENT_ID:?KMS_CLIENT_ID is required}"
: "${KMS_CLIENT_SECRET:?KMS_CLIENT_SECRET is required}"

prompt_secret() {
	# $1: human label, $2: variable name to set
	local label="$1" varname="$2" value
	# -s: don't echo (typed credentials should never hit the terminal)
	read -r -s -p "${label}: " value
	echo
	printf -v "$varname" '%s' "$value"
}

prompt_visible() {
	local label="$1" varname="$2" value
	read -r -p "${label}: " value
	printf -v "$varname" '%s' "$value"
}

echo "Seeding KMS for brand=${ORG} (fleet default)."
echo "Values are written to ${KMS_ENDPOINT} under brand/${ORG}/plivo/*."
echo

prompt_secret  "Plivo Auth ID"                    PLIVO_AUTH_ID
prompt_secret  "Plivo Auth Token"                 PLIVO_AUTH_TOKEN
prompt_visible "Plivo Sender ID (E.164 or UUID)"  PLIVO_SENDER_ID
prompt_visible "Plivo From Email (optional, RET to skip)" PLIVO_FROM_EMAIL

kms_put() {
	local path="$1" value="$2"
	# Pipe via stdin to keep secrets off argv.
	printf '%s' "$value" | kms \
		--addr "${KMS_ENDPOINT}" \
		--iam-addr "${IAM_ENDPOINT}" \
		--org "${ORG}" \
		put "${path}" --stdin
}

kms_put "brand/${ORG}/plivo/auth-id"    "$PLIVO_AUTH_ID"
kms_put "brand/${ORG}/plivo/auth-token" "$PLIVO_AUTH_TOKEN"
kms_put "brand/${ORG}/plivo/sender-id"  "$PLIVO_SENDER_ID"
if [ -n "$PLIVO_FROM_EMAIL" ]; then
	kms_put "brand/${ORG}/plivo/from-email" "$PLIVO_FROM_EMAIL"
fi

echo
echo "Done. Verify with: kms --org ${ORG} get brand/${ORG}/plivo/sender-id"
