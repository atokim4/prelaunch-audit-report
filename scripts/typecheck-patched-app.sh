#!/usr/bin/env bash
# Applies every patch from the sample report to a copy of the demo app, installs the app's real
# dependencies (Next.js, Stripe, Supabase) and type-checks the result. Needs network for npm install.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cp -r "$root/test/fixtures/broken-notes-app/." "$work/"
for patch in "$root"/examples/sample-report/patches/*.diff; do
  (cd "$work" && git apply "$patch")
done

cd "$work"
npm install --no-audit --no-fund --ignore-scripts --silent
npm install --no-audit --no-fund --ignore-scripts --silent \
  typescript@5.9.3 @types/node@22.20.5 @types/react@19.1.12 @types/react-dom@19.1.9
npx tsc --noEmit -p . --skipLibCheck
echo "patched app type-checks"
