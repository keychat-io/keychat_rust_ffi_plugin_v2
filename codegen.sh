#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

flutter_rust_bridge_codegen generate \
  --rust-input "crate::api_v2" \
  --rust-root rust/ \
  --dart-output lib/
