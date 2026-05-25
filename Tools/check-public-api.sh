#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE="$ROOT_DIR/API/public-api-baseline.tsv"
MODE="${1:-check}"

usage() {
  cat <<'USAGE'
Usage:
  Tools/check-public-api.sh [check|update]

Commands:
  check   Compare the current public Swift symbol graph against API/public-api-baseline.tsv.
  update  Regenerate API/public-api-baseline.tsv from the current source tree.
USAGE
}

case "$MODE" in
  check|update)
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 64
    ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required to extract the public API baseline." >&2
  exit 69
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cd "$ROOT_DIR"

swift package dump-symbol-graph \
  --minimum-access-level public \
  --skip-synthesized-members >/dev/null

SYMBOL_GRAPH="$(
  find "$ROOT_DIR/.build" \
    -path '*/symbolgraph/Traversio.symbols.json' \
    -type f \
    -print \
    | sort \
    | tail -n 1
)"

if [[ -z "$SYMBOL_GRAPH" ]]; then
  echo "error: Traversio.symbols.json was not produced by swift package dump-symbol-graph." >&2
  exit 66
fi

CURRENT="$TMP_DIR/public-api-baseline.tsv"

{
  echo "# Traversio public API baseline"
  echo "# Generated with: swift package dump-symbol-graph --minimum-access-level public --skip-synthesized-members"
  echo "# Format: kind<TAB>path<TAB>precise-symbol-id<TAB>declaration"
  jq -r '
    .symbols
    | sort_by((.pathComponents | join(".")), .kind.identifier, .identifier.precise)
    | .[]
    | [
        .kind.identifier,
        (.pathComponents | join(".")),
        .identifier.precise,
        ((.declarationFragments // .names.subHeading // []) | map(.spelling) | join(""))
      ]
    | @tsv
  ' "$SYMBOL_GRAPH"
} > "$CURRENT"

if [[ "$MODE" == "update" ]]; then
  cp "$CURRENT" "$BASELINE"
  echo "Updated $BASELINE"
  exit 0
fi

if [[ ! -f "$BASELINE" ]]; then
  echo "error: missing public API baseline at $BASELINE" >&2
  echo "run Tools/check-public-api.sh update to create it intentionally" >&2
  exit 66
fi

diff -u "$BASELINE" "$CURRENT"
