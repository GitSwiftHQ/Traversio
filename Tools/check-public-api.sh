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

# Declaration text in the symbol graph depends on the SwiftPM build system, not
# on the compiler version. The Swift Build build system emits symbol graphs from
# the compiler during the build, so declarations keep the type spelling written
# in source. The native build system extracts them from the built module with
# fully qualified type spelling. Pin the build system so the baseline does not
# change when a toolchain changes its default.
BUILD_SYSTEM="swiftbuild"

if ! DUMP_OUTPUT="$(
  swift package \
    --build-system "$BUILD_SYSTEM" \
    dump-symbol-graph \
    --minimum-access-level public \
    --skip-synthesized-members 2>&1
)"; then
  printf '%s\n' "$DUMP_OUTPUT" >&2
  echo "error: swift package dump-symbol-graph failed." >&2
  exit 1
fi

# Read the graph from the directory this run reports so a stale graph left by
# another build system or toolchain under .build is never compared.
SYMBOL_GRAPH_DIR="$(printf '%s\n' "$DUMP_OUTPUT" | sed -n 's/^Files written to //p' | tail -n 1)"
SYMBOL_GRAPH="$SYMBOL_GRAPH_DIR/Traversio.symbols.json"

if [[ -z "$SYMBOL_GRAPH_DIR" || ! -f "$SYMBOL_GRAPH" ]]; then
  printf '%s\n' "$DUMP_OUTPUT" >&2
  echo "error: Traversio.symbols.json was not produced by swift package dump-symbol-graph." >&2
  exit 66
fi

CURRENT="$TMP_DIR/public-api-baseline.tsv"

{
  echo "# Traversio public API baseline"
  echo "# Generated with: swift package --build-system $BUILD_SYSTEM dump-symbol-graph --minimum-access-level public --skip-synthesized-members"
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
