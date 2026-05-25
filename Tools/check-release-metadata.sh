#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="$ROOT_DIR/Sources/Traversio/TraversioVersion.swift"
TRANSPORT_CLIENT_FILE="$ROOT_DIR/Sources/Traversio/TransportProtocol/SSHTransportProtocolClient.swift"

usage() {
  cat <<'USAGE'
Usage:
  Tools/check-release-metadata.sh [expected-version]

Checks that the source release version and SSH client identification banner
match the expected release version. If no version is passed, the script uses
TRAVERSIO_RELEASE_VERSION or the exact git tag pointing at HEAD.

Examples:
  Tools/check-release-metadata.sh 1.0.0
  TRAVERSIO_RELEASE_VERSION=1.0.0 Tools/check-release-metadata.sh
USAGE
}

case "${1:-}" in
  -h|--help|help)
    usage
    exit 0
    ;;
esac

expected_version="${1:-${TRAVERSIO_RELEASE_VERSION:-}}"
if [[ -z "$expected_version" ]]; then
  tag="$(
    git -C "$ROOT_DIR" tag --points-at HEAD \
      | sed -E 's/^v//' \
      | grep -E '^[0-9]+[.][0-9]+[.][0-9]+$' \
      | sort -V \
      | tail -n 1
  )"
  expected_version="$tag"
fi

if [[ -z "$expected_version" ]]; then
  echo "error: pass an expected version or run this check on an exact release tag." >&2
  exit 64
fi

source_version="$(
  sed -nE 's/^[[:space:]]*package static let version = "([^"]+)"/\1/p' "$VERSION_FILE"
)"

if [[ "$source_version" != "$expected_version" ]]; then
  echo "error: TraversioRelease.version is $source_version, expected $expected_version." >&2
  exit 1
fi

expected_software_version="Traversio_${expected_version}"
expected_identification="SSH-2.0-${expected_software_version}"

if ! grep -F 'package static let sshSoftwareVersion = "Traversio_\(version)"' "$VERSION_FILE" >/dev/null; then
  echo "error: SSH software version must be derived from TraversioRelease.version." >&2
  exit 1
fi

if ! grep -F 'package static let sshIdentificationRawValue = "SSH-2.0-\(sshSoftwareVersion)"' "$VERSION_FILE" >/dev/null; then
  echo "error: SSH identification raw value must be derived from TraversioRelease.sshSoftwareVersion." >&2
  exit 1
fi

if ! grep -F 'uncheckedRawValue: TraversioRelease.sshIdentificationRawValue' "$TRANSPORT_CLIENT_FILE" >/dev/null; then
  echo "error: default client identification must use TraversioRelease.sshIdentificationRawValue." >&2
  exit 1
fi

if ! grep -F 'softwareVersion: TraversioRelease.sshSoftwareVersion' "$TRANSPORT_CLIENT_FILE" >/dev/null; then
  echo "error: default client identification must use TraversioRelease.sshSoftwareVersion." >&2
  exit 1
fi

old_banner_matches="$(mktemp)"
trap 'rm -f "$old_banner_matches"' EXIT

if grep -R -n -E 'Traversio_0[.]1|SSH-2[.]0-Traversio_0[.]1' \
  "$ROOT_DIR/Sources" "$ROOT_DIR/Tests" "$ROOT_DIR/README.md" "$ROOT_DIR/CHANGELOG.md" >"$old_banner_matches"; then
  cat "$old_banner_matches" >&2
  echo "error: found stale Traversio 0.1 SSH identification text." >&2
  exit 1
fi

echo "Traversio release metadata matches $expected_version."
echo "SSH identification: $expected_identification"
