# Contributing

Thanks for considering a contribution to Traversio.

## Development Requirements

- Xcode toolchain with Swift `6.2`
- macOS development environment for the current Apple-first package
- `jq` for the public API baseline check
- Network access only for tests or experiments that you explicitly choose to run outside the deterministic suite

## Local Checks

Run these before opening a pull request:

```bash
swift test
swift build -Xswiftc -strict-concurrency=complete -Xswiftc -warn-concurrency
Tools/check-public-api.sh
Tools/check-release-metadata.sh 1.0.0
```

Use focused tests while iterating:

```bash
swift test --filter SSHAgentClient
swift test --filter SSHTransportProtocolClientSFTP
swift test --filter SSHClient
```

## Test Style

New tests should use Swift Testing:

```swift
import Testing

@Test
func exampleBehavior() throws {
    #expect(true)
}
```

Prefer deterministic protocol fixtures and exact byte expectations for packet, wire, parser, and algorithm behavior.

## Code Style

- Keep public APIs small and deliberate.
- Keep SSH protocol layers separated: transport, wire framing, transport protocol, authentication, connection/channel routing, SFTP, forwarding, and public client wrappers.
- Prefer value types for protocol data and actors for mutable shared state.
- Make cancellation and lifetime ownership explicit.
- Keep security-sensitive behavior fail-closed.
- Add comments only where they clarify a non-obvious invariant or protocol rule.

## Debugging Discipline

Bug fixes should start from the real failure path: packet bytes, state transitions, task ownership, transport callbacks, API contracts, or documented server behavior.

Before changing code:

- reproduce or narrow the failure with the smallest useful test, fixture, packet trace, or log
- identify the invariant that failed
- fix the implementation at that boundary
- add regression coverage that proves the invariant

## Pull Request Notes

Include:

- the behavior changed
- the reason for the change
- validation commands run
- any protocol references used

For security-sensitive changes, describe the failure mode and why the new behavior is conservative.

## Public API Baseline

`API/public-api-baseline.tsv` records the current public Swift symbol graph in a
stable, reviewable format. Run `Tools/check-public-api.sh` before release
candidate cuts to catch source-compatibility changes.

When a public API change is intentional, regenerate the baseline and explain the
source-compatibility effect in the pull request and changelog:

```bash
Tools/check-public-api.sh update
```

## Release Metadata

`Sources/Traversio/TraversioVersion.swift` is the source release-version value.
The SSH client identification banner is derived from that value, so release
version updates should start there.

Before tagging a release, run:

```bash
Tools/check-release-metadata.sh 1.0.0
```

When running on a checked-out release tag, the version argument can be omitted;
the script reads the exact tag pointing at `HEAD`.
