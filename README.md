# Traversio

Traversio is a Swift SSH2 client library for Apple platforms.

Documentation and examples: https://traversio.org

The package provides a native Swift API for common SSH client workflows:

- command execution and streamed exec sessions
- PTY-backed interactive shells
- SFTP metadata, file, directory, and transfer operations
- single-file SCP compatibility helpers
- local, dynamic, remote, streamlocal, proxy, and ProxyJump forwarding paths
- explicit host-key trust policy
- password, keyboard-interactive, public-key, callback-backed, and SSH agent-backed authentication
- OpenSSH private-key loading, metadata inspection, and key generation

## Package Requirements

- Swift `6.2`
- Apple platform targets declared by `Package.swift`:
  - macOS 10.15
  - iOS 13
  - tvOS 13
  - watchOS 6
  - visionOS 1

At runtime, Traversio uses the newer Apple transport APIs on platform release 26 and later. Older supported releases use compatibility transport and listener backends behind the same public API.

## Release Maturity

The `1.0.x` line is Traversio's V1 API and validation boundary. It is suitable
for targeted application integration against the documented feature set, but it
is not a claim that every deployment environment has production-maturity
evidence. Applications should keep their own rollout, reconnect, credential
storage, and operational gating policies above the library.

## Add The Package

```swift
dependencies: [
    .package(
        url: "https://github.com/GitSwiftHQ/Traversio.git",
        from: "1.0.0"
    )
]
```

Then add the product to your target:

```swift
.target(
    name: "ExampleApp",
    dependencies: [
        .product(name: "Traversio", package: "Traversio")
    ]
)
```

## First Connection

```swift
import Traversio

func runRemoteUname() async throws -> String {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "deploy",
        authentication: .password("correct horse battery staple"),
        hostKeyPolicy: .knownHostsFile("/Users/me/.ssh/known_hosts")
    )

    return try await SSHClient.withConnection(configuration: configuration) { connection in
        let result = try await connection.execute("uname -a")
        return String(decoding: result.standardOutput, as: UTF8.self)
    }
}
```

## Lifecycle And Cancellation Boundary

`SSHClient.connect(configuration:)` returns a long-lived `SSHConnection`.
`SSHClient.withConnection(configuration:_:)` closes that connection when the
closure returns or throws. Sessions, SFTP clients, and forwarding helpers created
from a connection become invalid when the connection closes.

Long-running operations observe Swift task cancellation and usually surface
`CancellationError` when cancellation wins the race. If transport loss, remote
disconnect, or a protocol failure arrives first, callers should handle the
corresponding Traversio error instead. Session transcript collectors and event
iterators attempt a best-effort `channel-close` on cancellation or early iterator
exit; that cleanup is not a guarantee that a peer which has already closed or
stopped reading will process it.

Forwarding helpers are closure-scoped. Local listener shutdown is best-effort:
after scope exit Traversio stops bridging data and closes late accepted
connections as soon as possible, but it does not promise the local port is
unconnectable at the exact instant the closure returns. Remote listener shutdown
sends the matching cancel request; if the server rejects that request, Traversio
closes the parent connection so the remote listener does not stay active on the
server.

## Security Boundary And Scope

Traversio requires an explicit host-key policy on every connection. It does not
fall back to accepting host keys implicitly; use `knownHostsFile`,
`trustOnFirstUse`, exact pinning, or another explicit policy.

Legacy `ssh-rsa` is disabled by default. Enable
`SSHLegacyAlgorithmOptions.sshRSA` only for a specific connection or jump-host
hop that still requires SHA-1 RSA host-key or userauth compatibility. That
switch controls built-in RSA keys, callback-backed public-key auth, and
SSH-agent-backed auth.

Unsupported transport algorithms and auth modes are not silently retried. The
current public surface intentionally defers hostbased auth, security-key auth,
X11 forwarding, auth-agent forwarding, local `ssh_config` parsing, mandatory
built-in trust-store persistence, and library-owned automatic reconnect.

## Validation

Run the deterministic test suite:

```bash
swift test
```

Run strict-concurrency checking:

```bash
swift build -Xswiftc -strict-concurrency=complete -Xswiftc -warn-concurrency
```

## Repository Layout

- `Sources/Traversio`: public Swift library and package-internal SSH implementation
- `Sources/TraversioCCrypto`: small C shims for packet crypto primitives used by the Swift target
- `Tests/TraversioTests`: deterministic Swift Testing coverage
- `CHANGELOG.md`: release notes
- `CONTRIBUTING.md`: contributor workflow

The source snapshot is intentionally limited to the public package, deterministic tests, and license/contribution material.

## License

Traversio is dual licensed:

- community license: `AGPL-3.0-or-later`
- commercial license: available separately from GitSwift LLC

Commercial licensing details are available at
<https://traversio.org/commercial-license>.

See `LICENSE`, `COPYING`, `COMMERCIAL-LICENSE.md`, and
`THIRD_PARTY_NOTICES.md`.
