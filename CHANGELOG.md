# Changelog

## Unreleased

## 1.0.2 - 2026-05-28

Connection lifecycle and timeout fixes:

- Background transport-failure teardown now clears lifecycle handlers and
  cancels keepalive/rekey scheduling even when the close path skips the normal
  SSH disconnect packet. This prevents retained connection coordinators and
  transport clients after network loss.
- `SSHTimeoutPolicy` now has a separate `hostKeyTrustTimeInterval`. Host-key
  confirmation can have a longer allowance without consuming the normal
  connection setup timeout.
- Public README security scope wording now lists unsupported capabilities
  directly and keeps release-status wording focused on application integration.

## 1.0.1 - 2026-05-27

Compatibility fix for migrated private keys:

- Added `SSHAuthenticationMethod.privateKeyPEM(...)` and
  `contentsOfFile:` helpers for apps that need to accept both OpenSSH
  `openssh-key-v1` private keys, unencrypted PKCS#8 `PRIVATE KEY` PEM
  containers for Ed25519/RSA/ECDSA, unencrypted traditional `EC PRIVATE KEY`
  PEM containers, and traditional `RSA PRIVATE KEY` PEM containers.
- Traditional `RSA PRIVATE KEY` PEM now supports passphrase-encrypted OpenSSL
  legacy PEM with AES-CBC and DES-EDE3-CBC `DEK-Info` headers. Encrypted PKCS#8
  `ENCRYPTED PRIVATE KEY` remains outside this release.
- `SSHAuthenticationMethodError` now exposes readable localized descriptions, so
  direct authentication input failures no longer surface through Foundation as
  opaque enum-domain numeric errors.
- Local OpenSSH matrix validation now includes real public-key login targets for
  OpenSSL Ed25519/RSA/ECDSA PKCS#8 keys, traditional RSA/EC PEM keys,
  encrypted traditional RSA PEM, and traditional RSA PEM with opt-in legacy
  `ssh-rsa` userauth.

## 1.0.0 - 2026-05-25

Version 1.0.0 establishes Traversio's first public Swift package surface.
This release covers the documented public feature set. Applications should
validate their own servers, proxy routes, credentials, network conditions, and
long-running workloads before using it as their default SSH engine.

Release hardening:

- `SSHOpenSSHPrivateKeyInfo` now exposes public OpenSSH private-key envelope
  metadata parsing for UI labels, capability displays, fingerprints, and
  import diagnostics without decrypting the private-key block.
- Added a checked public API baseline and `Tools/check-public-api.sh` release
  check so source-compatibility changes are explicit before release.
- Added a release-metadata check that keeps `TraversioRelease.version`, the
  source package release tag, and the SSH client identification banner aligned.
- Public docs now spell out connection lifecycle and cancellation behavior for
  connection ownership, best-effort session channel cleanup, local listener
  scope exit, and remote forwarding cancellation fallback.
- Remote TCP/IP forward listeners now ignore late channel messages for recently
  closed forwarded channels while waiting for the next accepted connection,
  fixing repeated remote/listener-backed forwarding workloads.
- Support-export reports now redact common inline secret fragments in
  server-provided language-tag fields for auth banners, password-change
  prompts, remote disconnect/debug diagnostics, and SFTP status details.
- Callback-backed and agent-backed public-key authentication now filter out
  legacy `ssh-rsa` unless `SSHLegacyAlgorithmOptions.sshRSA` is explicitly
  enabled for that connection or jump-host hop.
- `SSHPortLatencyOptions` now validates through typed `SSHPortLatencyError`
  failures instead of process-level precondition traps when invalid options reach
  the measurement path.
- `SSHPortLatencyError` now exposes `diagnosticReport` for copyable support
  output covering invalid options, route setup timeout, SSH service-request
  timeout, and no-successful-sample failures.
- User callback failures can now expose an opt-in stable diagnostic code and
  safe summary through `SSHCallbackFailureDiagnosticProviding`; Traversio copies
  those fields into connection failure diagnostics, logs, and support reports.

Implemented surface:

- encrypted SSH transport with the documented algorithm profile, explicit host trust, structured diagnostics, setup timeouts, reply timeouts, idle keepalive, and automatic local rekey policy
- password, password-change callback, keyboard-interactive, Ed25519/RSA/ECDSA public-key auth, callback-backed signing, SSH agent-backed signing, encrypted OpenSSH key loading, key generation, and explicit legacy `ssh-rsa` compatibility
- exec, streamed exec, named subsystem startup, PTY shell, environment requests, standard-error extended-data writes, PTY resize, outbound signal requests, and remote exit-signal reporting
- SFTP metadata, listing, file handles, reads, writes, resumable transfers, recursive directory transfers, progress callbacks, path and handle mutation, filesystem queries, symlink/readlink, and optional OpenSSH fsync
- single-file SCP receive/send helpers and local file URL wrappers
- raw direct TCP/IP, local forwarding, dynamic SOCKS forwarding, raw remote TCP listeners, fixed remote TCP bridge helpers, direct streamlocal, remote streamlocal, SOCKS5 / HTTP CONNECT outer connection proxies, and API-level ProxyJump

Validation for this source snapshot:

- `swift build -Xswiftc -strict-concurrency=complete -Xswiftc -warn-concurrency`
- `swift test`

Not included in this release:

- library-owned automatic reconnect
- local `ssh_config` parsing
- mandatory built-in trust-store persistence
- mandatory Keychain-backed trust storage
- hostbased auth, security-key auth, X11 forwarding, and auth-agent forwarding
- broader host-certificate algorithm coverage beyond the current Ed25519 and ECDSA P-256 paths
- broader non-OpenSSH streamlocal compatibility
- release-quality public benchmark comparisons
