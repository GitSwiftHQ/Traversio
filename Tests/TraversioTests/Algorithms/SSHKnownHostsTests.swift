// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation
import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsReturnsPinnedPolicyForExactDefaultPortMatch() throws {
    let trustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x01...0x20)
    )
    let knownHosts = SSHKnownHosts(
        contents: makeKnownHostsLine(
            hosts: "example.com",
            algorithm: "ssh-ed25519",
            trustedHostKey: trustedHostKey
        )
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "example.com", port: 22)
    )

    #expect(policy == .requireMatch(trustedHostKey))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsPrefersPortSpecificMatchBeforeRawHostFallback() throws {
    let defaultPortHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x21...0x40)
    )
    let customPortHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x41...0x60)
    )
    let knownHosts = SSHKnownHosts(
        contents: [
            makeKnownHostsLine(
                hosts: "example.com",
                algorithm: "ssh-ed25519",
                trustedHostKey: defaultPortHostKey
            ),
            makeKnownHostsLine(
                hosts: "[example.com]:2222",
                algorithm: "ssh-ed25519",
                trustedHostKey: customPortHostKey
            ),
        ].joined(separator: "\n")
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "example.com", port: 2222)
    )

    #expect(policy == .requireMatch(customPortHostKey))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsFallsBackToRawHostWhenPortSpecificEntryIsAbsent() throws {
    let trustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x61...0x80)
    )
    let knownHosts = SSHKnownHosts(
        contents: makeKnownHostsLine(
            hosts: "example.com",
            algorithm: "ssh-ed25519",
            trustedHostKey: trustedHostKey
        )
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "example.com", port: 2222)
    )

    #expect(policy == .requireMatch(trustedHostKey))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsBuildsTrustedSetPolicyWhenMultipleKeysMatchSameHost() throws {
    let firstTrustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x81...0xa0)
    )
    let secondTrustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0xa1...0xc0)
    )
    let knownHosts = SSHKnownHosts(
        contents: [
            makeKnownHostsLine(
                hosts: "example.com",
                algorithm: "ssh-ed25519",
                trustedHostKey: firstTrustedHostKey
            ),
            makeKnownHostsLine(
                hosts: "example.com",
                algorithm: "ssh-ed25519",
                trustedHostKey: secondTrustedHostKey
            ),
        ].joined(separator: "\n")
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "example.com", port: 22)
    )

    #expect(policy == .requireMatchAny([firstTrustedHostKey, secondTrustedHostKey]))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsMatchesHashedDefaultPortEntry() throws {
    let trustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0xc1...0xe0)
    )
    let hashedHost = makeHashedKnownHost(
        "example.com",
        salt: Array(0x01...0x14)
    )
    let knownHosts = SSHKnownHosts(
        contents: makeKnownHostsLine(
            hosts: hashedHost,
            algorithm: "ssh-ed25519",
            trustedHostKey: trustedHostKey
        )
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "example.com", port: 22)
    )

    #expect(policy == .requireMatch(trustedHostKey))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsMatchesHashedPortSpecificEntryBeforeRawHostFallback() throws {
    let defaultPortHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x61...0x80)
    )
    let customPortHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x81...0xa0)
    )
    let hashedPortSpecificHost = makeHashedKnownHost(
        "[example.com]:2222",
        salt: Array(0x15...0x28)
    )
    let knownHosts = SSHKnownHosts(
        contents: [
            makeKnownHostsLine(
                hosts: "example.com",
                algorithm: "ssh-ed25519",
                trustedHostKey: defaultPortHostKey
            ),
            makeKnownHostsLine(
                hosts: hashedPortSpecificHost,
                algorithm: "ssh-ed25519",
                trustedHostKey: customPortHostKey
            ),
        ].joined(separator: "\n")
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "example.com", port: 2222)
    )

    #expect(policy == .requireMatch(customPortHostKey))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsFallsBackToHashedRawHostWhenPortSpecificEntryIsAbsent() throws {
    let trustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x21...0x40)
    )
    let hashedHost = makeHashedKnownHost(
        "example.com",
        salt: Array(0x29...0x3c)
    )
    let knownHosts = SSHKnownHosts(
        contents: makeKnownHostsLine(
            hosts: hashedHost,
            algorithm: "ssh-ed25519",
            trustedHostKey: trustedHostKey
        )
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "example.com", port: 2222)
    )

    #expect(policy == .requireMatch(trustedHostKey))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsMatchesIPv4CIDRPattern() throws {
    let trustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x01...0x20)
    )
    let knownHosts = SSHKnownHosts(
        contents: makeKnownHostsLine(
            hosts: "192.0.2.0/24",
            algorithm: "ssh-ed25519",
            trustedHostKey: trustedHostKey
        )
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "192.0.2.33", port: 22)
    )

    #expect(policy == .requireMatch(trustedHostKey))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsMatchesIPv6CIDRPattern() throws {
    let trustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x21...0x40)
    )
    let knownHosts = SSHKnownHosts(
        contents: makeKnownHostsLine(
            hosts: "2001:db8::/64",
            algorithm: "ssh-ed25519",
            trustedHostKey: trustedHostKey
        )
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "2001:db8::42", port: 22)
    )

    #expect(policy == .requireMatch(trustedHostKey))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsFallsBackToRawIPAddressForCIDRMatchOnCustomPort() throws {
    let trustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x41...0x60)
    )
    let knownHosts = SSHKnownHosts(
        contents: makeKnownHostsLine(
            hosts: "192.0.2.0/24",
            algorithm: "ssh-ed25519",
            trustedHostKey: trustedHostKey
        )
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "192.0.2.44", port: 2222)
    )

    #expect(policy == .requireMatch(trustedHostKey))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsFilePolicyLoadsHashedEntryFromDisk() throws {
    let trustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0xa1...0xc0)
    )
    let temporaryDirectoryURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let knownHostsURL = temporaryDirectoryURL.appendingPathComponent("known_hosts")
    let knownHostsContents = makeKnownHostsLine(
        hosts: makeHashedKnownHost("example.com", salt: Array(0x3d...0x50)),
        algorithm: "ssh-ed25519",
        trustedHostKey: trustedHostKey
    )

    try FileManager.default.createDirectory(
        at: temporaryDirectoryURL,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectoryURL)
    }

    try knownHostsContents.write(to: knownHostsURL, atomically: true, encoding: .utf8)

    let policy = try SSHHostKeyPolicy
        .knownHostsFile(knownHostsURL.path)
        .resolveTrustPolicy(for: SSHSocketEndpoint(host: "example.com", port: 22))

    #expect(policy == .requireMatch(trustedHostKey))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsMatchesWildcardHostPattern() throws {
    let trustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x41...0x60)
    )
    let knownHosts = SSHKnownHosts(
        contents: makeKnownHostsLine(
            hosts: "*.example.com",
            algorithm: "ssh-ed25519",
            trustedHostKey: trustedHostKey
        )
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "api.example.com", port: 22)
    )

    #expect(policy == .requireMatch(trustedHostKey))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsMatchesAdditionalLookupNameAtDefaultPort() throws {
    let trustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0xe1...0xff)
    )
    let knownHosts = SSHKnownHosts(
        contents: makeKnownHostsLine(
            hosts: "192.0.2.10",
            algorithm: "ssh-ed25519",
            trustedHostKey: trustedHostKey
        )
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "example.com", port: 22),
        additionalLookupNames: ["192.0.2.10"]
    )

    #expect(policy == .requireMatch(trustedHostKey))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsPrefersPortSpecificAdditionalLookupNameBeforeRawHostFallback() throws {
    let rawHostTrustedKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x21...0x40)
    )
    let portSpecificAddressTrustedKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x41...0x60)
    )
    let knownHosts = SSHKnownHosts(
        contents: [
            makeKnownHostsLine(
                hosts: "example.com",
                algorithm: "ssh-ed25519",
                trustedHostKey: rawHostTrustedKey
            ),
            makeKnownHostsLine(
                hosts: "[192.0.2.10]:2222",
                algorithm: "ssh-ed25519",
                trustedHostKey: portSpecificAddressTrustedKey
            ),
        ].joined(separator: "\n")
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "example.com", port: 2222),
        additionalLookupNames: ["192.0.2.10"]
    )

    #expect(policy == .requireMatch(portSpecificAddressTrustedKey))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsNegatedPatternOverridesPositiveWildcard() throws {
    let trustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x61...0x80)
    )
    let knownHosts = SSHKnownHosts(
        contents: makeKnownHostsLine(
            hosts: "*.example.com,!bastion.example.com",
            algorithm: "ssh-ed25519",
            trustedHostKey: trustedHostKey
        )
    )
    let endpoint = SSHSocketEndpoint(host: "bastion.example.com", port: 22)

    do {
        _ = try knownHosts.requireTrustPolicy(for: endpoint)
        Issue.record("Expected negated host pattern to prevent a match")
    } catch {
        #expect(error as? SSHKnownHostsError == .noMatchingHostKey(endpoint))
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsReturnsRevokedAwarePolicyWhenEndpointMatchesRevokedEntry() throws {
    let trustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x41...0x60)
    )
    let revokedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x81...0xa0)
    )
    let knownHosts = SSHKnownHosts(
        contents: [
            "@revoked example.com ssh-ed25519 \(encoded(revokedHostKey))",
            makeKnownHostsLine(
                hosts: "example.com",
                algorithm: "ssh-ed25519",
                trustedHostKey: trustedHostKey
            ),
        ].joined(separator: "\n")
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "example.com", port: 22)
    )

    #expect(
        policy == .knownHosts(
            trustedHostKeys: [trustedHostKey],
            revokedHostKeys: [revokedHostKey],
            trustedCertificateAuthorityKeys: []
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsDoesNotFallBackToRawHostWhenPortSpecificRevokedEntryMatches() throws {
    let rawHostTrustedKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x21...0x40)
    )
    let portSpecificRevokedKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x41...0x60)
    )
    let knownHosts = SSHKnownHosts(
        contents: [
            makeKnownHostsLine(
                hosts: "example.com",
                algorithm: "ssh-ed25519",
                trustedHostKey: rawHostTrustedKey
            ),
            "@revoked [example.com]:2222 ssh-ed25519 \(encoded(portSpecificRevokedKey))",
        ].joined(separator: "\n")
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "example.com", port: 2222)
    )

    #expect(
        policy == .knownHosts(
            trustedHostKeys: [],
            revokedHostKeys: [portSpecificRevokedKey],
            trustedCertificateAuthorityKeys: []
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsReturnsCertAuthorityAwarePolicyWhenEndpointMatchesCAEntry() throws {
    let certificateAuthorityKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x41...0x60)
    )
    let knownHosts = SSHKnownHosts(
        contents: "@cert-authority example.com ssh-ed25519 \(encoded(certificateAuthorityKey))"
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "example.com", port: 22)
    )

    #expect(
        policy == .knownHosts(
            trustedHostKeys: [],
            revokedHostKeys: [],
            trustedCertificateAuthorityKeys: [certificateAuthorityKey]
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsParsesCertAuthorityMarkerAndIgnoresMalformedHashedOrCIDREntries() throws {
    let trustedHostKey = try makeTrustedHostKey(
        algorithm: "ssh-ed25519",
        payload: Array(0x41...0x60)
    )
    let knownHosts = SSHKnownHosts(
        contents: [
            "@cert-authority example.com ssh-ed25519 \(encoded(trustedHostKey))",
            "|1|bad-salt|still-bad ssh-ed25519 \(encoded(trustedHostKey))",
            "192.0.2.99/24 ssh-ed25519 \(encoded(trustedHostKey))",
            makeKnownHostsLine(
                hosts: "example.com,192.0.2.10",
                algorithm: "ssh-ed25519",
                trustedHostKey: trustedHostKey
            ),
        ].joined(separator: "\n")
    )

    let policy = try knownHosts.requireTrustPolicy(
        for: SSHSocketEndpoint(host: "example.com", port: 22)
    )

    #expect(
        policy == .knownHosts(
            trustedHostKeys: [trustedHostKey],
            revokedHostKeys: [],
            trustedCertificateAuthorityKeys: [trustedHostKey]
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func knownHostsThrowsWhenNoTrustedKeyMatchesEndpoint() {
    let knownHosts = SSHKnownHosts(contents: "")
    let endpoint = SSHSocketEndpoint(host: "example.com", port: 22)

    do {
        _ = try knownHosts.requireTrustPolicy(for: endpoint)
        Issue.record("Expected no-matching-host-key error")
    } catch {
        #expect(error as? SSHKnownHostsError == .noMatchingHostKey(endpoint))
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeTrustedHostKey(
    algorithm: String,
    payload: [UInt8]
) throws -> SSHTrustedHostKey {
    var writer = SSHWireWriter()
    writer.write(utf8: algorithm)
    writer.write(string: payload)
    return try SSHTrustedHostKey(rawRepresentation: writer.bytes)
}

private func makeKnownHostsLine(
    hosts: String,
    algorithm: String,
    trustedHostKey: SSHTrustedHostKey
) -> String {
    "\(hosts) \(algorithm) \(encoded(trustedHostKey))"
}

private func makeHashedKnownHost(_ host: String, salt: [UInt8]) -> String {
    let authenticationCode = HMAC<Insecure.SHA1>.authenticationCode(
        for: Data(host.utf8),
        using: SymmetricKey(data: Data(salt))
    )
    let encodedSalt = Data(salt).base64EncodedString()
    let encodedHash = Data(authenticationCode).base64EncodedString()
    return "|1|\(encodedSalt)|\(encodedHash)"
}

private func encoded(_ trustedHostKey: SSHTrustedHostKey) -> String {
    Data(trustedHostKey.rawRepresentation).base64EncodedString()
}
