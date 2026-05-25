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
func hostKeyTrustPolicyAcceptsVerifiedKeyWhenExplicitlyConfigured() async throws {
    let verifiedHostKey = try makeVerifiedEd25519HostKey()
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "example.com", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9"),
        verificationDate: try certificateDate("2005-01-01T00:00:00Z")
    )

    let trust = try await SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey.evaluate(
        verifiedHostKey,
        context: context
    )

    #expect(trust.method == .acceptAnyVerifiedHostKey)
    #expect(trust.trustedHostKey == SSHTrustedHostKey(verifiedHostKey: verifiedHostKey))
    #expect(trust.context == context)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyRejectsMismatchedPinnedHostKey() async throws {
    let verifiedHostKey = try makeVerifiedEd25519HostKey(
        seed: Array(0x01...0x20),
        exchangeHash: Array(0x80...0x9f)
    )
    let mismatchedHostKey = try makeVerifiedEd25519HostKey(
        seed: Array(0x21...0x40),
        exchangeHash: Array(0x90...0xaf)
    )
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "example.com", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9")
    )
    let expectedHostKey = SSHTrustedHostKey(verifiedHostKey: mismatchedHostKey)

    do {
        _ = try await SSHHostKeyTrustPolicy.requireMatch(expectedHostKey).evaluate(
            verifiedHostKey,
            context: context
        )
        Issue.record("Expected pinned host-key mismatch error")
    } catch {
        #expect(
            error as? SSHHostKeyTrustError
                == .mismatchedHostKey(
                    expectedAlgorithmName: expectedHostKey.algorithmName,
                    receivedAlgorithmName: verifiedHostKey.algorithmName,
                    expectedFingerprintSHA256: expectedHostKey.fingerprintSHA256,
                    receivedFingerprintSHA256: SSHTrustedHostKey(
                        verifiedHostKey: verifiedHostKey
                    ).fingerprintSHA256,
                    context: context
                )
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyAcceptsMatchFromTrustedKeySet() async throws {
    let trustedHostKey = SSHTrustedHostKey(
        verifiedHostKey: try makeVerifiedEd25519HostKey(
            seed: Array(0x01...0x20),
            exchangeHash: Array(0x80...0x9f)
        )
    )
    let alternateTrustedHostKey = SSHTrustedHostKey(
        verifiedHostKey: try makeVerifiedEd25519HostKey(
            seed: Array(0x21...0x40),
            exchangeHash: Array(0x90...0xaf)
        )
    )
    let verifiedHostKey = try makeVerifiedEd25519HostKey(
        seed: Array(0x21...0x40),
        exchangeHash: Array(0x90...0xaf)
    )
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "example.com", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9")
    )

    let trust = try await SSHHostKeyTrustPolicy.requireMatchAny(
        [trustedHostKey, alternateTrustedHostKey]
    ).evaluate(
        verifiedHostKey,
        context: context
    )

    #expect(trust.method == .trustedSetMatch)
    #expect(trust.trustedHostKey == alternateTrustedHostKey)
    #expect(trust.context == context)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyRejectsRevokedKnownHostsKey() async throws {
    let trustedHostKey = SSHTrustedHostKey(
        verifiedHostKey: try makeVerifiedEd25519HostKey(
            seed: Array(0x01...0x20),
            exchangeHash: Array(0x80...0x9f)
        )
    )
    let revokedVerifiedHostKey = try makeVerifiedEd25519HostKey(
        seed: Array(0x21...0x40),
        exchangeHash: Array(0x90...0xaf)
    )
    let revokedHostKey = SSHTrustedHostKey(verifiedHostKey: revokedVerifiedHostKey)
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "example.com", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9")
    )

    do {
        _ = try await SSHHostKeyTrustPolicy.knownHosts(
            trustedHostKeys: [trustedHostKey],
            revokedHostKeys: [revokedHostKey],
            trustedCertificateAuthorityKeys: []
        ).evaluate(
            revokedVerifiedHostKey,
            context: context
        )
        Issue.record("Expected revoked known_hosts key to be rejected")
    } catch {
        #expect(
            error as? SSHHostKeyTrustError
                == .hostKeyRevoked(
                    receivedAlgorithmName: revokedVerifiedHostKey.algorithmName,
                    receivedFingerprintSHA256: revokedHostKey.fingerprintSHA256,
                    revokedHostKeys: [revokedHostKey],
                    context: context
                )
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyKnownHostsAcceptsHostCertificateSignedByTrustedAuthority() async throws {
    let verifiedHostKey = try makeVerifiedEd25519HostCertificate()
    let certificateAuthorityKey = try #require(verifiedHostKey.certificate?.certificateAuthorityKey)
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "host1", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9"),
        verificationDate: try certificateDate("2005-01-01T00:00:00Z")
    )

    let trust = try await SSHHostKeyTrustPolicy.knownHosts(
        trustedHostKeys: [],
        revokedHostKeys: [],
        trustedCertificateAuthorityKeys: [certificateAuthorityKey]
    ).evaluate(
        verifiedHostKey,
        context: context
    )

    #expect(trust.method == .certificateAuthorityMatch)
    #expect(trust.trustedHostKey == certificateAuthorityKey)
    #expect(trust.context == context)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyKnownHostsAcceptsECDSAHostCertificateSignedByTrustedAuthority() async throws {
    let verifiedHostKey = try makeVerifiedECDSAHostCertificate()
    let certificateAuthorityKey = try #require(verifiedHostKey.certificate?.certificateAuthorityKey)
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "host1", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9"),
        verificationDate: try certificateDate("2005-01-01T00:00:00Z")
    )

    let trust = try await SSHHostKeyTrustPolicy.knownHosts(
        trustedHostKeys: [],
        revokedHostKeys: [],
        trustedCertificateAuthorityKeys: [certificateAuthorityKey]
    ).evaluate(
        verifiedHostKey,
        context: context
    )

    #expect(trust.method == .certificateAuthorityMatch)
    #expect(trust.trustedHostKey == certificateAuthorityKey)
    #expect(trust.context == context)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyKnownHostsRejectsHostCertificateSignedByUntrustedAuthority() async throws {
    let verifiedHostKey = try makeVerifiedEd25519HostCertificate()
    let certificateAuthorityKey = try #require(verifiedHostKey.certificate?.certificateAuthorityKey)
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "host1", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9"),
        verificationDate: try certificateDate("2005-01-01T00:00:00Z")
    )

    do {
        _ = try await SSHHostKeyTrustPolicy.knownHosts(
            trustedHostKeys: [],
            revokedHostKeys: [],
            trustedCertificateAuthorityKeys: []
        ).evaluate(
            verifiedHostKey,
            context: context
        )
        Issue.record("Expected untrusted host certificate authority to be rejected")
    } catch {
        #expect(
            error as? SSHHostKeyTrustError
                == .hostCertificateAuthorityNotTrusted(
                    receivedAlgorithmName: verifiedHostKey.algorithmName,
                    certificateAuthorityAlgorithmName: certificateAuthorityKey.algorithmName,
                    certificateAuthorityFingerprintSHA256: certificateAuthorityKey.fingerprintSHA256,
                    trustedCertificateAuthorities: [],
                    context: context
                )
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyKnownHostsRejectsHostCertificateSignedByRevokedAuthority() async throws {
    let verifiedHostKey = try makeVerifiedEd25519HostCertificate()
    let certificateAuthorityKey = try #require(verifiedHostKey.certificate?.certificateAuthorityKey)
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "host1", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9"),
        verificationDate: try certificateDate("2005-01-01T00:00:00Z")
    )

    do {
        _ = try await SSHHostKeyTrustPolicy.knownHosts(
            trustedHostKeys: [],
            revokedHostKeys: [certificateAuthorityKey],
            trustedCertificateAuthorityKeys: [certificateAuthorityKey]
        ).evaluate(
            verifiedHostKey,
            context: context
        )
        Issue.record("Expected revoked host certificate authority to be rejected")
    } catch {
        #expect(
            error as? SSHHostKeyTrustError
                == .hostCertificateAuthorityRevoked(
                    receivedAlgorithmName: verifiedHostKey.algorithmName,
                    certificateAuthorityAlgorithmName: certificateAuthorityKey.algorithmName,
                    certificateAuthorityFingerprintSHA256: certificateAuthorityKey.fingerprintSHA256,
                    revokedHostKeys: [certificateAuthorityKey],
                    context: context
                )
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyAcceptsValidHostCertificateForMatchingPrincipal() async throws {
    let verifiedHostKey = try makeVerifiedEd25519HostCertificate()
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "host1", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9"),
        verificationDate: try certificateDate("2005-01-01T00:00:00Z")
    )

    let trust = try await SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey.evaluate(
        verifiedHostKey,
        context: context
    )

    #expect(trust.method == .acceptAnyVerifiedHostKey)
    #expect(trust.trustedHostKey == SSHTrustedHostKey(verifiedHostKey: verifiedHostKey))
    #expect(trust.context == context)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyRejectsExpiredHostCertificate() async throws {
    let verifiedHostKey = try makeVerifiedEd25519HostCertificate()
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "host1", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9"),
        verificationDate: try certificateDate("2012-01-01T00:00:00Z")
    )

    do {
        _ = try await SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey.evaluate(
            verifiedHostKey,
            context: context
        )
        Issue.record("Expected expired host certificate to be rejected")
    } catch {
        #expect(
            error as? SSHHostKeyTrustError
                == .invalidHostCertificate(
                    receivedAlgorithmName: verifiedHostKey.algorithmName,
                    reason: .expired(validBefore: 1_293_836_400),
                    context: context
                )
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyRejectsNotYetValidHostCertificate() async throws {
    let verifiedHostKey = try makeVerifiedEd25519HostCertificate()
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "host1", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9"),
        verificationDate: try certificateDate("1998-12-31T00:00:00Z")
    )

    do {
        _ = try await SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey.evaluate(
            verifiedHostKey,
            context: context
        )
        Issue.record("Expected not-yet-valid host certificate to be rejected")
    } catch {
        #expect(
            error as? SSHHostKeyTrustError
                == .invalidHostCertificate(
                    receivedAlgorithmName: verifiedHostKey.algorithmName,
                    reason: .notYetValid(validAfter: 915_145_200),
                    context: context
                )
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyRejectsHostCertificateWhenPrincipalDoesNotMatch() async throws {
    let verifiedHostKey = try makeVerifiedEd25519HostCertificate()
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "other.example.com", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9"),
        verificationDate: try certificateDate("2005-01-01T00:00:00Z")
    )

    do {
        _ = try await SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey.evaluate(
            verifiedHostKey,
            context: context
        )
        Issue.record("Expected principal mismatch to reject host certificate")
    } catch {
        #expect(
            error as? SSHHostKeyTrustError
                == .invalidHostCertificate(
                    receivedAlgorithmName: verifiedHostKey.algorithmName,
                    reason: .principalMismatch(
                        expectedHost: "other.example.com",
                        principals: ["host1", "host2"]
                    ),
                    context: context
                )
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyRejectsHostCertificateWithoutRemoteEndpoint() async throws {
    let verifiedHostKey = try makeVerifiedEd25519HostCertificate()
    let context = SSHHostKeyValidationContext(
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9"),
        verificationDate: try certificateDate("2005-01-01T00:00:00Z")
    )

    do {
        _ = try await SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey.evaluate(
            verifiedHostKey,
            context: context
        )
        Issue.record("Expected missing remote endpoint to reject host certificate")
    } catch {
        #expect(
            error as? SSHHostKeyTrustError
                == .invalidHostCertificate(
                    receivedAlgorithmName: verifiedHostKey.algorithmName,
                    reason: .missingRemoteEndpoint,
                    context: context
                )
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyAcceptsHostCertificateWildcardPrincipal() async throws {
    let verifiedHostKey = try makeVerifiedEd25519HostCertificate(
        updateCertificate: { certificate in
            SSHVerifiedHostCertificate(
                validPrincipals: ["*.example.com"],
                validAfter: certificate.validAfter,
                validBefore: certificate.validBefore,
                certificateAuthorityKey: certificate.certificateAuthorityKey
            )
        }
    )
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "db.example.com", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9"),
        verificationDate: try certificateDate("2005-01-01T00:00:00Z")
    )

    let trust = try await SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey.evaluate(
        verifiedHostKey,
        context: context
    )

    #expect(trust.method == .acceptAnyVerifiedHostKey)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func hostKeyTrustPolicyRejectsHostCertificateWithoutPrincipals() async throws {
    let verifiedHostKey = try makeVerifiedEd25519HostCertificate(
        updateCertificate: { certificate in
            SSHVerifiedHostCertificate(
                validPrincipals: [],
                validAfter: certificate.validAfter,
                validBefore: certificate.validBefore,
                certificateAuthorityKey: certificate.certificateAuthorityKey
            )
        }
    )
    let context = SSHHostKeyValidationContext(
        remoteEndpoint: SSHSocketEndpoint(host: "host1", port: 22),
        remoteIdentification: try SSHIdentification(rawValue: "SSH-2.0-OpenSSH_9.9"),
        verificationDate: try certificateDate("2005-01-01T00:00:00Z")
    )

    do {
        _ = try await SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey.evaluate(
            verifiedHostKey,
            context: context
        )
        Issue.record("Expected missing principals to reject host certificate")
    } catch {
        #expect(
            error as? SSHHostKeyTrustError
                == .invalidHostCertificate(
                    receivedAlgorithmName: verifiedHostKey.algorithmName,
                    reason: .missingPrincipals,
                    context: context
                )
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeVerifiedEd25519HostKey(
    seed: [UInt8] = Array(0x41...0x60),
    exchangeHash: [UInt8] = Array(0x70...0x8f)
) throws -> SSHVerifiedHostKey {
    let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed))
    let hostKey = makeEd25519Blob(bytes: Array(privateKey.publicKey.rawRepresentation))
    let signature = makeEd25519Blob(
        bytes: Array(try privateKey.signature(for: Data(exchangeHash)))
    )

    return try SSHHostKeyVerifier().verifyHostKey(
        expectedHostKeyAlgorithm: "ssh-ed25519",
        exchangeHash: exchangeHash,
        hostKey: hostKey,
        signature: signature
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeVerifiedEd25519HostCertificate(
    exchangeHash: [UInt8] = Array(0xa0...0xbf),
    updateCertificate: ((SSHVerifiedHostCertificate) -> SSHVerifiedHostCertificate)? = nil
) throws -> SSHVerifiedHostKey {
    let privateKey = try SSHEd25519PrivateKey(
        openSSHPrivateKey: try loadBundledOpenSSHFixture(named: "ed25519_1")
    )
    let hostCertificate = try loadBundledOpenSSHAuthorizedKeyBlob(named: "ed25519_1-cert.pub")
    let signature = try privateKey.signUserAuthenticationRequest(
        exchangeHash,
        algorithmName: "ssh-ed25519"
    )
    let verifiedHostKey = try SSHHostKeyVerifier().verifyHostKey(
        expectedHostKeyAlgorithm: "ssh-ed25519-cert-v01@openssh.com",
        exchangeHash: exchangeHash,
        hostKey: hostCertificate,
        signature: signature
    )

    guard let updateCertificate,
          let certificate = verifiedHostKey.certificate else {
        return verifiedHostKey
    }

    return SSHVerifiedHostKey(
        algorithmName: verifiedHostKey.algorithmName,
        publicKey: verifiedHostKey.publicKey,
        rawHostKey: verifiedHostKey.rawHostKey,
        rawSignature: verifiedHostKey.rawSignature,
        certificate: updateCertificate(certificate)
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeVerifiedECDSAHostCertificate(
    exchangeHash: [UInt8] = Array(0xc0...0xdf),
    updateCertificate: ((SSHVerifiedHostCertificate) -> SSHVerifiedHostCertificate)? = nil
) throws -> SSHVerifiedHostKey {
    let privateKey = SSHECDSAPrivateKey.nistp256(
        rawRepresentation: sampleOpenSSHECDSATestKey1RawRepresentation
    )
    let hostCertificate = try loadBundledOpenSSHAuthorizedKeyBlob(named: "ecdsa_1-cert.pub")
    let signature = try privateKey.signUserAuthenticationRequest(
        exchangeHash,
        algorithmName: "ecdsa-sha2-nistp256"
    )
    let verifiedHostKey = try SSHHostKeyVerifier().verifyHostKey(
        expectedHostKeyAlgorithm: "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        exchangeHash: exchangeHash,
        hostKey: hostCertificate,
        signature: signature
    )

    guard let updateCertificate,
          let certificate = verifiedHostKey.certificate else {
        return verifiedHostKey
    }

    return SSHVerifiedHostKey(
        algorithmName: verifiedHostKey.algorithmName,
        publicKey: verifiedHostKey.publicKey,
        rawHostKey: verifiedHostKey.rawHostKey,
        rawSignature: verifiedHostKey.rawSignature,
        certificate: updateCertificate(certificate)
    )
}

private func makeEd25519Blob(bytes: [UInt8]) -> [UInt8] {
    var writer = SSHWireWriter()
    writer.write(utf8: "ssh-ed25519")
    writer.write(string: bytes)
    return writer.bytes
}

private func certificateDate(_ value: String) throws -> Date {
    let formatter = ISO8601DateFormatter()
    guard let date = formatter.date(from: value) else {
        throw HostKeyTrustTestError.invalidDate
    }
    return date
}

private enum HostKeyTrustTestError: Error {
    case invalidDate
}

private let sampleOpenSSHECDSATestKey1RawRepresentation: [UInt8] = [
    0xf3, 0xcd, 0xc9, 0x40, 0x27, 0x8e, 0xf1, 0x6b,
    0xf9, 0xe4, 0xff, 0xee, 0xdf, 0xc8, 0xca, 0x3b,
    0x90, 0x41, 0xdf, 0xda, 0x2c, 0x58, 0x93, 0x63,
    0xdd, 0x8b, 0x07, 0xd8, 0x08, 0x8f, 0x2a, 0xcc,
]
