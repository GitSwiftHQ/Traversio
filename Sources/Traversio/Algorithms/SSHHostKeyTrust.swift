// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation
enum SSHHostKeyTrustError: Error, Equatable, Sendable {
    case invalidHostCertificate(
        receivedAlgorithmName: String,
        reason: SSHHostCertificateValidationFailureReason,
        context: SSHHostKeyValidationContext
    )
    case hostCertificateAuthorityRevoked(
        receivedAlgorithmName: String,
        certificateAuthorityAlgorithmName: String,
        certificateAuthorityFingerprintSHA256: String,
        revokedHostKeys: [SSHTrustedHostKey],
        context: SSHHostKeyValidationContext
    )
    case hostCertificateAuthorityNotTrusted(
        receivedAlgorithmName: String,
        certificateAuthorityAlgorithmName: String,
        certificateAuthorityFingerprintSHA256: String,
        trustedCertificateAuthorities: [SSHTrustedHostKey],
        context: SSHHostKeyValidationContext
    )
    case mismatchedHostKey(
        expectedAlgorithmName: String,
        receivedAlgorithmName: String,
        expectedFingerprintSHA256: String,
        receivedFingerprintSHA256: String,
        context: SSHHostKeyValidationContext
    )
    case hostKeyRevoked(
        receivedAlgorithmName: String,
        receivedFingerprintSHA256: String,
        revokedHostKeys: [SSHTrustedHostKey],
        context: SSHHostKeyValidationContext
    )
    case hostKeyNotTrusted(
        receivedAlgorithmName: String,
        receivedFingerprintSHA256: String,
        trustedHostKeys: [SSHTrustedHostKey],
        context: SSHHostKeyValidationContext
    )
}

package enum SSHHostCertificateValidationFailureReason: Equatable, Sendable {
    case notYetValid(validAfter: UInt64)
    case expired(validBefore: UInt64)
    case missingPrincipals
    case missingRemoteEndpoint
    case principalMismatch(expectedHost: String, principals: [String])
}

package struct SSHHostKeyValidationContext: Equatable, Sendable {
    let remoteEndpoint: SSHSocketEndpoint?
    let remoteIdentification: SSHIdentification?
    let verificationDate: Date?

    init(
        remoteEndpoint: SSHSocketEndpoint? = nil,
        remoteIdentification: SSHIdentification? = nil,
        verificationDate: Date? = nil
    ) {
        self.remoteEndpoint = remoteEndpoint
        self.remoteIdentification = remoteIdentification
        self.verificationDate = verificationDate
    }
}
/// A parsed SSH host key suitable for pinning or trust-store persistence.
public struct SSHTrustedHostKey: Equatable, Sendable {
    /// SSH algorithm name.
    public let algorithmName: String

    /// Raw SSH wire representation.
    public let rawRepresentation: [UInt8]

    /// Parses a trusted host key from its SSH wire representation.
    public init(rawRepresentation: [UInt8]) throws {
        var reader = SSHWireReader(bytes: rawRepresentation)
        self.algorithmName = try reader.readUTF8String()
        self.rawRepresentation = rawRepresentation
    }

    init(verifiedHostKey: SSHVerifiedHostKey) {
        self.algorithmName = verifiedHostKey.algorithmName
        self.rawRepresentation = verifiedHostKey.rawHostKey
    }

    /// SHA-256 fingerprint of the raw SSH host-key representation.
    public var fingerprintSHA256: String {
        let digest = SHA256.hash(data: Data(self.rawRepresentation))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

/// How a host key became trusted for a successful connection.
public enum SSHHostKeyTrustMethod: String, Equatable, Sendable {
    /// The policy accepted any cryptographically valid host key.
    case acceptAnyVerifiedHostKey = "accept-any-verified-host-key"

    /// The received key matched one exact expected key.
    case exactMatch = "exact-match"

    /// The received key matched one key from a trusted set.
    case trustedSetMatch = "trusted-set-match"

    /// The received OpenSSH host certificate was signed by a trusted certificate authority.
    case certificateAuthorityMatch = "certificate-authority-match"

    /// An application callback accepted the verified host key.
    case callback = "callback"
}
package struct SSHHostKeyTrust: Equatable, Sendable {
    package let method: SSHHostKeyTrustMethod
    package let trustedHostKey: SSHTrustedHostKey
    package let context: SSHHostKeyValidationContext
}
package enum SSHHostKeyTrustPolicy: Equatable, Sendable {
    case acceptAnyVerifiedHostKey
    case requireMatch(SSHTrustedHostKey)
    case requireMatchAny([SSHTrustedHostKey])
    case knownHosts(
        trustedHostKeys: [SSHTrustedHostKey],
        revokedHostKeys: [SSHTrustedHostKey],
        trustedCertificateAuthorityKeys: [SSHTrustedHostKey]
    )
    case callback(
        @Sendable (_ verifiedHostKey: SSHVerifiedHostKey, _ context: SSHHostKeyValidationContext)
            async throws -> SSHHostKeyTrust
    )

    package static func ==(lhs: SSHHostKeyTrustPolicy, rhs: SSHHostKeyTrustPolicy) -> Bool {
        switch (lhs, rhs) {
        case (.acceptAnyVerifiedHostKey, .acceptAnyVerifiedHostKey):
            return true
        case let (.requireMatch(lhsKey), .requireMatch(rhsKey)):
            return lhsKey == rhsKey
        case let (.requireMatchAny(lhsKeys), .requireMatchAny(rhsKeys)):
            return lhsKeys == rhsKeys
        case let (
            .knownHosts(
                trustedHostKeys: lhsTrustedHostKeys,
                revokedHostKeys: lhsRevokedHostKeys,
                trustedCertificateAuthorityKeys: lhsTrustedCertificateAuthorityKeys
            ),
            .knownHosts(
                trustedHostKeys: rhsTrustedHostKeys,
                revokedHostKeys: rhsRevokedHostKeys,
                trustedCertificateAuthorityKeys: rhsTrustedCertificateAuthorityKeys
            )
        ):
            return lhsTrustedHostKeys == rhsTrustedHostKeys &&
                lhsRevokedHostKeys == rhsRevokedHostKeys &&
                lhsTrustedCertificateAuthorityKeys == rhsTrustedCertificateAuthorityKeys
        case (.callback, .callback):
            return false
        default:
            return false
        }
    }

    func evaluate(
        _ verifiedHostKey: SSHVerifiedHostKey,
        context: SSHHostKeyValidationContext
    ) async throws -> SSHHostKeyTrust {
        try Self.validateHostCertificateIfNeeded(
            verifiedHostKey,
            context: context
        )
        let trustedHostKey = SSHTrustedHostKey(verifiedHostKey: verifiedHostKey)

        switch self {
        case .acceptAnyVerifiedHostKey:
            return Self.makeTrust(
                method: .acceptAnyVerifiedHostKey,
                trustedHostKey: trustedHostKey,
                context: context
            )
        case let .requireMatch(expectedHostKey):
            return try Self.evaluateExactMatch(
                expectedHostKey,
                trustedHostKey: trustedHostKey,
                context: context
            )
        case let .requireMatchAny(expectedHostKeys):
            return try Self.evaluateTrustedSetMatch(
                expectedHostKeys,
                trustedHostKey: trustedHostKey,
                context: context
            )
        case let .knownHosts(
            expectedHostKeys,
            revokedHostKeys,
            trustedCertificateAuthorityKeys
        ):
            return try Self.evaluateKnownHostsPolicy(
                verifiedHostKey,
                trustedHostKey: trustedHostKey,
                trustedHostKeys: expectedHostKeys,
                revokedHostKeys: revokedHostKeys,
                trustedCertificateAuthorityKeys: trustedCertificateAuthorityKeys,
                context: context
            )
        case let .callback(evaluator):
            return try await evaluator(verifiedHostKey, context)
        }
    }

    private static func makeTrust(
        method: SSHHostKeyTrustMethod,
        trustedHostKey: SSHTrustedHostKey,
        context: SSHHostKeyValidationContext
    ) -> SSHHostKeyTrust {
        SSHHostKeyTrust(
            method: method,
            trustedHostKey: trustedHostKey,
            context: context
        )
    }

    private static func evaluateExactMatch(
        _ expectedHostKey: SSHTrustedHostKey,
        trustedHostKey: SSHTrustedHostKey,
        context: SSHHostKeyValidationContext
    ) throws -> SSHHostKeyTrust {
        guard expectedHostKey.rawRepresentation == trustedHostKey.rawRepresentation else {
            throw SSHHostKeyTrustError.mismatchedHostKey(
                expectedAlgorithmName: expectedHostKey.algorithmName,
                receivedAlgorithmName: trustedHostKey.algorithmName,
                expectedFingerprintSHA256: expectedHostKey.fingerprintSHA256,
                receivedFingerprintSHA256: trustedHostKey.fingerprintSHA256,
                context: context
            )
        }

        return Self.makeTrust(
            method: .exactMatch,
            trustedHostKey: trustedHostKey,
            context: context
        )
    }

    private static func evaluateTrustedSetMatch(
        _ expectedHostKeys: [SSHTrustedHostKey],
        trustedHostKey: SSHTrustedHostKey,
        context: SSHHostKeyValidationContext
    ) throws -> SSHHostKeyTrust {
        guard expectedHostKeys.contains(where: {
            $0.rawRepresentation == trustedHostKey.rawRepresentation
        }) else {
            throw SSHHostKeyTrustError.hostKeyNotTrusted(
                receivedAlgorithmName: trustedHostKey.algorithmName,
                receivedFingerprintSHA256: trustedHostKey.fingerprintSHA256,
                trustedHostKeys: expectedHostKeys,
                context: context
            )
        }

        return Self.makeTrust(
            method: .trustedSetMatch,
            trustedHostKey: trustedHostKey,
            context: context
        )
    }

    private static func evaluateKnownHostsPolicy(
        _ verifiedHostKey: SSHVerifiedHostKey,
        trustedHostKey: SSHTrustedHostKey,
        trustedHostKeys: [SSHTrustedHostKey],
        revokedHostKeys: [SSHTrustedHostKey],
        trustedCertificateAuthorityKeys: [SSHTrustedHostKey],
        context: SSHHostKeyValidationContext
    ) throws -> SSHHostKeyTrust {
        if revokedHostKeys.contains(where: {
            $0.rawRepresentation == trustedHostKey.rawRepresentation
        }) {
            throw SSHHostKeyTrustError.hostKeyRevoked(
                receivedAlgorithmName: trustedHostKey.algorithmName,
                receivedFingerprintSHA256: trustedHostKey.fingerprintSHA256,
                revokedHostKeys: revokedHostKeys,
                context: context
            )
        }

        if let certificate = verifiedHostKey.certificate {
            if revokedHostKeys.contains(where: {
                $0.rawRepresentation == certificate.certificateAuthorityKey.rawRepresentation
            }) {
                throw SSHHostKeyTrustError.hostCertificateAuthorityRevoked(
                    receivedAlgorithmName: verifiedHostKey.algorithmName,
                    certificateAuthorityAlgorithmName: certificate.certificateAuthorityKey.algorithmName,
                    certificateAuthorityFingerprintSHA256: certificate.certificateAuthorityKey.fingerprintSHA256,
                    revokedHostKeys: revokedHostKeys,
                    context: context
                )
            }

            guard let trustedCertificateAuthority = trustedCertificateAuthorityKeys.first(where: {
                $0.rawRepresentation == certificate.certificateAuthorityKey.rawRepresentation
            }) else {
                throw SSHHostKeyTrustError.hostCertificateAuthorityNotTrusted(
                    receivedAlgorithmName: verifiedHostKey.algorithmName,
                    certificateAuthorityAlgorithmName: certificate.certificateAuthorityKey.algorithmName,
                    certificateAuthorityFingerprintSHA256: certificate.certificateAuthorityKey.fingerprintSHA256,
                    trustedCertificateAuthorities: trustedCertificateAuthorityKeys,
                    context: context
                )
            }

            return Self.makeTrust(
                method: .certificateAuthorityMatch,
                trustedHostKey: trustedCertificateAuthority,
                context: context
            )
        }

        if trustedHostKeys.count == 1, let expectedHostKey = trustedHostKeys.first {
            return try Self.evaluateExactMatch(
                expectedHostKey,
                trustedHostKey: trustedHostKey,
                context: context
            )
        }

        return try Self.evaluateTrustedSetMatch(
            trustedHostKeys,
            trustedHostKey: trustedHostKey,
            context: context
        )
    }

    private static func validateHostCertificateIfNeeded(
        _ verifiedHostKey: SSHVerifiedHostKey,
        context: SSHHostKeyValidationContext
    ) throws {
        guard let certificate = verifiedHostKey.certificate else {
            return
        }

        let verificationTimestamp = (
            context.verificationDate ?? Date()
        ).timeIntervalSince1970
        if verificationTimestamp < 0 ||
            verificationTimestamp < Double(certificate.validAfter) {
            throw SSHHostKeyTrustError.invalidHostCertificate(
                receivedAlgorithmName: verifiedHostKey.algorithmName,
                reason: .notYetValid(validAfter: certificate.validAfter),
                context: context
            )
        }

        if verificationTimestamp >= Double(certificate.validBefore) {
            throw SSHHostKeyTrustError.invalidHostCertificate(
                receivedAlgorithmName: verifiedHostKey.algorithmName,
                reason: .expired(validBefore: certificate.validBefore),
                context: context
            )
        }

        guard !certificate.validPrincipals.isEmpty else {
            throw SSHHostKeyTrustError.invalidHostCertificate(
                receivedAlgorithmName: verifiedHostKey.algorithmName,
                reason: .missingPrincipals,
                context: context
            )
        }

        guard let remoteHost = context.remoteEndpoint?.host,
              !remoteHost.isEmpty else {
            throw SSHHostKeyTrustError.invalidHostCertificate(
                receivedAlgorithmName: verifiedHostKey.algorithmName,
                reason: .missingRemoteEndpoint,
                context: context
            )
        }

        guard certificate.validPrincipals.contains(where: {
            SSHWildcardPatternMatcher.matches(remoteHost, pattern: $0)
        }) else {
            throw SSHHostKeyTrustError.invalidHostCertificate(
                receivedAlgorithmName: verifiedHostKey.algorithmName,
                reason: .principalMismatch(
                    expectedHost: remoteHost,
                    principals: certificate.validPrincipals
                ),
                context: context
            )
        }
    }
}
