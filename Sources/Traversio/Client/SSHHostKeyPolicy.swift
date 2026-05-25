// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Errors raised while evaluating or updating host-key trust state.
public enum SSHHostKeyPolicyError: Error, Equatable, Sendable {
    /// A stored host key did not match the key presented by the server.
    case storedHostKeyMismatch(
        endpointHost: String,
        endpointPort: UInt16,
        storedHostKey: SSHTrustedHostKey,
        receivedHostKey: SSHTrustedHostKey
    )

    /// The stored host key changed while a trust-on-first-use update was in progress.
    case concurrentStoredHostKeyUpdate(
        endpointHost: String,
        endpointPort: UInt16,
        expectedStoredHostKey: SSHTrustedHostKey?,
        actualStoredHostKey: SSHTrustedHostKey?
    )
}
/// Host-key validation input passed to callback-based trust policies.
public struct SSHHostKeyValidationRequest: Equatable, Sendable {
    /// Endpoint host name or address.
    public let endpointHost: String
    /// Endpoint port number.
    public let endpointPort: UInt16

    /// Raw SSH identification string received from the server when available.
    public let remoteIdentification: String?

    /// Host key presented by the server and verified at the algorithm layer.
    public let trustedHostKey: SSHTrustedHostKey

    /// Creates a host-key validation request value.
    public init(
        endpointHost: String,
        endpointPort: UInt16,
        remoteIdentification: String? = nil,
        trustedHostKey: SSHTrustedHostKey
    ) {
        self.endpointHost = endpointHost
        self.endpointPort = endpointPort
        self.remoteIdentification = remoteIdentification
        self.trustedHostKey = trustedHostKey
    }

    /// Returns whether the received host key matches a stored key.
    public func matches(_ storedHostKey: SSHTrustedHostKey) -> Bool {
        self.trustedHostKey == storedHostKey
    }
}
/// Details passed when a stored host key does not match the key received from
/// the server.
public struct SSHHostKeyChangeRequest: Equatable, Sendable {
    /// Endpoint host name or address.
    public let endpointHost: String
    /// Endpoint port number.
    public let endpointPort: UInt16

    /// Raw SSH identification string received from the server when available.
    public let remoteIdentification: String?

    /// Previously stored key for this endpoint.
    public let storedHostKey: SSHTrustedHostKey

    /// Newly received key that did not match the stored key.
    public let receivedHostKey: SSHTrustedHostKey

    /// Creates a host-key change request value.
    public init(
        endpointHost: String,
        endpointPort: UInt16,
        remoteIdentification: String? = nil,
        storedHostKey: SSHTrustedHostKey,
        receivedHostKey: SSHTrustedHostKey
    ) {
        self.endpointHost = endpointHost
        self.endpointPort = endpointPort
        self.remoteIdentification = remoteIdentification
        self.storedHostKey = storedHostKey
        self.receivedHostKey = receivedHostKey
    }
}
/// Request passed to a trust-on-first-use store callback.
///
/// `expectedStoredHostKey` lets stores reject concurrent updates that raced
/// with another connection.
public struct SSHHostKeyStoreRequest: Equatable, Sendable {
    /// Endpoint host name or address.
    public let endpointHost: String
    /// Endpoint port number.
    public let endpointPort: UInt16
    /// remote identification.
    public let remoteIdentification: String?
    /// Expected Stored host key.
    public let expectedStoredHostKey: SSHTrustedHostKey?
    /// Trusted host key.
    public let trustedHostKey: SSHTrustedHostKey
    /// Creates an SSHHostKeyStoreRequest.

    public init(
        endpointHost: String,
        endpointPort: UInt16,
        remoteIdentification: String? = nil,
        expectedStoredHostKey: SSHTrustedHostKey? = nil,
        trustedHostKey: SSHTrustedHostKey
    ) {
        self.endpointHost = endpointHost
        self.endpointPort = endpointPort
        self.remoteIdentification = remoteIdentification
        self.expectedStoredHostKey = expectedStoredHostKey
        self.trustedHostKey = trustedHostKey
    }

    /// Returns whether the current store value still matches the value observed
    /// before storing.
    public func matchesExpectedStoredHostKey(
        _ storedHostKey: SSHTrustedHostKey?
    ) -> Bool {
        self.expectedStoredHostKey == storedHostKey
    }
}

/// Decision returned when a trust-on-first-use policy sees a changed host key.
public enum SSHHostKeyChangeDecision: String, Equatable, Sendable {
    /// Reject.
    case reject
    /// Replace Stored host key.
    case replaceStoredHostKey = "replace-stored-host-key"
}
/// Host-key verification policy for an SSH connection or ProxyJump hop.
///
/// Host trust is fail-closed by default: callers must choose an explicit
/// policy. `acceptAnyVerifiedHostKey` verifies only that the server's signature
/// matches the negotiated host key; it does not pin the key and should be used
/// only for deliberate test or controlled environments.
///
/// Example:
///
/// ```swift
/// let policy = SSHHostKeyPolicy.knownHostsFile("/Users/me/.ssh/known_hosts")
/// ```
public struct SSHHostKeyPolicy: Equatable, Sendable {
    private enum Storage: Sendable {
        case acceptAnyVerifiedHostKey
        case requireMatch(SSHTrustedHostKey)
        case requireMatchAny([SSHTrustedHostKey])
        case knownHostsFile(path: String, additionalLookupNames: [String])
        case callback(
            @Sendable (SSHHostKeyValidationRequest) async throws -> SSHHostKeyTrustMethod
        )
    }

    private let storage: Storage

    private init(storage: Storage) {
        self.storage = storage
    }

    /// Accept Any Verified host key.
    public static let acceptAnyVerifiedHostKey = Self(
        storage: .acceptAnyVerifiedHostKey
    )

    /// Requires the server host key to match one trusted key exactly.
    public static func requireMatch(_ trustedHostKey: SSHTrustedHostKey) -> Self {
        Self(storage: .requireMatch(trustedHostKey))
    }

    /// Requires the server host key to match one key in `trustedHostKeys`.
    public static func requireMatchAny(_ trustedHostKeys: [SSHTrustedHostKey]) -> Self {
        Self(storage: .requireMatchAny(trustedHostKeys))
    }

    /// Verifies the server with an OpenSSH-style `known_hosts` file.
    public static func knownHostsFile(_ path: String) -> Self {
        Self(
            storage: .knownHostsFile(
                path: path,
                additionalLookupNames: []
            )
        )
    }

    /// Verifies the server with an OpenSSH-style `known_hosts` file and
    /// additional lookup names.
    public static func knownHostsFile(
        _ path: String,
        additionalLookupNames: [String]
    ) -> Self {
        Self(
            storage: .knownHostsFile(
                path: path,
                additionalLookupNames: additionalLookupNames
            )
        )
    }

    /// Evaluates host trust with caller-owned async logic.
    public static func callback(
        _ evaluator: @escaping @Sendable (SSHHostKeyValidationRequest) async throws
            -> SSHHostKeyTrustMethod
    ) -> Self {
        Self(storage: .callback(evaluator))
    }

    /// Creates a trust-on-first-use policy that stores the first observed host
    /// key and rejects later mismatches.
    public static func trustOnFirstUse(
        lookup: @escaping @Sendable (_ endpointHost: String, _ endpointPort: UInt16)
            async throws -> SSHTrustedHostKey?,
        store: @escaping @Sendable (SSHHostKeyStoreRequest) async throws -> Void
    ) -> Self {
        Self.trustOnFirstUse(
            lookup: lookup,
            store: store,
            onStoredHostKeyMismatch: { _ in
                .reject
            }
        )
    }

    /// Creates a trust-on-first-use policy with caller-owned mismatch handling.
    public static func trustOnFirstUse(
        lookup: @escaping @Sendable (_ endpointHost: String, _ endpointPort: UInt16)
            async throws -> SSHTrustedHostKey?,
        store: @escaping @Sendable (SSHHostKeyStoreRequest) async throws -> Void,
        onStoredHostKeyMismatch: @escaping @Sendable (
            SSHHostKeyChangeRequest
        ) async throws -> SSHHostKeyChangeDecision
    ) -> Self {
        Self.callback { request in
            if let storedHostKey = try await lookup(
                request.endpointHost,
                request.endpointPort
            ) {
                guard !request.matches(storedHostKey) else {
                    return .callback
                }

                let changeRequest = SSHHostKeyChangeRequest(
                    endpointHost: request.endpointHost,
                    endpointPort: request.endpointPort,
                    remoteIdentification: request.remoteIdentification,
                    storedHostKey: storedHostKey,
                    receivedHostKey: request.trustedHostKey
                )

                switch try await onStoredHostKeyMismatch(changeRequest) {
                case .reject:
                    throw SSHHostKeyPolicyError.storedHostKeyMismatch(
                        endpointHost: request.endpointHost,
                        endpointPort: request.endpointPort,
                        storedHostKey: storedHostKey,
                        receivedHostKey: request.trustedHostKey
                    )
                case .replaceStoredHostKey:
                    try await store(
                        SSHHostKeyStoreRequest(
                            endpointHost: request.endpointHost,
                            endpointPort: request.endpointPort,
                            remoteIdentification: request.remoteIdentification,
                            expectedStoredHostKey: storedHostKey,
                            trustedHostKey: request.trustedHostKey
                        )
                    )
                    return .callback
                }
            }

            try await store(
                SSHHostKeyStoreRequest(
                    endpointHost: request.endpointHost,
                    endpointPort: request.endpointPort,
                    remoteIdentification: request.remoteIdentification,
                    expectedStoredHostKey: nil,
                    trustedHostKey: request.trustedHostKey
                )
            )
            return .callback
        }
    }

    /// Creates a trust-on-first-use policy backed by an `SSHHostKeyTrustStore`.
    public static func trustOnFirstUse<Store: SSHHostKeyTrustStore>(
        using store: Store
    ) -> Self {
        Self.trustOnFirstUse(
            lookup: { endpointHost, endpointPort in
                try await store.lookupHostKey(
                    endpointHost: endpointHost,
                    endpointPort: endpointPort
                )
            },
            store: { request in
                try await store.storeHostKey(request)
            },
            onStoredHostKeyMismatch: { request in
                try await store.decisionForChangedHostKey(request)
            }
        )
    }

    public static func ==(lhs: SSHHostKeyPolicy, rhs: SSHHostKeyPolicy) -> Bool {
        switch (lhs.storage, rhs.storage) {
        case (.acceptAnyVerifiedHostKey, .acceptAnyVerifiedHostKey):
            return true
        case let (.requireMatch(lhsKey), .requireMatch(rhsKey)):
            return lhsKey == rhsKey
        case let (.requireMatchAny(lhsKeys), .requireMatchAny(rhsKeys)):
            return lhsKeys == rhsKeys
        case let (
            .knownHostsFile(
                path: lhsPath,
                additionalLookupNames: lhsAdditionalLookupNames
            ),
            .knownHostsFile(
                path: rhsPath,
                additionalLookupNames: rhsAdditionalLookupNames
            )
        ):
            return lhsPath == rhsPath &&
                lhsAdditionalLookupNames == rhsAdditionalLookupNames
        case (.callback, .callback):
            return false
        default:
            return false
        }
    }

    func resolveTrustPolicy(for endpoint: SSHSocketEndpoint) throws -> SSHHostKeyTrustPolicy {
        switch self.storage {
        case .acceptAnyVerifiedHostKey:
            return .acceptAnyVerifiedHostKey
        case let .requireMatch(trustedHostKey):
            return .requireMatch(trustedHostKey)
        case let .requireMatchAny(trustedHostKeys):
            return .requireMatchAny(trustedHostKeys)
        case let .knownHostsFile(path, additionalLookupNames):
            let knownHosts = try SSHKnownHosts.load(from: path)
            return try knownHosts.requireTrustPolicy(
                for: endpoint,
                additionalLookupNames: additionalLookupNames
            )
        case let .callback(evaluator):
            return .callback { verifiedHostKey, context in
                let trustedHostKey = SSHTrustedHostKey(verifiedHostKey: verifiedHostKey)
                do {
                    let method = try await evaluator(
                        SSHHostKeyValidationRequest(
                            endpointHost: endpoint.host,
                            endpointPort: endpoint.port,
                            remoteIdentification: context.remoteIdentification?.rawValue,
                            trustedHostKey: trustedHostKey
                        )
                    )
                    return SSHHostKeyTrust(
                        method: method,
                        trustedHostKey: trustedHostKey,
                        context: context
                    )
                } catch let error as SSHHostKeyPolicyError {
                    throw error
                } catch {
                    throw SSHUserCallbackFailure(source: .hostKeyPolicy, error: error)
                }
            }
        }
    }
}
