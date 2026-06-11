// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

package enum SSHTCPTransportBackendPreference: String, Equatable, Sendable {
    case automatic
    case modern
    case legacy
}
package enum SSHTCPByteStreamTransportFactory {
    static func makeTransportHandle(
        to endpoint: SSHSocketEndpoint,
        preference: SSHTCPTransportBackendPreference = .automatic
    ) async throws -> SSHClientTransportHandle {
        try await self.makeTransportHandle(
            to: endpoint,
            policy: self.policy(
                role: .ordinaryConnection,
                preference: preference
            )
        )
    }

    static func makeRouteRootTransportHandle(
        to endpoint: SSHSocketEndpoint,
        preference: SSHTCPTransportBackendPreference = .automatic
    ) async throws -> SSHClientTransportHandle {
        try await self.makeTransportHandle(
            to: endpoint,
            policy: self.policy(
                role: .routeRootConnection,
                preference: preference
            )
        )
    }

    package static func connect(
        to endpoint: SSHSocketEndpoint,
        preference: SSHTCPTransportBackendPreference = .automatic
    ) async throws -> any SSHByteStreamTransport {
        try await self.makeTransport(
            to: endpoint,
            policy: self.policy(
                role: .ordinaryConnection,
                preference: preference
            )
        )
    }

    package static func withConnected<Result>(
        to endpoint: SSHSocketEndpoint,
        preference: SSHTCPTransportBackendPreference = .automatic,
        _ body: @escaping (any SSHByteStreamTransport) async throws -> Result
    ) async throws -> Result {
        try await self.withConnected(
            to: endpoint,
            policy: self.policy(
                role: .scopedConnection,
                preference: preference
            ),
            body
        )
    }

    package static func withConnected<Result>(
        to endpoint: SSHSocketEndpoint,
        policy: SSHTCPTransportFlowPolicy,
        _ body: @escaping (any SSHByteStreamTransport) async throws -> Result
    ) async throws -> Result {
        switch policy.selectedBackend {
        case .modernNetworkConnection:
            guard #available(
                macOS 26.0,
                iOS 26.0,
                tvOS 26.0,
                watchOS 26.0,
                visionOS 26.0,
                *
            ) else {
                throw self.unavailableModernTransportError()
            }
            return try await NetworkTCPByteStreamTransport.withConnected(to: endpoint) {
                transport in
                try await body(transport)
            }
        case .legacyNWConnection:
            return try await LegacyNetworkTCPByteStreamTransport.withConnected(to: endpoint) {
                transport in
                try await body(transport)
            }
        }
    }

    private static func makeTransportHandle(
        to endpoint: SSHSocketEndpoint,
        policy: SSHTCPTransportFlowPolicy
    ) async throws -> SSHClientTransportHandle {
        if policy.ownershipModel == .libraryOwnedStructuredScope {
            guard #available(
                macOS 26.0,
                iOS 26.0,
                tvOS 26.0,
                watchOS 26.0,
                visionOS 26.0,
                *
            ) else {
                throw self.unavailableModernTransportError()
            }
            return try await NetworkTCPByteStreamTransport.makeRouteRootTransportHandle(
                to: endpoint
            )
        }

        return SSHClientTransportHandle(
            transport: try await self.makeTransport(to: endpoint, policy: policy)
        )
    }

    private static func makeTransport(
        to endpoint: SSHSocketEndpoint,
        policy: SSHTCPTransportFlowPolicy
    ) async throws -> any SSHByteStreamTransport {
        switch policy.selectedBackend {
        case .modernNetworkConnection:
            guard #available(
                macOS 26.0,
                iOS 26.0,
                tvOS 26.0,
                watchOS 26.0,
                visionOS 26.0,
                *
            ) else {
                throw self.unavailableModernTransportError()
            }
            return try NetworkTCPByteStreamTransport.connect(to: endpoint)
        case .legacyNWConnection:
            return try await LegacyNetworkTCPByteStreamTransport.connect(to: endpoint)
        }
    }

    private static func policy(
        role: SSHTCPTransportFlowRole,
        preference: SSHTCPTransportBackendPreference
    ) -> SSHTCPTransportFlowPolicy {
        SSHTCPTransportFlowPolicy.resolveCurrentPlatform(
            role: role,
            preference: preference
        )
    }

    private static func unavailableModernTransportError() -> SSHTransportError {
        SSHTransportError.unsupportedTransportBackend(
            "The modern NetworkConnection<TCP> transport requires Apple platform release 26 or newer."
        )
    }
}
