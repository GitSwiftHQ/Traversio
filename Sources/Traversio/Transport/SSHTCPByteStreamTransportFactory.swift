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
        switch preference {
        case .automatic:
            if #available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
                return SSHClientTransportHandle(
                    transport: try NetworkTCPByteStreamTransport.connect(to: endpoint)
                )
            }

            return SSHClientTransportHandle(
                transport: try await LegacyNetworkTCPByteStreamTransport.connect(to: endpoint)
            )
        case .modern:
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
            return SSHClientTransportHandle(
                transport: try NetworkTCPByteStreamTransport.connect(to: endpoint)
            )
        case .legacy:
            return SSHClientTransportHandle(
                transport: try await LegacyNetworkTCPByteStreamTransport.connect(to: endpoint)
            )
        }
    }

    static func makeRouteRootTransportHandle(
        to endpoint: SSHSocketEndpoint,
        preference: SSHTCPTransportBackendPreference = .automatic
    ) async throws -> SSHClientTransportHandle {
        switch preference {
        case .automatic, .legacy:
            return SSHClientTransportHandle(
                transport: try await LegacyNetworkTCPByteStreamTransport.connect(to: endpoint)
            )
        case .modern:
            return try await self.makeTransportHandle(
                to: endpoint,
                preference: preference
            )
        }
    }

    package static func connect(
        to endpoint: SSHSocketEndpoint,
        preference: SSHTCPTransportBackendPreference = .automatic
    ) async throws -> any SSHByteStreamTransport {
        switch preference {
        case .automatic:
            if #available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
                return try NetworkTCPByteStreamTransport.connect(to: endpoint)
            }

            return try await LegacyNetworkTCPByteStreamTransport.connect(to: endpoint)
        case .modern:
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
        case .legacy:
            return try await LegacyNetworkTCPByteStreamTransport.connect(to: endpoint)
        }
    }

    package static func withConnected<Result>(
        to endpoint: SSHSocketEndpoint,
        preference: SSHTCPTransportBackendPreference = .automatic,
        _ body: @escaping @Sendable (any SSHByteStreamTransport) async throws -> Result
    ) async throws -> Result {
        switch preference {
        case .automatic:
            if #available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *) {
                return try await NetworkTCPByteStreamTransport.withConnected(to: endpoint) {
                    transport in
                    try await body(transport)
                }
            }

            return try await LegacyNetworkTCPByteStreamTransport.withConnected(to: endpoint) {
                transport in
                try await body(transport)
            }
        case .modern:
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
        case .legacy:
            return try await LegacyNetworkTCPByteStreamTransport.withConnected(to: endpoint) {
                transport in
                try await body(transport)
            }
        }
    }

    private static func unavailableModernTransportError() -> SSHTransportError {
        SSHTransportError.unsupportedTransportBackend(
            "The modern NetworkConnection<TCP> transport requires Apple platform release 26 or newer."
        )
    }
}
