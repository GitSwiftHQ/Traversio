// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Network

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
package final class NetworkTCPListener: @unchecked Sendable, SSHTCPListener {
    // Sendable invariant: `NetworkListener` owns callback serialization; readiness completion
    // is protected by `SSHTCPAsyncResult`.
    private let listener: NetworkListener<TCP>
    private let readyState = SSHTCPAsyncResult<UInt16>()

    package init(localHost: String, localPort: UInt16) throws {
        let localEndpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(localHost),
            port: try SSHTCPEndpointParser.port(localPort)
        )
        let parameters = NWParametersBuilder<TCP>.parameters {
            TCP()
        }
            .localEndpoint(localEndpoint)
            .localEndpointReuseAllowed(true)
        let listener = try NetworkListener(using: parameters)
        self.listener = listener

        listener.onStateUpdate { listener, state in
            switch state {
            case .ready:
                if let boundPort = listener.port?.rawValue {
                    self.readyState.resume(with: .success(boundPort))
                } else {
                    self.readyState.resume(
                        with: .failure(SSHTransportError.listenerDidNotReportPort)
                    )
                }
            case let .failed(error):
                self.readyState.resume(with: .failure(error))
            case .cancelled:
                self.readyState.resume(with: .failure(CancellationError()))
            case .setup, .waiting:
                break
            @unknown default:
                break
            }
        }
    }

    package func readyPort() async throws -> UInt16 {
        try await self.readyState.value()
    }

    package func run(
        _ handler: @escaping @Sendable (SSHTCPAcceptedConnection) async -> Void
    ) async throws {
        try await self.listener.run { connection in
            await handler(
                SSHTCPAcceptedConnection(
                    originatorResult: SSHTCPEndpointParser.originatorResult(
                        for: connection.remoteEndpoint
                    ),
                    transport: NetworkTCPByteStreamTransport(connection: connection)
                )
            )
        }
    }
}
