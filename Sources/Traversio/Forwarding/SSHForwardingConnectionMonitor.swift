// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

struct SSHForwardingConnectionMonitor: Sendable {
    private let client: SSHTransportProtocolClient
    private let lifetime: SSHConnectionLifetime

    init(
        client: SSHTransportProtocolClient,
        lifetime: SSHConnectionLifetime
    ) {
        self.client = client
        self.lifetime = lifetime
    }

    func makeConnectionClosureTask(
        _ shutdown: @escaping @Sendable () async -> Void
    ) -> Task<Void, Never> {
        let lifetime = self.lifetime
        return Task {
            await lifetime.waitUntilClosed()
            await shutdown()
        }
    }

    func makeFallbackLivenessTaskIfNeeded() async -> Task<Void, Never>? {
        guard let policy = await self.client.forwardingFallbackKeepalivePolicy(),
              let intervalNanoseconds = policy.intervalNanoseconds else {
            return nil
        }

        let client = self.client
        let lifetime = self.lifetime
        return Task {
            while !Task.isCancelled {
                do {
                    try await Task.sleep(nanoseconds: intervalNanoseconds)
                } catch {
                    return
                }

                guard !Task.isCancelled else {
                    return
                }

                do {
                    try await client.sendKeepalive(
                        responseTimeoutNanoseconds: policy.responseTimeoutNanoseconds
                    )
                } catch is CancellationError {
                    return
                } catch {
                    await lifetime.close()
                    return
                }
            }
        }
    }

    func closeLifetimeIfNeeded(for error: any Error) async {
        guard Self.isConnectionLivenessFailure(error) else {
            return
        }

        await self.lifetime.close()
    }

    static func isConnectionLivenessFailure(_ error: any Error) -> Bool {
        if error is CancellationError {
            return false
        }

        if let clientError = error as? SSHClientError {
            switch clientError {
            case .connectionScopeEnded:
                return true
            case let .operationFailed(failure):
                switch failure.code {
                case .transportClosed,
                        .transportError,
                        .timeout,
                        .remoteDisconnect,
                        .unexpectedTransportMessage,
                        .unexpectedConnectionMessage:
                    return true
                default:
                    return false
                }
            default:
                return false
            }
        }

        if let transportError = error as? SSHTransportError {
            switch transportError {
            case .emptyReceive,
                 .transportClosed,
                 .endOfStreamBeforeIdentification,
                 .endOfStreamBeforePacket,
                 .unexpectedTransportMessage,
                 .strictKeyExchangeViolation,
                 .internalInvariantBroken:
                return true
            default:
                return false
            }
        }

        if let connectionError = error as? SSHConnectionError {
            switch connectionError {
            case .unexpectedConnectionMessage,
                    .invalidGlobalRequestResponse:
                return true
            default:
                return false
            }
        }

        return error is SSHTimeoutError
    }
}
