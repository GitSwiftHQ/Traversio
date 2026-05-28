// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

extension SSHClient {
    private static let defaultDiscoveryGracefulCloseTimeoutNanoseconds: UInt64 = 1_000_000_000

    private actor DiscoveryTaskCompletionGate {
        private var continuation: CheckedContinuation<Bool, Never>?

        init(_ continuation: CheckedContinuation<Bool, Never>) {
            self.continuation = continuation
        }

        func resume(with value: Bool) {
            guard let continuation else {
                return
            }

            self.continuation = nil
            continuation.resume(returning: value)
        }
    }

    /// Discovers the authentication method names offered by a server for a
    /// username.
    ///
    /// Example:
    ///
    /// ```swift
    /// let result = try await SSHClient.discoverAuthenticationMethods(
    ///     configuration: discoveryConfiguration
    /// )
    /// print(result.availableMethods)
    /// ```
    public static func discoverAuthenticationMethods(
        configuration: SSHAuthenticationMethodDiscoveryConfiguration
    ) async throws -> SSHAuthenticationMethodDiscoveryResult {
        try await self.discoverAuthenticationMethods(
            configuration: configuration,
            logHandler: .disabled
        )
    }

    /// Discovers server authentication methods with a caller-provided log
    /// handler.
    public static func discoverAuthenticationMethods(
        configuration: SSHAuthenticationMethodDiscoveryConfiguration,
        logHandler: SSHClientLogHandler
    ) async throws -> SSHAuthenticationMethodDiscoveryResult {
        try await self.discoverAuthenticationMethods(
            configuration: configuration,
            logHandler: logHandler,
            transportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeDefaultTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy
                )
            },
            routeRootTransportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeDefaultRouteRootTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy
                )
            },
            jumpTransportFactory: self.makeJumpTransportHandle
        )
    }

    static func discoverAuthenticationMethods(
        configuration: SSHAuthenticationMethodDiscoveryConfiguration,
        transportFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> any SSHByteStreamTransport
    ) async throws -> SSHAuthenticationMethodDiscoveryResult {
        try await self.discoverAuthenticationMethods(
            configuration: configuration,
            logHandler: .disabled,
            transportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy,
                    transportFactory: transportFactory
                )
            },
            jumpTransportFactory: self.makeJumpTransportHandle
        )
    }

    static func discoverAuthenticationMethods(
        configuration: SSHAuthenticationMethodDiscoveryConfiguration,
        logHandler: SSHClientLogHandler,
        transportFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> any SSHByteStreamTransport
    ) async throws -> SSHAuthenticationMethodDiscoveryResult {
        try await self.discoverAuthenticationMethods(
            configuration: configuration,
            logHandler: logHandler,
            transportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy,
                    transportFactory: transportFactory
                )
            },
            jumpTransportFactory: self.makeJumpTransportHandle
        )
    }

    static func discoverAuthenticationMethods(
        configuration: SSHAuthenticationMethodDiscoveryConfiguration,
        logHandler: SSHClientLogHandler,
        transportHandleFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle,
        routeRootTransportHandleFactory: (@Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle)? = nil,
        jumpTransportFactory: @escaping @Sendable (
            _ upstreamConnection: SSHConnection,
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle
    ) async throws -> SSHAuthenticationMethodDiscoveryResult {
        let endpoint = SSHSocketEndpoint(host: configuration.host, port: configuration.port)

        guard configuration.proxyJumpHosts.isEmpty else {
            return try await self.discoverAuthenticationMethodsViaProxyJump(
                configuration: configuration,
                logHandler: logHandler,
                transportHandleFactory: transportHandleFactory,
                routeRootTransportHandleFactory: routeRootTransportHandleFactory,
                jumpTransportFactory: jumpTransportFactory
            )
        }

        self.logAuthenticationMethodDiscoveryStarted(
            endpoint: endpoint,
            username: configuration.username,
            logHandler: logHandler
        )

        return try await self.performAuthenticationMethodDiscoveryWithRouteSetupTimeout(
            configuration: configuration,
            endpoint: endpoint,
            transportHandleFactory: {
                try await transportHandleFactory(endpoint)
            },
            logHandler: logHandler
        )
    }

    static func discoverAuthenticationMethods(
        configuration: SSHAuthenticationMethodDiscoveryConfiguration,
        transportRunner: (
            _ endpoint: SSHSocketEndpoint,
            _ handler: @escaping (any SSHByteStreamTransport) async throws
                -> SSHAuthenticationMethodDiscoveryResult
        ) async throws -> SSHAuthenticationMethodDiscoveryResult
    ) async throws -> SSHAuthenticationMethodDiscoveryResult {
        try await self.discoverAuthenticationMethods(
            configuration: configuration,
            logHandler: .disabled,
            transportRunner: transportRunner
        )
    }

    static func discoverAuthenticationMethods(
        configuration: SSHAuthenticationMethodDiscoveryConfiguration,
        logHandler: SSHClientLogHandler,
        transportRunner: (
            _ endpoint: SSHSocketEndpoint,
            _ handler: @escaping (any SSHByteStreamTransport) async throws
                -> SSHAuthenticationMethodDiscoveryResult
        ) async throws -> SSHAuthenticationMethodDiscoveryResult
    ) async throws -> SSHAuthenticationMethodDiscoveryResult {
        let endpoint = SSHSocketEndpoint(host: configuration.host, port: configuration.port)
        self.logAuthenticationMethodDiscoveryStarted(
            endpoint: endpoint,
            username: configuration.username,
            logHandler: logHandler
        )

        return try await transportRunner(endpoint) { transport in
            try await self.performAuthenticationMethodDiscovery(
                configuration: configuration,
                endpoint: endpoint,
                transportHandle: SSHClientTransportHandle(transport: transport),
                logHandler: logHandler
            )
        }
    }

    private static func performAuthenticationMethodDiscoveryWithRouteSetupTimeout(
        configuration: SSHAuthenticationMethodDiscoveryConfiguration,
        endpoint: SSHSocketEndpoint,
        transportHandleFactory: @escaping @Sendable () async throws -> SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)? = nil,
        failedSetupDependentCloseOperation: (@Sendable () async -> Void)? = nil,
        logHandler: SSHClientLogHandler
    ) async throws -> SSHAuthenticationMethodDiscoveryResult {
        let timeoutPolicy = SSHInternalTimeoutPolicy(configuration.timeoutPolicy)
        let connectionSetupBudget = SSHConnectionSetupTimeoutBudget(
            timeoutNanoseconds: timeoutPolicy.connectionSetupTimeoutNanoseconds
        )
        do {
            let transportHandle = try await connectionSetupBudget.withTimeout {
                try await transportHandleFactory()
            }
            return try await self.performAuthenticationMethodDiscovery(
                configuration: configuration,
                endpoint: endpoint,
                transportHandle: transportHandle,
                dependentCloseOperation: dependentCloseOperation,
                failedSetupDependentCloseOperation: failedSetupDependentCloseOperation,
                logHandler: logHandler,
                connectionSetupBudget: connectionSetupBudget
            )
        } catch let error as SSHClientError {
            throw error
        } catch let error as SSHHostKeyPolicyError {
            throw error
        } catch let error as SSHAuthenticationMethodError {
            throw error
        } catch {
            throw self.wrapEarlyAuthenticationMethodDiscoverySetupError(
                error,
                username: configuration.username,
                endpoint: endpoint,
                logHandler: logHandler
            )
        }
    }

    private static func performAuthenticationMethodDiscovery(
        configuration: SSHAuthenticationMethodDiscoveryConfiguration,
        endpoint: SSHSocketEndpoint,
        transportHandle: SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)? = nil,
        failedSetupDependentCloseOperation: (@Sendable () async -> Void)? = nil,
        logHandler: SSHClientLogHandler,
        connectionSetupBudget: SSHConnectionSetupTimeoutBudget? = nil
    ) async throws -> SSHAuthenticationMethodDiscoveryResult {
        let timeoutPolicy = SSHInternalTimeoutPolicy(configuration.timeoutPolicy)
        let connectionSetupBudget =
            connectionSetupBudget
            ?? SSHConnectionSetupTimeoutBudget(
                timeoutNanoseconds: timeoutPolicy.connectionSetupTimeoutNanoseconds
            )
        let transportConfiguration = SSHTransportProtocolClientConfiguration(
            preferredServerHostKeyAlgorithms:
                configuration.legacyAlgorithmOptions.preferredServerHostKeyAlgorithms,
            compressionPreference: configuration.compressionPreference,
            automaticRekeyPolicy: .disabled,
            keepalivePolicy: .disabled,
            responseTimeoutNanoseconds: timeoutPolicy.responseTimeoutNanoseconds
        )
        let client = SSHTransportProtocolClient(
            transport: transportHandle.transport,
            transportConfiguration: transportConfiguration
        )

        do {
            let hostKeyTrustPolicy = try configuration.hostKeyPolicy.resolveTrustPolicy(
                for: endpoint
            )
            _ = try await connectionSetupBudget.withTimeout {
                try await client.exchangeIdentifications()
            }
            let negotiation = try await connectionSetupBudget.withTimeout {
                try await client.exchangeKeyExchangeInit()
            }
            let keyExchangeResult = try await connectionSetupBudget.withTimeout {
                try await client.beginCurve25519KeyExchange(negotiation: negotiation)
            }
            let hostKeyTrustEvaluation = try await client.evaluateCurve25519HostKeyTrust(
                negotiation: negotiation,
                keyExchangeResult: keyExchangeResult,
                remoteEndpoint: endpoint,
                hostKeyTrustPolicy: hostKeyTrustPolicy,
                hostKeyTrustTimeoutNanoseconds: timeoutPolicy.hostKeyTrustTimeoutNanoseconds
            )
            _ = try await connectionSetupBudget.withTimeout {
                try await client.activateTrustedCurve25519Transport(
                    evaluation: hostKeyTrustEvaluation,
                    remoteEndpoint: endpoint,
                    hostKeyTrustPolicy: hostKeyTrustPolicy
                )
            }
            let result = try await connectionSetupBudget.withTimeout {
                try await client.discoverAuthenticationMethods(username: configuration.username)
            }

            self.logAuthenticationMethodDiscoveryCompleted(
                result,
                endpoint: endpoint,
                logHandler: logHandler
            )
            await self.closeDiscoveryTransportResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: dependentCloseOperation,
                gracefulCloseTimeoutNanoseconds: self.discoveryGracefulCloseTimeoutNanoseconds(
                    responseTimeoutNanoseconds: timeoutPolicy.responseTimeoutNanoseconds
                )
            )
            return result
        } catch let error as SSHClientError {
            await self.abortDiscoveryTransportResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation
            )
            throw error
        } catch let error as SSHHostKeyPolicyError {
            await self.abortDiscoveryTransportResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation
            )
            throw error
        } catch let error as SSHAuthenticationMethodError {
            await self.abortDiscoveryTransportResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation
            )
            throw error
        } catch {
            let snapshot = await client.diagnosticsSnapshot()
            await self.abortDiscoveryTransportResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation
            )

            if let failure = self.wrapConnectionFailure(
                error,
                endpoint: endpoint,
                username: configuration.username,
                snapshot: snapshot
            ) {
                logHandler.logConnectionFailure(failure)
                throw SSHClientError.connectionFailed(failure)
            }

            logHandler.logUnwrappedConnectionFailure(
                error,
                endpoint: endpoint
            )
            throw error
        }
    }

    private static func discoverAuthenticationMethodsViaProxyJump(
        configuration: SSHAuthenticationMethodDiscoveryConfiguration,
        logHandler: SSHClientLogHandler,
        transportHandleFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle,
        routeRootTransportHandleFactory: (@Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle)? = nil,
        jumpTransportFactory: @escaping @Sendable (
            _ upstreamConnection: SSHConnection,
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle
    ) async throws -> SSHAuthenticationMethodDiscoveryResult {
        let routePlan = SSHRoutePlan(configuration: configuration)
        let routeGraph = SSHRouteLifecycleGraph(plan: routePlan)
        let finalEndpoint = routePlan.finalEndpoint
        let routeLifecycle = SSHRouteLifecycleOwner(graph: routeGraph)
        let rootTransportHandleFactory =
            routeRootTransportHandleFactory ?? transportHandleFactory
        self.logAuthenticationMethodDiscoveryStarted(
            endpoint: finalEndpoint,
            username: configuration.username,
            logHandler: logHandler
        )

        do {
            for (hopIndex, hop) in configuration.proxyJumpHosts.enumerated() {
                let hopOrdinal = hopIndex + 1
                guard let hopEdgeID = routeGraph.sshHopEdgeID(ordinal: hopOrdinal) else {
                    preconditionFailure("Missing ProxyJump hop edge \(hopOrdinal)")
                }
                let endpoint = SSHSocketEndpoint(host: hop.host, port: hop.port)
                let hopConfiguration = SSHClientConfiguration(
                    host: hop.host,
                    port: hop.port,
                    username: hop.username,
                    authenticationMethods: hop.authenticationMethods,
                    hostKeyPolicy: hop.hostKeyPolicy,
                    compressionPreference: hop.compressionPreference,
                    legacyAlgorithmOptions: hop.legacyAlgorithmOptions,
                    automaticRekeyPolicy: hop.automaticRekeyPolicy,
                    keepalivePolicy: hop.keepalivePolicy,
                    timeoutPolicy: hop.timeoutPolicy
                )

                let upstreamConnection = await routeLifecycle.lastConnection()
                await routeLifecycle.beginAcquiringConnection(edgeID: hopEdgeID)
                let connection = try await self.connect(
                    configuration: hopConfiguration,
                    logHandler: logHandler,
                    transportHandleFactory: { _ in
                        if let upstreamConnection {
                            try await jumpTransportFactory(upstreamConnection, endpoint)
                        } else {
                            try await rootTransportHandleFactory(endpoint)
                        }
                    }
                )
                await routeLifecycle.registerConnection(connection, edgeID: hopEdgeID)
            }

            let upstreamConnection = await routeLifecycle.lastConnection()

            await routeLifecycle.beginAcquiringConnection(edgeID: routeGraph.finalSSHEdgeID)
            let result = try await self.performAuthenticationMethodDiscoveryWithRouteSetupTimeout(
                configuration: configuration,
                endpoint: finalEndpoint,
                transportHandleFactory: {
                    if let upstreamConnection {
                        try await jumpTransportFactory(upstreamConnection, finalEndpoint)
                    } else {
                        try await rootTransportHandleFactory(finalEndpoint)
                    }
                },
                dependentCloseOperation: {
                    await routeLifecycle.closeAfterExternalFinalClose()
                },
                failedSetupDependentCloseOperation: {
                    await routeLifecycle.abortAfterExternalFinalClose()
                },
                logHandler: logHandler
            )
            return result
        } catch let error as SSHClientError {
            await routeLifecycle.abort()
            throw error
        } catch let error as SSHHostKeyPolicyError {
            await routeLifecycle.abort()
            throw error
        } catch let error as SSHAuthenticationMethodError {
            await routeLifecycle.abort()
            throw error
        } catch {
            await routeLifecycle.abort()
            throw self.wrapEarlyAuthenticationMethodDiscoverySetupError(
                error,
                username: configuration.username,
                endpoint: finalEndpoint,
                logHandler: logHandler
            )
        }
    }

    private static func discoveryGracefulCloseTimeoutNanoseconds(
        responseTimeoutNanoseconds: UInt64?
    ) -> UInt64 {
        guard let responseTimeoutNanoseconds else {
            return self.defaultDiscoveryGracefulCloseTimeoutNanoseconds
        }

        return max(
            1,
            min(
                responseTimeoutNanoseconds,
                self.defaultDiscoveryGracefulCloseTimeoutNanoseconds
            )
        )
    }

    private static func closeDiscoveryTransportResources(
        client: SSHTransportProtocolClient,
        transportHandle: SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)?,
        gracefulCloseTimeoutNanoseconds: UInt64
    ) async {
        let disconnectTask = Task {
            await client.disconnect()
        }

        let didDisconnectFinish = await self.waitForDiscoveryTaskCompletion(
            disconnectTask,
            upTo: gracefulCloseTimeoutNanoseconds
        )
        if !didDisconnectFinish {
            disconnectTask.cancel()
        }

        await transportHandle.close()
        await dependentCloseOperation?()
    }

    private static func abortDiscoveryTransportResources(
        client: SSHTransportProtocolClient,
        transportHandle: SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)?
    ) async {
        await client.abortTransportLifecycle()
        await transportHandle.abort()
        await dependentCloseOperation?()
    }

    private static func waitForDiscoveryTaskCompletion(
        _ task: Task<Void, Never>,
        upTo nanoseconds: UInt64
    ) async -> Bool {
        await withCheckedContinuation { continuation in
            let gate = DiscoveryTaskCompletionGate(continuation)

            Task {
                await task.value
                await gate.resume(with: true)
            }

            Task {
                try? await Task.sleep(nanoseconds: nanoseconds)
                await gate.resume(with: false)
            }
        }
    }

    private static func logAuthenticationMethodDiscoveryStarted(
        endpoint: SSHSocketEndpoint,
        username: String,
        logHandler: SSHClientLogHandler
    ) {
        logHandler.emit(
            level: .info,
            category: .authentication,
            message: "Starting SSH authentication method discovery.",
            metadata: sshLogMetadata(
                ("endpointHost", endpoint.host),
                ("endpointPort", String(endpoint.port)),
                ("username", username),
                ("authenticationMethod", "none")
            )
        )
    }

    private static func logAuthenticationMethodDiscoveryCompleted(
        _ result: SSHAuthenticationMethodDiscoveryResult,
        endpoint: SSHSocketEndpoint,
        logHandler: SSHClientLogHandler
    ) {
        logHandler.emit(
            level: .info,
            category: .authentication,
            message: result.allowsUnauthenticatedAccess
                ? "SSH target accepted unauthenticated access during discovery."
                : "Discovered SSH authentication methods.",
            metadata: sshLogMetadata(
                ("endpointHost", endpoint.host),
                ("endpointPort", String(endpoint.port)),
                ("username", result.username),
                ("serviceName", result.serviceName),
                (
                    "availableMethods",
                    result.availableMethods.isEmpty
                        ? nil
                        : result.availableMethods.joined(separator: ",")
                ),
                ("partialSuccess", String(result.partialSuccess)),
                (
                    "allowsUnauthenticatedAccess",
                    String(result.allowsUnauthenticatedAccess)
                ),
                ("bannerCount", String(result.banners.count))
            )
        )
    }

    private static func wrapEarlyAuthenticationMethodDiscoverySetupError(
        _ error: any Error,
        username: String,
        endpoint: SSHSocketEndpoint,
        logHandler: SSHClientLogHandler
    ) -> any Error {
        let snapshot = SSHTransportProtocolDiagnosticsSnapshot(
            phase: .identification,
            clientIdentification: SSHTransportProtocolClient.defaultClientIdentification.rawValue,
            remoteIdentification: nil,
            preIdentificationLines: [],
            keepaliveIntervalNanoseconds: nil,
            keepaliveReplyTimeoutNanoseconds: nil,
            responseTimeoutNanoseconds: nil,
            negotiatedAlgorithms: nil,
            didReceiveServerExtensionInfo: false,
            serverExtensionNames: [],
            serverSignatureAlgorithms: nil,
            remoteDisconnect: nil,
            remoteDebugMessages: []
        )

        if let failure = self.wrapConnectionFailure(
            error,
            endpoint: endpoint,
            username: username,
            snapshot: snapshot
        ) {
            logHandler.logConnectionFailure(failure)
            return SSHClientError.connectionFailed(failure)
        }

        logHandler.logUnwrappedConnectionFailure(
            error,
            endpoint: endpoint
        )
        return error
    }
}
