// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Entry points for connecting to SSH servers and running scoped SSH work.
///
/// Example:
///
/// ```swift
/// let configuration = SSHClientConfiguration(
///     host: "server.example.com",
///     username: "deploy",
///     authentication: .password("secret"),
///     hostKeyPolicy: .knownHostsFile("/Users/me/.ssh/known_hosts")
/// )
///
/// let result = try await SSHClient.withConnection(configuration: configuration) {
///     try await $0.execute("uptime")
/// }
/// ```
public enum SSHClient {
    private static let defaultGracefulCloseTimeoutNanoseconds: UInt64 = 1_000_000_000

    private actor TaskCompletionGate {
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

    actor ConnectionSetupCleanup {
        private enum State {
            case waitingForTransport
            case acquiredTransport(SSHClientTransportHandle, connectionSetupStarted: Bool)
            case closed
            case released
        }

        private var state: State = .waitingForTransport

        func register(_ transportHandle: SSHClientTransportHandle) -> Bool {
            guard case .waitingForTransport = self.state else {
                return false
            }

            self.state = .acquiredTransport(
                transportHandle,
                connectionSetupStarted: false
            )
            return true
        }

        func beginConnectionSetup() -> Bool {
            guard case let .acquiredTransport(transportHandle, _) = self.state else {
                return false
            }

            self.state = .acquiredTransport(
                transportHandle,
                connectionSetupStarted: true
            )
            return true
        }

        func claimSetupTimeoutClose() -> SSHClientTransportHandle? {
            guard case let .acquiredTransport(transportHandle, _) = self.state else {
                return nil
            }

            self.state = .closed
            return transportHandle
        }

        func claimClose() -> SSHClientTransportHandle? {
            guard case let .acquiredTransport(transportHandle, _) = self.state else {
                return nil
            }

            self.state = .closed
            return transportHandle
        }

        func release() {
            self.state = .released
        }
    }

    /// Connects, verifies the host key, authenticates, and returns an open
    /// connection.
    ///
    /// The caller owns the returned connection and must eventually call
    /// `SSHConnection.close()`.
    public static func connect(
        configuration: SSHClientConfiguration
    ) async throws -> SSHConnection {
        return try await self.connect(
            configuration: configuration,
            logHandler: .disabled
        )
    }

    /// Connects with a caller-provided log handler.
    ///
    /// Use `SSHClientLogRecorder` when the app wants a bounded, redacted support
    /// report after failures.
    public static func connect(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler
    ) async throws -> SSHConnection {
        return try await self.connect(
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

    package static func connect(
        configuration: SSHClientConfiguration,
        transportBackendPreference: SSHTCPTransportBackendPreference
    ) async throws -> SSHConnection {
        return try await self.connect(
            configuration: configuration,
            logHandler: .disabled,
            transportBackendPreference: transportBackendPreference
        )
    }

    package static func connect(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportBackendPreference: SSHTCPTransportBackendPreference
    ) async throws -> SSHConnection {
        return try await self.connect(
            configuration: configuration,
            logHandler: logHandler,
            transportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeDefaultTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy,
                    preference: transportBackendPreference
                )
            },
            routeRootTransportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeDefaultRouteRootTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy,
                    preference: transportBackendPreference
                )
            },
            jumpTransportFactory: self.makeJumpTransportHandle,
            connectionTransportBackendPreference: transportBackendPreference
        )
    }

    /// Connects, runs `body`, and closes the connection when `body` returns or
    /// throws.
    ///
    /// This is the safest entry point for one-off operations.
    public static func withConnection<Result>(
        configuration: SSHClientConfiguration,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        try await self.withConnection(
            configuration: configuration,
            logHandler: .disabled,
            body
        )
    }

    /// Connects with logging, runs `body`, and closes the connection when
    /// `body` returns or throws.
    public static func withConnection<Result>(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        let connection = try await self.connect(
            configuration: configuration,
            logHandler: logHandler
        )

        do {
            let result = try await body(connection)
            await connection.close()
            return result
        } catch {
            await connection.close()
            throw error
        }
    }

    package static func withConnection<Result>(
        configuration: SSHClientConfiguration,
        transportBackendPreference: SSHTCPTransportBackendPreference,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        try await self.withConnection(
            configuration: configuration,
            logHandler: .disabled,
            transportBackendPreference: transportBackendPreference,
            body
        )
    }

    package static func withConnection<Result>(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportBackendPreference: SSHTCPTransportBackendPreference,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        let connection = try await self.connect(
            configuration: configuration,
            logHandler: logHandler,
            transportBackendPreference: transportBackendPreference
        )

        do {
            let result = try await body(connection)
            await connection.close()
            return result
        } catch {
            await connection.close()
            throw error
        }
    }

    static func connect(
        configuration: SSHClientConfiguration,
        transportFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> any SSHByteStreamTransport
    ) async throws -> SSHConnection {
        try await self.connect(
            configuration: configuration,
            logHandler: .disabled,
            transportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy,
                    transportFactory: transportFactory
                )
            }
        )
    }

    static func connect(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> any SSHByteStreamTransport
    ) async throws -> SSHConnection {
        try await self.connect(
            configuration: configuration,
            logHandler: logHandler,
            transportFactory: transportFactory,
            jumpTransportFactory: self.makeJumpTransportHandle,
            connectionTransportBackendPreference: .automatic
        )
    }

    static func connect(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> any SSHByteStreamTransport,
        jumpTransportFactory: @escaping @Sendable (
            _ upstreamConnection: SSHConnection,
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle
        ,
        connectionTransportBackendPreference: SSHTCPTransportBackendPreference = .automatic
    ) async throws -> SSHConnection {
        try await self.connect(
            configuration: configuration,
            logHandler: logHandler,
            transportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy,
                    transportFactory: transportFactory
                )
            },
            jumpTransportFactory: jumpTransportFactory,
            connectionTransportBackendPreference: connectionTransportBackendPreference
        )
    }

    static func connect(
        configuration: SSHClientConfiguration,
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
        ,
        connectionTransportBackendPreference: SSHTCPTransportBackendPreference = .automatic
    ) async throws -> SSHConnection {
        if configuration.proxyJumpHosts.isEmpty {
            let endpoint = SSHSocketEndpoint(host: configuration.host, port: configuration.port)
            let directRouteRootTransportHandleFactory =
                routeRootTransportHandleFactory ?? transportHandleFactory
            logHandler.logConnectionStarted(
                endpoint: endpoint,
                username: configuration.username,
                authentication: configuration.authentication
            )

            return try await self.makeConnectionWithRouteSetupTimeout(
                configuration: configuration,
                endpoint: endpoint,
                transportHandleFactory: {
                    try await directRouteRootTransportHandleFactory(endpoint)
                },
                transportBackendPreference: connectionTransportBackendPreference,
                logHandler: logHandler
            )
        }

        return try await self.connectViaProxyJump(
            configuration: configuration,
            logHandler: logHandler,
            transportHandleFactory: transportHandleFactory,
            routeRootTransportHandleFactory: routeRootTransportHandleFactory,
            jumpTransportFactory: jumpTransportFactory,
            connectionTransportBackendPreference: connectionTransportBackendPreference
        )
    }

    static func connect(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportHandleFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle
    ) async throws -> SSHConnection {
        try await self.connect(
            configuration: configuration,
            logHandler: logHandler,
            transportHandleFactory: transportHandleFactory,
            jumpTransportFactory: self.makeJumpTransportHandle
        )
    }

    static func makeJumpTransportHandle(
        upstreamConnection: SSHConnection,
        endpoint: SSHSocketEndpoint
    ) async throws -> SSHClientTransportHandle {
        try await upstreamConnection.makeJumpTransportHandle(to: endpoint)
    }

    static func withConnection<Result>(
        configuration: SSHClientConfiguration,
        transportRunner: (
            _ endpoint: SSHSocketEndpoint,
            _ handler: @escaping (any SSHByteStreamTransport) async throws -> Result
        ) async throws -> Result,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        try await self.withConnection(
            configuration: configuration,
            logHandler: .disabled,
            transportRunner: transportRunner,
            body
        )
    }

    static func withConnection<Result>(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportRunner: (
            _ endpoint: SSHSocketEndpoint,
            _ handler: @escaping (any SSHByteStreamTransport) async throws -> Result
        ) async throws -> Result,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        let endpoint = SSHSocketEndpoint(host: configuration.host, port: configuration.port)

        return try await transportRunner(endpoint) { transport in
            let connection = try await self.makeConnection(
                configuration: configuration,
                endpoint: endpoint,
                transportHandle: SSHClientTransportHandle(transport: transport),
                transportBackendPreference: .automatic,
                logHandler: logHandler
            )

            do {
                let result = try await body(connection)
                await connection.close()
                return result
            } catch {
                await connection.close()
                throw error
            }
        }
    }

    private static func makeConnectionWithRouteSetupTimeout(
        configuration: SSHClientConfiguration,
        endpoint: SSHSocketEndpoint,
        transportHandleFactory: @escaping @Sendable () async throws -> SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)? = nil,
        failedSetupDependentCloseOperation: (@Sendable () async -> Void)? = nil,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic,
        logHandler: SSHClientLogHandler
    ) async throws -> SSHConnection {
        let timeoutPolicy = SSHInternalTimeoutPolicy(configuration.timeoutPolicy)
        let connectionSetupBudget = SSHConnectionSetupTimeoutBudget(
            timeoutNanoseconds: timeoutPolicy.connectionSetupTimeoutNanoseconds
        )
        let setupCleanup = ConnectionSetupCleanup()
        do {
            let transportHandle = try await connectionSetupBudget.withTimeout {
                try await transportHandleFactory()
            }
            guard await setupCleanup.register(transportHandle) else {
                await transportHandle.abort()
                throw CancellationError()
            }
            guard await setupCleanup.beginConnectionSetup() else {
                await transportHandle.abort()
                throw CancellationError()
            }

            return try await self.makeConnection(
                configuration: configuration,
                endpoint: endpoint,
                transportHandle: transportHandle,
                dependentCloseOperation: dependentCloseOperation,
                failedSetupDependentCloseOperation: failedSetupDependentCloseOperation,
                transportBackendPreference: transportBackendPreference,
                logHandler: logHandler,
                setupCleanup: setupCleanup,
                connectionSetupBudget: connectionSetupBudget
            )
        } catch let error as SSHClientError {
            throw error
        } catch let error as CancellationError {
            throw error
        } catch {
            throw self.wrapEarlyConnectionSetupError(
                error,
                username: configuration.username,
                endpoint: endpoint,
                logHandler: logHandler
            )
        }
    }

    private static func withConnectionSetupTimeout<Result: Sendable>(
        _ connectionSetupBudget: SSHConnectionSetupTimeoutBudget,
        _ operation: @escaping @Sendable () async throws -> Result
    ) async throws -> Result {
        try await connectionSetupBudget.withTimeout(operation)
    }

    static func makeConnection(
        configuration: SSHClientConfiguration,
        endpoint: SSHSocketEndpoint,
        transportHandle: SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)? = nil,
        failedSetupDependentCloseOperation: (@Sendable () async -> Void)? = nil,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic,
        logHandler: SSHClientLogHandler,
        setupCleanup: ConnectionSetupCleanup? = nil,
        connectionSetupBudget: SSHConnectionSetupTimeoutBudget? = nil
    ) async throws -> SSHConnection {
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
            automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy(
                configuration.automaticRekeyPolicy
            ),
            keepalivePolicy: SSHTransportKeepalivePolicy(
                configuration.keepalivePolicy,
                defaultResponseTimeoutNanoseconds: timeoutPolicy.responseTimeoutNanoseconds
            ),
            responseTimeoutNanoseconds: timeoutPolicy.responseTimeoutNanoseconds
        )
        let client = SSHTransportProtocolClient(
            transport: transportHandle.transport,
            transportConfiguration: transportConfiguration
        )
        let transportObservationBuffer = SSHConnectionTransportObservationBuffer()
        // Transport observation events must reach the state coordinator IN ORDER:
        // its liveness/terminal logic treats previous→current transitions as
        // ordered (a reordered viability flip can wedge `.degraded`; a reordered
        // `.failed` can misreport the terminal snapshot). Spawning an independent
        // `Task` per event gives no cross-task ordering guarantee, so instead we
        // funnel events through a single FIFO async stream. `yield` is synchronous
        // and non-blocking (the observation callback never blocks the transport),
        // and a single forwarding task drains the stream serially into the buffer,
        // preserving emission order end-to-end. The stream terminates when the
        // transport releases the handler closure on `setObservationHandler(nil)`.
        let (observationEvents, observationContinuation) = AsyncStream.makeStream(
            of: SSHTransportObservationEvent.self,
            bufferingPolicy: .unbounded
        )
        await transportHandle.transport.setObservationHandler { event in
            observationContinuation.yield(event)
        }
        // Fire-and-forget: the loop ends when the stream finishes, which happens
        // once the transport releases the handler closure (on close/abort via
        // `setObservationHandler(nil)`) and this function's local continuation
        // reference is dropped on return/throw. No orphan task lingers.
        Task {
            for await event in observationEvents {
                await transportObservationBuffer.record(event)
            }
        }
        do {
            let hostKeyTrustPolicy = try configuration.hostKeyPolicy.resolveTrustPolicy(
                for: endpoint
            )
            let versionExchange = try await self.withConnectionSetupTimeout(
                connectionSetupBudget
            ) {
                try await client.exchangeIdentifications()
            }
            let negotiation = try await self.withConnectionSetupTimeout(
                connectionSetupBudget
            ) {
                try await client.exchangeKeyExchangeInit()
            }
            let keyExchangeResult = try await self.withConnectionSetupTimeout(
                connectionSetupBudget
            ) {
                try await client.beginCurve25519KeyExchange(negotiation: negotiation)
            }
            let hostKeyTrustEvaluation = try await client.evaluateCurve25519HostKeyTrust(
                negotiation: negotiation,
                keyExchangeResult: keyExchangeResult,
                remoteEndpoint: endpoint,
                hostKeyTrustPolicy: hostKeyTrustPolicy,
                hostKeyTrustTimeoutNanoseconds: timeoutPolicy.hostKeyTrustTimeoutNanoseconds
            )
            let activation = try await self.withConnectionSetupTimeout(
                connectionSetupBudget
            ) {
                try await client.activateTrustedCurve25519Transport(
                    evaluation: hostKeyTrustEvaluation,
                    remoteEndpoint: endpoint,
                    hostKeyTrustPolicy: hostKeyTrustPolicy
                )
            }

            let authenticationBanners = try await self.withConnectionSetupTimeout(
                connectionSetupBudget
            ) {
                try await self.authenticateAny(
                    configuration.authenticationMethods,
                    username: configuration.username,
                    client: client,
                    endpoint: endpoint,
                    legacyAlgorithmOptions: configuration.legacyAlgorithmOptions,
                    logHandler: logHandler
                )
            }

            let metadata = SSHConnectionMetadata(
                endpointHost: endpoint.host,
                endpointPort: endpoint.port,
                username: configuration.username,
                clientIdentification: versionExchange.clientIdentification.rawValue,
                remoteIdentification: versionExchange.remoteIdentification.rawValue,
                preIdentificationLines: versionExchange.preIdentificationLines,
                authenticationBanners: authenticationBanners,
                hostKeyAlgorithm: activation.verifiedHostKey.algorithmName,
                hostKeyFingerprintSHA256: SSHTrustedHostKey(
                    verifiedHostKey: activation.verifiedHostKey
                ).fingerprintSHA256,
                hostKeyTrustMethod: activation.hostKeyTrust.method
            )
            let lifetime = SSHConnectionLifetime(closeOperation: { [client] in
                await self.closeTransportResources(
                    client: client,
                    transportHandle: transportHandle,
                    dependentCloseOperation: dependentCloseOperation,
                    gracefulCloseTimeoutNanoseconds: self.gracefulCloseTimeoutNanoseconds(
                        responseTimeoutNanoseconds: timeoutPolicy.responseTimeoutNanoseconds
                    ),
                    logHandler: logHandler
                )
            }, abortOperation: {
                await self.abortTransportResources(
                    client: client,
                    transportHandle: transportHandle,
                    dependentCloseOperation: dependentCloseOperation
                )
            })
            let stateCoordinator = SSHConnectionStateCoordinator(
                client: client,
                logHandler: logHandler
            )
            if let initialNetworkPath = await transportHandle.transport.currentNetworkPath() {
                await stateCoordinator.recordInitialTransportNetworkPath(initialNetworkPath)
            }
            await transportObservationBuffer.attach { [weak lifetime, weak stateCoordinator] event in
                guard let stateCoordinator else {
                    return
                }

                let shouldCloseLifetime = await stateCoordinator.recordTransportObservation(event)
                if shouldCloseLifetime {
                    await lifetime?.close()
                }
            }
            await client.setBackgroundFailureHandler { [weak lifetime, weak stateCoordinator] error in
                await stateCoordinator?.recordBackgroundFailure(error)
                await lifetime?.close()
            }
            let connection = SSHConnection(
                metadata: metadata,
                client: client,
                lifetime: lifetime,
                stateCoordinator: stateCoordinator,
                stateEvents: stateCoordinator.stateEvents,
                logHandler: logHandler,
                transportBackendPreference: transportBackendPreference
            )
            logHandler.logConnectionEstablished(metadata)
            await setupCleanup?.release()
            return connection
        } catch let error as SSHClientError {
            await self.closeFailedConnectionSetupResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation,
                setupCleanup: setupCleanup,
                timeoutPolicy: timeoutPolicy
            )
            throw error
        } catch let error as SSHHostKeyPolicyError {
            await self.closeFailedConnectionSetupResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation,
                setupCleanup: setupCleanup,
                timeoutPolicy: timeoutPolicy
            )
            throw error
        } catch let error as SSHAuthenticationMethodError {
            await self.closeFailedConnectionSetupResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation,
                setupCleanup: setupCleanup,
                timeoutPolicy: timeoutPolicy
            )
            throw error
        } catch let error as CancellationError {
            await self.closeFailedConnectionSetupResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation,
                setupCleanup: setupCleanup,
                timeoutPolicy: timeoutPolicy
            )
            throw error
        } catch {
            let snapshot = await client.diagnosticsSnapshot()
            await self.closeFailedConnectionSetupResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation,
                setupCleanup: setupCleanup,
                timeoutPolicy: timeoutPolicy
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

    private static func closeFailedConnectionSetupResources(
        client _: SSHTransportProtocolClient,
        transportHandle: SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)? = nil,
        setupCleanup: ConnectionSetupCleanup? = nil,
        timeoutPolicy _: SSHInternalTimeoutPolicy
    ) async {
        if let setupCleanup {
            guard let claimedTransportHandle = await setupCleanup.claimClose() else {
                return
            }
            await claimedTransportHandle.abort()
            await dependentCloseOperation?()
            return
        }

        await transportHandle.abort()
        await dependentCloseOperation?()
    }

    private static func connectViaProxyJump(
        configuration: SSHClientConfiguration,
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
        ,
        connectionTransportBackendPreference: SSHTCPTransportBackendPreference = .automatic
    ) async throws -> SSHConnection {
        let routePlan = SSHRoutePlan(configuration: configuration)
        let routeGraph = SSHRouteLifecycleGraph(plan: routePlan)
        let finalEndpoint = routePlan.finalEndpoint
        let routeLifecycle = SSHRouteLifecycleOwner(graph: routeGraph)
        let rootTransportHandleFactory =
            routeRootTransportHandleFactory ?? transportHandleFactory
        let proxyJumpConnectionCount = routePlan.connectionCount
        logHandler.logProxyJumpSetupStarted(
            finalEndpoint: finalEndpoint,
            username: configuration.username,
            authentication: configuration.authentication,
            connectionCount: proxyJumpConnectionCount
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
                logHandler.logProxyJumpHopStarted(
                    endpoint: endpoint,
                    username: hop.username,
                    authentication: hop.authentication,
                    connectionIndex: hopOrdinal,
                    connectionCount: proxyJumpConnectionCount
                )
                if let upstreamConnection = await routeLifecycle.lastConnection() {
                    logHandler.logProxyJumpChannelOpening(
                        upstreamMetadata: upstreamConnection.metadata,
                        targetEndpoint: endpoint,
                        connectionIndex: hopOrdinal,
                        connectionCount: proxyJumpConnectionCount
                    )
                }

                let upstreamConnection = await routeLifecycle.lastConnection()
                await routeLifecycle.beginAcquiringConnection(edgeID: hopEdgeID)
                let connection = try await self.makeConnectionWithRouteSetupTimeout(
                    configuration: hopConfiguration,
                    endpoint: endpoint,
                    transportHandleFactory: {
                        if let upstreamConnection {
                            try await jumpTransportFactory(upstreamConnection, endpoint)
                        } else {
                            try await rootTransportHandleFactory(endpoint)
                        }
                    },
                    transportBackendPreference: connectionTransportBackendPreference,
                    logHandler: logHandler
                )
                await routeLifecycle.registerConnection(connection, edgeID: hopEdgeID)
            }

            if let upstreamConnection = await routeLifecycle.lastConnection() {
                logHandler.logProxyJumpChannelOpening(
                    upstreamMetadata: upstreamConnection.metadata,
                    targetEndpoint: finalEndpoint,
                    connectionIndex: proxyJumpConnectionCount,
                    connectionCount: proxyJumpConnectionCount
                )
            }
            let upstreamConnection = await routeLifecycle.lastConnection()

            logHandler.logProxyJumpTargetStarted(
                endpoint: finalEndpoint,
                username: configuration.username,
                authentication: configuration.authentication,
                connectionIndex: proxyJumpConnectionCount,
                connectionCount: proxyJumpConnectionCount
            )

            await routeLifecycle.beginAcquiringConnection(edgeID: routeGraph.finalSSHEdgeID)
            let finalConnection = try await self.makeConnectionWithRouteSetupTimeout(
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
                transportBackendPreference: connectionTransportBackendPreference,
                logHandler: logHandler
            )
            await routeLifecycle.registerFinalConnectionEstablished()
            return finalConnection
        } catch let error as SSHClientError {
            await routeLifecycle.abort()
            throw error
        } catch {
            await routeLifecycle.abort()
            throw self.wrapEarlyConnectionSetupError(
                error,
                username: configuration.username,
                endpoint: finalEndpoint,
                logHandler: logHandler
            )
        }
    }

    private static func gracefulCloseTimeoutNanoseconds(
        responseTimeoutNanoseconds: UInt64?
    ) -> UInt64 {
        guard let responseTimeoutNanoseconds else {
            return self.defaultGracefulCloseTimeoutNanoseconds
        }

        return max(
            1,
            min(
                responseTimeoutNanoseconds,
                self.defaultGracefulCloseTimeoutNanoseconds
            )
        )
    }

    static func closeTransportResources(
        client: SSHTransportProtocolClient,
        transportHandle: SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)?,
        gracefulCloseTimeoutNanoseconds: UInt64,
        logHandler: SSHClientLogHandler
    ) async {
        await transportHandle.transport.setObservationHandler(nil)
        let hasPendingBackgroundTransportFailure =
            await client.hasPendingBackgroundTransportFailure()
        await client.prepareForTransportLifecycleClose()

        if !hasPendingBackgroundTransportFailure {
            let disconnectTask = Task {
                await client.disconnect()
            }

            let didDisconnectFinish = await self.waitForTaskCompletion(
                disconnectTask,
                upTo: gracefulCloseTimeoutNanoseconds
            )
            if !didDisconnectFinish {
                disconnectTask.cancel()
            }
        }

        // Closing a modern route-root transport waits for its structured scope
        // to drop (there is no cancel/close API on `NetworkConnection<TCP>`). If
        // that scope stalls, an unbounded `transportHandle.close()` would wedge
        // connection teardown, so bound it like the disconnect above. We do not
        // cancel the close task on timeout: cancelling could strand an escaped
        // connection, so we let it drain in the background and proceed.
        let transportCloseTask = Task {
            await transportHandle.close()
        }
        let didTransportCloseFinish = await self.waitForTaskCompletion(
            transportCloseTask,
            upTo: gracefulCloseTimeoutNanoseconds
        )
        if !didTransportCloseFinish {
            logHandler.emit(
                level: .warning,
                category: .transport,
                message: "Timed out closing transport handle; proceeding with teardown.",
                metadata: sshLogMetadata(
                    ("timeoutNanoseconds", String(gracefulCloseTimeoutNanoseconds))
                )
            )
        }

        await dependentCloseOperation?()
    }

    private static func abortTransportResources(
        client: SSHTransportProtocolClient,
        transportHandle: SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)?
    ) async {
        await client.abortTransportLifecycle()
        await transportHandle.abort()
        await dependentCloseOperation?()
    }

    private static func waitForTaskCompletion(
        _ task: Task<Void, Never>,
        upTo nanoseconds: UInt64
    ) async -> Bool {
        await withCheckedContinuation { continuation in
            let gate = TaskCompletionGate(continuation)

            let timeoutTask = Task {
                try? await Task.sleep(nanoseconds: nanoseconds)
                await gate.resume(with: false)
            }

            Task {
                await task.value
                // Cancel the timeout sleeper as soon as the awaited work finishes
                // so it does not linger asleep up to the full timeout on every
                // graceful close.
                timeoutTask.cancel()
                await gate.resume(with: true)
            }
        }
    }

    private static func wrapEarlyConnectionSetupError(
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

        if error is CancellationError {
            return error
        }

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

struct SSHClientTransportHandle: Sendable {
    let transport: any SSHByteStreamTransport
    let closeOperation: (@Sendable () async -> Void)?
    let abortOperation: (@Sendable () async -> Void)?

    init(
        transport: any SSHByteStreamTransport,
        closeOperation: (@Sendable () async -> Void)? = nil,
        abortOperation: (@Sendable () async -> Void)? = nil
    ) {
        self.transport = transport
        self.closeOperation = closeOperation
        self.abortOperation = abortOperation
    }

    func close() async {
        await self.transport.setObservationHandler(nil)
        await self.transport.close()
        await self.closeOperation?()
    }

    func abort() async {
        await self.transport.setObservationHandler(nil)
        await self.transport.abort()
        if let abortOperation {
            await abortOperation()
        } else {
            await self.closeOperation?()
        }
    }
}
