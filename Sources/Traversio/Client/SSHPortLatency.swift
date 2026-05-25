// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Dispatch
import Foundation

/// Errors thrown by SSH-port latency measurement.
public enum SSHPortLatencyError: Error, CustomStringConvertible, Sendable {
    /// Invalid Sample Count.
    case invalidSampleCount(Int)
    /// Invalid Connect Timeout.
    case invalidConnectTimeout(TimeInterval)
    /// Invalid First Server Byte Timeout.
    case invalidFirstServerByteTimeout(TimeInterval)
    /// Invalid Delay Between Samples.
    case invalidDelayBetweenSamples(TimeInterval)
    /// Connection Timed Out.
    case connectionTimedOut(endpointHost: String, endpointPort: UInt16, timeout: TimeInterval)
    /// First Server Byte Timed Out.
    case firstServerByteTimedOut(endpointHost: String, endpointPort: UInt16, timeout: TimeInterval)
    /// No Successful Samples.
    case noSuccessfulSamples(endpointHost: String, endpointPort: UInt16, failureCount: Int)

    /// Description.
    public var description: String {
        switch self {
        case let .invalidSampleCount(sampleCount):
            return "sampleCount must be greater than zero; got \(sampleCount)"
        case let .invalidConnectTimeout(timeout):
            return "connectTimeout must be finite and greater than zero seconds; got \(timeout)"
        case let .invalidFirstServerByteTimeout(timeout):
            return "firstServerByteTimeout must be finite and greater than zero seconds for SSH service request sampling; got \(timeout)"
        case let .invalidDelayBetweenSamples(delay):
            return "delayBetweenSamples must be finite and greater than or equal to zero seconds; got \(delay)"
        case let .connectionTimedOut(endpointHost, endpointPort, timeout):
            return
                "TCP connect to \(endpointHost):\(endpointPort) timed out after \(formattedLatencyInterval(timeout))."
        case let .firstServerByteTimedOut(endpointHost, endpointPort, timeout):
            return
                "Timed out waiting for SSH service accept from \(endpointHost):\(endpointPort) after \(formattedLatencyInterval(timeout))."
        case let .noSuccessfulSamples(endpointHost, endpointPort, failureCount):
            return
                "No successful SSH-port latency samples for \(endpointHost):\(endpointPort); failures recorded: \(failureCount)."
        }
    }
}

/// Options for `SSHClient.measurePortLatency(...)`.
public struct SSHPortLatencyOptions: Codable, Equatable, Sendable {
    /// Default Sample Count.
    public static let defaultSampleCount = 10
    /// Default Connect Timeout.
    public static let defaultConnectTimeout: TimeInterval = 3
    /// Default First Server Byte Timeout.
    public static let defaultFirstServerByteTimeout: TimeInterval = 3
    /// Default Delay Between Samples.
    public static let defaultDelayBetweenSamples: TimeInterval = 0.25
/// Sample count.

    /// Sample Count.
    public let sampleCount: Int
    /// Connect Timeout.
    public let connectTimeout: TimeInterval
    /// First Server Byte Timeout.
    public let firstServerByteTimeout: TimeInterval
    /// Delay Between Samples.
    public let delayBetweenSamples: TimeInterval

    /// SSH Service Request Timeout.
    public var sshServiceRequestTimeout: TimeInterval {
        self.firstServerByteTimeout
    }
    /// Creates an SSHPortLatencyOptions.

    public init(
        sampleCount: Int = Self.defaultSampleCount,
        connectTimeout: TimeInterval = Self.defaultConnectTimeout,
        firstServerByteTimeout: TimeInterval = Self.defaultFirstServerByteTimeout,
        delayBetweenSamples: TimeInterval = Self.defaultDelayBetweenSamples
    ) {
        self.sampleCount = sampleCount
        self.connectTimeout = connectTimeout
        self.firstServerByteTimeout = firstServerByteTimeout
        self.delayBetweenSamples = delayBetweenSamples
    }

    /// Validates option values and throws `SSHPortLatencyError` when invalid.
    public func validate() throws {
        guard self.sampleCount > 0 else {
            throw SSHPortLatencyError.invalidSampleCount(self.sampleCount)
        }
        guard Self.isFinitePositive(self.connectTimeout) else {
            throw SSHPortLatencyError.invalidConnectTimeout(self.connectTimeout)
        }
        guard Self.isFinitePositive(self.firstServerByteTimeout) else {
            throw SSHPortLatencyError.invalidFirstServerByteTimeout(
                self.firstServerByteTimeout
            )
        }
        guard Self.isFiniteNonNegative(self.delayBetweenSamples) else {
            throw SSHPortLatencyError.invalidDelayBetweenSamples(
                self.delayBetweenSamples
            )
        }
    }

    private static func isFinitePositive(_ value: TimeInterval) -> Bool {
        value.isFinite && value > 0
    }

    private static func isFiniteNonNegative(_ value: TimeInterval) -> Bool {
        value.isFinite && value >= 0
    }
}

/// One successful SSH-port latency sample.
public struct SSHPortLatencySample: Codable, Equatable, Sendable {
    /// Attempt.
    public let attempt: Int
    /// Connect RTT.
    public let connectRTT: TimeInterval
    /// First Server Byte After Connect.
    public let firstServerByteAfterConnect: TimeInterval
    /// Connect RTT Milliseconds.

    public var connectRTTMilliseconds: Double {
        self.connectRTT * 1_000
    }
    /// First Server Byte After Connect Milliseconds.

    public var firstServerByteAfterConnectMilliseconds: Double {
        self.firstServerByteAfterConnect * 1_000
    }
    /// Estimated Path One Way From First Server Byte.

    public var estimatedPathOneWayFromFirstServerByte: TimeInterval {
        self.firstServerByteAfterConnect / 2
    }
    /// Estimated Path One Way From First Server Byte Milliseconds.

    public var estimatedPathOneWayFromFirstServerByteMilliseconds: Double {
        self.estimatedPathOneWayFromFirstServerByte * 1_000
    }

    /// SSH Service Request RTT.
    public var sshServiceRequestRTT: TimeInterval {
        self.firstServerByteAfterConnect
    }

    /// SSH Service Request RTT Milliseconds.
    public var sshServiceRequestRTTMilliseconds: Double {
        self.sshServiceRequestRTT * 1_000
    }
    /// Estimated Path One Way From SSH Service Request.

    public var estimatedPathOneWayFromSSHServiceRequest: TimeInterval {
        self.sshServiceRequestRTT / 2
    }
    /// Estimated Path One Way From SSH Service Request Milliseconds.

    public var estimatedPathOneWayFromSSHServiceRequestMilliseconds: Double {
        self.estimatedPathOneWayFromSSHServiceRequest * 1_000
    }
}

/// One failed latency-sampling attempt.
public struct SSHPortLatencyFailure: Codable, Equatable, Sendable {
    /// Attempt.
    public let attempt: Int
    /// Diagnostic or server-provided message.
    public let message: String
}

/// Summary statistics for latency samples.
public struct SSHPortLatencyStatistics: Codable, Equatable, Sendable {
    /// Minimum time interval.
    public let minimumTimeInterval: TimeInterval
    /// Average time interval.
    public let averageTimeInterval: TimeInterval
    /// Maximum time interval.
    public let maximumTimeInterval: TimeInterval
    /// Standard Deviation time interval.
    public let standardDeviationTimeInterval: TimeInterval
    /// Minimum Milliseconds.

    public var minimumMilliseconds: Double {
        self.minimumTimeInterval * 1_000
    }
    /// Average Milliseconds.

    public var averageMilliseconds: Double {
        self.averageTimeInterval * 1_000
    }
    /// Maximum Milliseconds.

    public var maximumMilliseconds: Double {
        self.maximumTimeInterval * 1_000
    }
    /// Standard Deviation Milliseconds.

    public var standardDeviationMilliseconds: Double {
        self.standardDeviationTimeInterval * 1_000
    }
}

/// Result returned by `SSHClient.measurePortLatency(...)`.
public struct SSHPortLatencyReport: Codable, Sendable {
    /// Endpoint host name or address.
    public let endpointHost: String
    /// Endpoint port number.
    public let endpointPort: UInt16
    /// Options.
    public let options: SSHPortLatencyOptions
    /// Samples.
    public let samples: [SSHPortLatencySample]
    /// Failures.
    public let failures: [SSHPortLatencyFailure]
    /// Connect RTT Statistics.
    public let connectRTTStatistics: SSHPortLatencyStatistics
    /// First Server Byte After Connect Statistics.
    public let firstServerByteAfterConnectStatistics: SSHPortLatencyStatistics
    /// Estimated Path One Way From First Server Byte Statistics.
    public let estimatedPathOneWayFromFirstServerByteStatistics: SSHPortLatencyStatistics
    /// Requested Sample Count.

    public var requestedSampleCount: Int {
        self.options.sampleCount
    }
    /// Successful Sample Count.

    public var successfulSampleCount: Int {
        self.samples.count
    }
    /// Failed Sample Count.

    public var failedSampleCount: Int {
        self.failures.count
    }

    /// SSH Service Request RTT Statistics.
    public var sshServiceRequestRTTStatistics: SSHPortLatencyStatistics {
        self.firstServerByteAfterConnectStatistics
    }
    /// Estimated Path One Way From SSH Service Request Statistics.

    public var estimatedPathOneWayFromSSHServiceRequestStatistics: SSHPortLatencyStatistics {
        self.estimatedPathOneWayFromFirstServerByteStatistics
    }
}

struct SSHPortLatencyMeasuredSample: Sendable {
    let connectRTTNanoseconds: UInt64
    let sshServiceRequestRTTNanoseconds: UInt64
}

struct SSHPortLatencyRoute: Sendable {
    let connectionProxy: SSHConnectionProxy?
    let proxyJumpHosts: [SSHProxyJumpHost]
    let logHandler: SSHClientLogHandler
    let transportBackendPreference: SSHTCPTransportBackendPreference
    let preferredServerHostKeyAlgorithms: [String]
    let compressionPreference: SSHCompressionPreference

    init(
        connectionProxy: SSHConnectionProxy? = nil,
        proxyJumpHosts: [SSHProxyJumpHost] = [],
        logHandler: SSHClientLogHandler = .disabled,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic,
        preferredServerHostKeyAlgorithms: [String] =
            SSHLegacyAlgorithmOptions.disabled.preferredServerHostKeyAlgorithms,
        compressionPreference: SSHCompressionPreference = .disabled
    ) {
        self.connectionProxy = connectionProxy
        self.proxyJumpHosts = proxyJumpHosts
        self.logHandler = logHandler
        self.transportBackendPreference = transportBackendPreference
        self.preferredServerHostKeyAlgorithms = preferredServerHostKeyAlgorithms
        self.compressionPreference = compressionPreference
    }
}

struct SSHPortLatencyRunner: Sendable {
    typealias SampleMeasurer = @Sendable (
        SSHSocketEndpoint,
        UInt64,
        UInt64
    ) async throws -> SSHPortLatencyMeasuredSample
    typealias Sleeper = @Sendable (UInt64) async throws -> Void
    typealias ByteStreamTransportFactory = @Sendable (
        SSHSocketEndpoint
    ) async throws -> any SSHByteStreamTransport
    typealias TransportHandleFactory = @Sendable (
        SSHSocketEndpoint
    ) async throws -> SSHClientTransportHandle
    typealias JumpTransportFactory = @Sendable (
        SSHConnection,
        SSHSocketEndpoint
    ) async throws -> SSHClientTransportHandle

    private let injectedMeasureSample: SampleMeasurer?
    private let sleep: Sleeper
    private let route: SSHPortLatencyRoute
    private let transportHandleFactory: TransportHandleFactory
    private let jumpTransportFactory: JumpTransportFactory

    init(
        measureSample: @escaping SampleMeasurer,
        sleep: @escaping Sleeper
    ) {
        self.injectedMeasureSample = measureSample
        self.sleep = sleep
        self.route = SSHPortLatencyRoute()
        self.transportHandleFactory = { endpoint in
            try await SSHTCPByteStreamTransportFactory.makeRouteRootTransportHandle(to: endpoint)
        }
        self.jumpTransportFactory = SSHClient.makeJumpTransportHandle
    }

    init() {
        self.init(
            route: SSHPortLatencyRoute(),
            sleep: { nanoseconds in
                try await Self.defaultSleep(nanoseconds: nanoseconds)
            }
        )
    }

    init(
        route: SSHPortLatencyRoute,
        sleep: @escaping Sleeper
    ) {
        self.init(
            route: route,
            transportHandleFactory: { endpoint in
                try await SSHTCPByteStreamTransportFactory.makeRouteRootTransportHandle(
                    to: endpoint,
                    preference: route.transportBackendPreference
                )
            },
            jumpTransportFactory: SSHClient.makeJumpTransportHandle,
            sleep: sleep
        )
    }

    init(
        route: SSHPortLatencyRoute,
        transportFactory: @escaping ByteStreamTransportFactory,
        jumpTransportFactory: @escaping JumpTransportFactory = SSHClient.makeJumpTransportHandle,
        sleep: @escaping Sleeper
    ) {
        self.init(
            route: route,
            transportHandleFactory: { endpoint in
                SSHClientTransportHandle(transport: try await transportFactory(endpoint))
            },
            jumpTransportFactory: jumpTransportFactory,
            sleep: sleep
        )
    }

    init(
        route: SSHPortLatencyRoute,
        transportHandleFactory: @escaping TransportHandleFactory,
        jumpTransportFactory: @escaping JumpTransportFactory = SSHClient.makeJumpTransportHandle,
        sleep: @escaping Sleeper
    ) {
        self.injectedMeasureSample = nil
        self.sleep = sleep
        self.route = route
        self.transportHandleFactory = transportHandleFactory
        self.jumpTransportFactory = jumpTransportFactory
    }

    func run(
        to endpoint: SSHSocketEndpoint,
        options: SSHPortLatencyOptions
    ) async throws -> SSHPortLatencyReport {
        try options.validate()
        return try await self.run(
            to: endpoint,
            sampleCount: options.sampleCount,
            connectTimeoutNanoseconds: Self.nanoseconds(from: options.connectTimeout),
            firstServerByteTimeoutNanoseconds: Self.nanoseconds(from: options.firstServerByteTimeout),
            delayBetweenSamplesNanoseconds: Self.nanoseconds(from: options.delayBetweenSamples)
        )
    }

    func run(
        to endpoint: SSHSocketEndpoint,
        sampleCount: Int,
        connectTimeoutNanoseconds: UInt64,
        firstServerByteTimeoutNanoseconds: UInt64,
        delayBetweenSamplesNanoseconds: UInt64
    ) async throws -> SSHPortLatencyReport {
        guard sampleCount > 0 else {
            throw SSHPortLatencyError.invalidSampleCount(sampleCount)
        }

        let connectTimeout = Self.timeInterval(from: connectTimeoutNanoseconds)
        guard connectTimeout > 0, connectTimeout.isFinite else {
            throw SSHPortLatencyError.invalidConnectTimeout(connectTimeout)
        }

        let firstServerByteTimeout = Self.timeInterval(from: firstServerByteTimeoutNanoseconds)
        guard firstServerByteTimeout > 0, firstServerByteTimeout.isFinite else {
            throw SSHPortLatencyError.invalidFirstServerByteTimeout(firstServerByteTimeout)
        }

        let delayBetweenSamples = Self.timeInterval(from: delayBetweenSamplesNanoseconds)
        guard delayBetweenSamples >= 0, delayBetweenSamples.isFinite else {
            throw SSHPortLatencyError.invalidDelayBetweenSamples(delayBetweenSamples)
        }

        let options = SSHPortLatencyOptions(
            sampleCount: sampleCount,
            connectTimeout: connectTimeout,
            firstServerByteTimeout: firstServerByteTimeout,
            delayBetweenSamples: delayBetweenSamples
        )
        let proxyJumpContext: SSHPortLatencyProxyJumpContext?
        if self.route.proxyJumpHosts.isEmpty {
            proxyJumpContext = nil
        } else {
            proxyJumpContext = try await Self.makeProxyJumpContext(
                to: endpoint,
                route: self.route,
                transportHandleFactory: self.transportHandleFactory,
                jumpTransportFactory: self.jumpTransportFactory
            )
        }

        do {
            var samples: [SSHPortLatencySample] = []
            samples.reserveCapacity(sampleCount)
            var failures: [SSHPortLatencyFailure] = []

            for attempt in 1...sampleCount {
                do {
                    let measuredSample: SSHPortLatencyMeasuredSample
                    if let injectedMeasureSample {
                        measuredSample = try await injectedMeasureSample(
                            endpoint,
                            connectTimeoutNanoseconds,
                            firstServerByteTimeoutNanoseconds
                        )
                    } else if let proxyJumpContext {
                        measuredSample = try await Self.sshServiceRequestSample(
                            to: endpoint,
                            route: self.route,
                            connectTimeoutNanoseconds: connectTimeoutNanoseconds,
                            firstServerByteTimeoutNanoseconds: firstServerByteTimeoutNanoseconds,
                            openTransportHandle: {
                                try await proxyJumpContext.openFinalTransportHandle()
                            }
                        )
                    } else {
                        let route = self.route
                        let transportHandleFactory = self.transportHandleFactory
                        measuredSample = try await Self.sshServiceRequestSample(
                            to: endpoint,
                            route: route,
                            connectTimeoutNanoseconds: connectTimeoutNanoseconds,
                            firstServerByteTimeoutNanoseconds: firstServerByteTimeoutNanoseconds,
                            openTransportHandle: {
                                try await SSHConnectionProxyTransport.makeTransportHandle(
                                    to: endpoint,
                                    proxy: route.connectionProxy,
                                    transportHandleFactory: transportHandleFactory
                                )
                            }
                        )
                    }
                    samples.append(
                        SSHPortLatencySample(
                            attempt: attempt,
                            connectRTT: Self.timeInterval(from: measuredSample.connectRTTNanoseconds),
                            firstServerByteAfterConnect: Self.timeInterval(
                                from: measuredSample.sshServiceRequestRTTNanoseconds
                            )
                        )
                    )
                } catch {
                    failures.append(
                        SSHPortLatencyFailure(
                            attempt: attempt,
                            message: String(describing: error)
                        )
                    )
                }

                if attempt < sampleCount, delayBetweenSamplesNanoseconds > 0 {
                    try await self.sleep(delayBetweenSamplesNanoseconds)
                }
            }

            guard !samples.isEmpty else {
                throw SSHPortLatencyError.noSuccessfulSamples(
                    endpointHost: endpoint.host,
                    endpointPort: endpoint.port,
                    failureCount: failures.count
                )
            }

            let connectRTTStatistics = Self.makeStatistics(
                from: samples.map(\.connectRTT)
            )
            let firstServerByteAfterConnectStatistics = Self.makeStatistics(
                from: samples.map(\.firstServerByteAfterConnect)
            )
            let estimatedPathOneWayFromFirstServerByteStatistics = Self.makeStatistics(
                from: samples.map(\.estimatedPathOneWayFromFirstServerByte)
            )

            let report = SSHPortLatencyReport(
                endpointHost: endpoint.host,
                endpointPort: endpoint.port,
                options: options,
                samples: samples,
                failures: failures,
                connectRTTStatistics: connectRTTStatistics,
                firstServerByteAfterConnectStatistics: firstServerByteAfterConnectStatistics,
                estimatedPathOneWayFromFirstServerByteStatistics: estimatedPathOneWayFromFirstServerByteStatistics
            )
            if let proxyJumpContext {
                await proxyJumpContext.close()
            }
            return report
        } catch {
            if let proxyJumpContext {
                await proxyJumpContext.close()
            }
            throw error
        }
    }

    private static func nanoseconds(from timeInterval: TimeInterval) -> UInt64 {
        let nanoseconds = timeInterval * 1_000_000_000
        if nanoseconds >= Double(UInt64.max) {
            return UInt64.max
        }

        if nanoseconds <= 0 {
            return 0
        }

        return UInt64(nanoseconds.rounded(.up))
    }

    private static func timeInterval(from nanoseconds: UInt64) -> TimeInterval {
        TimeInterval(nanoseconds) / 1_000_000_000
    }

    private static func sshServiceRequestSample(
        to endpoint: SSHSocketEndpoint,
        route: SSHPortLatencyRoute,
        connectTimeoutNanoseconds: UInt64,
        firstServerByteTimeoutNanoseconds: UInt64,
        openTransportHandle: @escaping @Sendable () async throws -> SSHClientTransportHandle
    ) async throws -> SSHPortLatencyMeasuredSample {
        let connectStartNanoseconds = DispatchTime.now().uptimeNanoseconds
        let handle = try await Self.withPortLatencyTimeout(
            timeoutNanoseconds: connectTimeoutNanoseconds,
            timeoutError: SSHPortLatencyError.connectionTimedOut(
                endpointHost: endpoint.host,
                endpointPort: endpoint.port,
                timeout: Self.timeInterval(from: connectTimeoutNanoseconds)
            )
        ) {
            try await openTransportHandle()
        }
        let connectRTTNanoseconds = DispatchTime.now().uptimeNanoseconds - connectStartNanoseconds

        do {
            let sshServiceRequestRTTNanoseconds = try await Self.measureSSHServiceRequestRTT(
                from: handle.transport,
                endpoint: endpoint,
                route: route,
                timeoutNanoseconds: firstServerByteTimeoutNanoseconds
            )
            await handle.close()
            return SSHPortLatencyMeasuredSample(
                connectRTTNanoseconds: connectRTTNanoseconds,
                sshServiceRequestRTTNanoseconds: sshServiceRequestRTTNanoseconds
            )
        } catch {
            await handle.close()
            throw error
        }
    }

    private static func makeProxyJumpContext(
        to endpoint: SSHSocketEndpoint,
        route: SSHPortLatencyRoute,
        transportHandleFactory: @escaping TransportHandleFactory,
        jumpTransportFactory: @escaping JumpTransportFactory
    ) async throws -> SSHPortLatencyProxyJumpContext {
        let routePlan = SSHRoutePlan(
            finalEndpoint: endpoint,
            connectionProxy: route.connectionProxy,
            proxyJumpHosts: route.proxyJumpHosts
        )
        let routeGraph = SSHRouteLifecycleGraph(plan: routePlan)
        let routeLifecycle = SSHRouteLifecycleOwner(graph: routeGraph)

        do {
            for (hopIndex, hop) in route.proxyJumpHosts.enumerated() {
                let hopOrdinal = hopIndex + 1
                guard let hopEdgeID = routeGraph.sshHopEdgeID(ordinal: hopOrdinal) else {
                    preconditionFailure("Missing ProxyJump hop edge \(hopOrdinal)")
                }
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

                let connection: SSHConnection
                if let upstreamConnection = await routeLifecycle.lastConnection() {
                    await routeLifecycle.beginAcquiringConnection(edgeID: hopEdgeID)
                    connection = try await SSHClient.connect(
                        configuration: hopConfiguration,
                        logHandler: route.logHandler,
                        transportHandleFactory: { endpoint in
                            try await jumpTransportFactory(upstreamConnection, endpoint)
                        },
                        jumpTransportFactory: jumpTransportFactory,
                        connectionTransportBackendPreference: route.transportBackendPreference
                    )
                } else {
                    await routeLifecycle.beginAcquiringConnection(edgeID: hopEdgeID)
                    connection = try await SSHClient.connect(
                        configuration: hopConfiguration,
                        logHandler: route.logHandler,
                        transportHandleFactory: { endpoint in
                            try await SSHConnectionProxyTransport.makeTransportHandle(
                                to: endpoint,
                                proxy: route.connectionProxy,
                                transportHandleFactory: transportHandleFactory
                            )
                        },
                        jumpTransportFactory: jumpTransportFactory,
                        connectionTransportBackendPreference: route.transportBackendPreference
                    )
                }
                await routeLifecycle.registerConnection(connection, edgeID: hopEdgeID)
            }

            guard let upstreamConnection = await routeLifecycle.lastConnection() else {
                throw TCPConnectionAttemptFailure(
                    "ProxyJump latency route requires at least one jump host."
                )
            }

            return SSHPortLatencyProxyJumpContext(
                finalEndpoint: endpoint,
                upstreamConnection: upstreamConnection,
                routeLifecycle: routeLifecycle,
                routeGraph: routeGraph,
                jumpTransportFactory: jumpTransportFactory
            )
        } catch {
            await routeLifecycle.abort()
            throw error
        }
    }

    private static func withPortLatencyTimeout<Result: Sendable>(
        timeoutNanoseconds: UInt64,
        timeoutError: @autoclosure @escaping @Sendable () -> SSHPortLatencyError,
        onTimeout: @escaping @Sendable () async -> Void = {},
        _ operation: @escaping @Sendable () async throws -> Result
    ) async throws -> Result {
        try await withThrowingTaskGroup(of: Result.self) { group in
            group.addTask {
                try await operation()
            }
            group.addTask {
                try await Task.sleep(nanoseconds: timeoutNanoseconds)
                await onTimeout()
                throw timeoutError()
            }

            defer {
                group.cancelAll()
            }

            guard let result = try await group.next() else {
                throw timeoutError()
            }
            return result
        }
    }

    private static func defaultSleep(nanoseconds: UInt64) async throws {
        try await Task.sleep(nanoseconds: nanoseconds)
    }

    private static func makeStatistics(from samples: [TimeInterval]) -> SSHPortLatencyStatistics {
        precondition(!samples.isEmpty, "statistics require at least one sample")

        let minimumTimeInterval = samples.min() ?? 0
        let maximumTimeInterval = samples.max() ?? 0
        let averageTimeInterval = samples.reduce(0, +) / Double(samples.count)
        let variance = samples.reduce(0) { partialResult, sample in
            let delta = sample - averageTimeInterval
            return partialResult + (delta * delta)
        } / Double(samples.count)

        return SSHPortLatencyStatistics(
            minimumTimeInterval: minimumTimeInterval,
            averageTimeInterval: averageTimeInterval,
            maximumTimeInterval: maximumTimeInterval,
            standardDeviationTimeInterval: variance.squareRoot()
        )
    }

    private static func measureSSHServiceRequestRTT(
        from transport: any SSHByteStreamTransport,
        endpoint: SSHSocketEndpoint,
        route: SSHPortLatencyRoute,
        timeoutNanoseconds: UInt64
    ) async throws -> UInt64 {
        return try await Self.withPortLatencyTimeout(
            timeoutNanoseconds: timeoutNanoseconds,
            timeoutError: SSHPortLatencyError.firstServerByteTimedOut(
                endpointHost: endpoint.host,
                endpointPort: endpoint.port,
                timeout: Self.timeInterval(from: timeoutNanoseconds)
            ),
            onTimeout: {
                await transport.close()
            }
        ) {
            let client = SSHTransportProtocolClient(
                transport: transport,
                preferredServerHostKeyAlgorithms: route.preferredServerHostKeyAlgorithms,
                compressionPreference: route.compressionPreference
            )
            _ = try await client.exchangeIdentifications()
            _ = try await client.completeCurve25519KeyExchange(
                remoteEndpoint: endpoint,
                hostKeyTrustPolicy: .acceptAnyVerifiedHostKey
            )

            let serviceRequestStartNanoseconds = DispatchTime.now().uptimeNanoseconds
            let serviceAccept = try await client.requestService("ssh-userauth")
            guard serviceAccept.serviceName == "ssh-userauth" else {
                throw TCPConnectionAttemptFailure(
                    "expected ssh-userauth service accept from \(endpoint.host):\(endpoint.port); received \(serviceAccept.serviceName)"
                )
            }
            let rtt = DispatchTime.now().uptimeNanoseconds - serviceRequestStartNanoseconds
            await client.disconnect(description: "SSH port latency sample complete")
            return rtt
        }
    }
}

private struct SSHPortLatencyProxyJumpContext: Sendable {
    let finalEndpoint: SSHSocketEndpoint
    let upstreamConnection: SSHConnection
    let routeLifecycle: SSHRouteLifecycleOwner
    let routeGraph: SSHRouteLifecycleGraph
    let jumpTransportFactory: SSHPortLatencyRunner.JumpTransportFactory

    func openFinalTransportHandle() async throws -> SSHClientTransportHandle {
        await self.routeLifecycle.beginAcquiringConnection(edgeID: self.routeGraph.finalSSHEdgeID)
        return try await self.jumpTransportFactory(
            self.upstreamConnection,
            self.finalEndpoint
        )
    }

    func close() async {
        await self.routeLifecycle.closeAfterExternalFinalClose()
    }
}

extension SSHClient {
    /// Measures SSH service-request latency for a direct host and port.
    ///
    /// This is a diagnostic helper, not a substitute for normal connection host
    /// trust and authentication. Dashboards that already hold an
    /// `SSHConnection` should prefer `SSHConnection.latency`.
    ///
    /// Example:
    ///
    /// ```swift
    /// let report = try await SSHClient.measurePortLatency(host: "server.example.com")
    /// print(report.sshServiceRequestRTTStatistics.averageMilliseconds)
    /// ```
    public static func measurePortLatency(
        host: String,
        port: UInt16 = 22,
        options: SSHPortLatencyOptions = .init()
    ) async throws -> SSHPortLatencyReport {
        try await self.measurePortLatency(
            host: host,
            port: port,
            connectionProxy: nil,
            proxyJumpHosts: [],
            options: options
        )
    }

    /// Measures SSH service-request latency using route options from a client
    /// configuration.
    public static func measurePortLatency(
        configuration: SSHClientConfiguration,
        options: SSHPortLatencyOptions = .init(),
        logHandler: SSHClientLogHandler = .disabled
    ) async throws -> SSHPortLatencyReport {
        try await SSHPortLatencyRunner(
            route: SSHPortLatencyRoute(
                connectionProxy: configuration.connectionProxy,
                proxyJumpHosts: configuration.proxyJumpHosts,
                logHandler: logHandler,
                preferredServerHostKeyAlgorithms:
                    configuration.legacyAlgorithmOptions.preferredServerHostKeyAlgorithms,
                compressionPreference: configuration.compressionPreference
            ),
            sleep: { nanoseconds in
                try await Task.sleep(nanoseconds: nanoseconds)
            }
        ).run(
            to: SSHSocketEndpoint(host: configuration.host, port: configuration.port),
            options: options
        )
    }

    /// Measures SSH service-request latency through an optional first-hop proxy
    /// and optional ProxyJump route.
    public static func measurePortLatency(
        host: String,
        port: UInt16 = 22,
        connectionProxy: SSHConnectionProxy? = nil,
        proxyJumpHosts: [SSHProxyJumpHost] = [],
        options: SSHPortLatencyOptions = .init(),
        logHandler: SSHClientLogHandler = .disabled
    ) async throws -> SSHPortLatencyReport {
        try await SSHPortLatencyRunner(
            route: SSHPortLatencyRoute(
                connectionProxy: connectionProxy,
                proxyJumpHosts: proxyJumpHosts,
                logHandler: logHandler
            ),
            sleep: { nanoseconds in
                try await Task.sleep(nanoseconds: nanoseconds)
            }
        ).run(
            to: SSHSocketEndpoint(host: host, port: port),
            options: options
        )
    }

    package static func measurePortLatency(
        host: String,
        port: UInt16 = 22,
        connectionProxy: SSHConnectionProxy? = nil,
        proxyJumpHosts: [SSHProxyJumpHost] = [],
        options: SSHPortLatencyOptions = .init(),
        logHandler: SSHClientLogHandler = .disabled,
        transportBackendPreference: SSHTCPTransportBackendPreference
    ) async throws -> SSHPortLatencyReport {
        try await SSHPortLatencyRunner(
            route: SSHPortLatencyRoute(
                connectionProxy: connectionProxy,
                proxyJumpHosts: proxyJumpHosts,
                logHandler: logHandler,
                transportBackendPreference: transportBackendPreference
            ),
            sleep: { nanoseconds in
                try await Task.sleep(nanoseconds: nanoseconds)
            }
        ).run(
            to: SSHSocketEndpoint(host: host, port: port),
            options: options
        )
    }
}

private func formattedLatencyInterval(_ timeInterval: TimeInterval) -> String {
    if timeInterval.rounded() == timeInterval {
        return "\(Int(timeInterval))s"
    }

    var rendered = String(format: "%.3f", timeInterval)
    while rendered.last == "0" {
        rendered.removeLast()
    }
    if rendered.last == "." {
        rendered.removeLast()
    }
    return "\(rendered)s"
}

private struct TCPConnectionAttemptFailure: Error, CustomStringConvertible {
    let description: String

    init(_ description: String) {
        self.description = description
    }
}
