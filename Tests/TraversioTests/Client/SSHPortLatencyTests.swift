// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func sshPortLatencyRunnerComputesConnectAndFirstServerByteStatistics() async throws {
    let measuredSamples: [SSHPortLatencyMeasuredSample] = [
        .init(connectRTTNanoseconds: 4_000_000, sshServiceRequestRTTNanoseconds: 8_000_000),
        .init(connectRTTNanoseconds: 6_000_000, sshServiceRequestRTTNanoseconds: 10_000_000),
        .init(connectRTTNanoseconds: 10_000_000, sshServiceRequestRTTNanoseconds: 14_000_000),
    ]
    let measurementState = MeasurementState()
    let runner = SSHPortLatencyRunner(
        measureSample: { _, _, _ in
            measuredSamples[await measurementState.nextIndex()]
        },
        sleep: { _ in }
    )

    let report = try await runner.run(
        to: SSHSocketEndpoint(host: "example.com", port: 22),
        sampleCount: measuredSamples.count,
        connectTimeoutNanoseconds: 1_000_000_000,
        firstServerByteTimeoutNanoseconds: 1_000_000_000,
        delayBetweenSamplesNanoseconds: 0
    )

    #expect(report.samples.map(\.connectRTTMilliseconds) == [4, 6, 10])
    #expect(report.samples.map(\.firstServerByteAfterConnectMilliseconds) == [8, 10, 14])
    #expect(report.successfulSampleCount == 3)
    #expect(report.failedSampleCount == 0)
    #expect(report.connectRTTStatistics.minimumMilliseconds == 4)
    #expect(report.connectRTTStatistics.averageMilliseconds == 6.666666666666667)
    #expect(report.connectRTTStatistics.maximumMilliseconds == 10)
    #expect(report.firstServerByteAfterConnectStatistics.minimumMilliseconds == 8)
    #expect(report.firstServerByteAfterConnectStatistics.averageMilliseconds == 10.666666666666666)
    #expect(report.firstServerByteAfterConnectStatistics.maximumMilliseconds == 14)
    #expect(report.estimatedPathOneWayFromFirstServerByteStatistics.minimumMilliseconds == 4)
    #expect(report.estimatedPathOneWayFromFirstServerByteStatistics.averageMilliseconds == 5.333333333333333)
    #expect(report.estimatedPathOneWayFromFirstServerByteStatistics.maximumMilliseconds == 7)
    #expect(report.sshServiceRequestRTTStatistics.averageMilliseconds == 10.666666666666666)
    #expect(report.estimatedPathOneWayFromSSHServiceRequestStatistics.averageMilliseconds == 5.333333333333333)
    #expect(report.samples.map(\.sshServiceRequestRTTMilliseconds) == [8, 10, 14])
    #expect(report.options.sampleCount == 3)
}

@Test
func sshPortLatencyRunnerRecordsFailuresAndContinuesSampling() async throws {
    let outcomes = OutcomeState([
        .success(
            SSHPortLatencyMeasuredSample(
                connectRTTNanoseconds: 5_000_000,
                sshServiceRequestRTTNanoseconds: 8_000_000
            )
        ),
        .failure("connection reset"),
        .success(
            SSHPortLatencyMeasuredSample(
                connectRTTNanoseconds: 9_000_000,
                sshServiceRequestRTTNanoseconds: 12_000_000
            )
        ),
    ])
    var sleepCalls: [UInt64] = []
    let sleepRecorder = SleepRecorder()
    let runner = SSHPortLatencyRunner(
        measureSample: { _, _, _ in
            try await outcomes.next()
        },
        sleep: { nanoseconds in
            await sleepRecorder.record(nanoseconds)
        }
    )

    let report = try await runner.run(
        to: SSHSocketEndpoint(host: "example.com", port: 22),
        sampleCount: 3,
        connectTimeoutNanoseconds: 1_000_000_000,
        firstServerByteTimeoutNanoseconds: 1_000_000_000,
        delayBetweenSamplesNanoseconds: 25_000_000
    )

    sleepCalls = await sleepRecorder.values()
    #expect(report.successfulSampleCount == 2)
    #expect(report.failedSampleCount == 1)
    #expect(report.samples.map { $0.attempt } == [1, 3])
    #expect(report.samples.map(\.firstServerByteAfterConnectMilliseconds) == [8, 12])
    #expect(report.failures.map { $0.attempt } == [2])
    #expect(report.failures[0].message == "connection reset")
    #expect(sleepCalls == [25_000_000, 25_000_000])
}

@Test
func sshPortLatencyRunnerFailsWhenNoSamplesSucceed() async throws {
    let runner = SSHPortLatencyRunner(
        measureSample: { _, _, _ in
            throw DummyError("timed out")
        },
        sleep: { _ in }
    )

    await #expect(throws: SSHPortLatencyError.self) {
        _ = try await runner.run(
            to: SSHSocketEndpoint(host: "example.com", port: 22),
            sampleCount: 2,
            connectTimeoutNanoseconds: 1_000_000_000,
            firstServerByteTimeoutNanoseconds: 1_000_000_000,
            delayBetweenSamplesNanoseconds: 0
        )
    }
}

@Test
func sshPortLatencyRunnerRejectsInvalidSampleCount() async throws {
    let runner = SSHPortLatencyRunner(
        measureSample: { _, _, _ in
            SSHPortLatencyMeasuredSample(
                connectRTTNanoseconds: 1_000_000,
                sshServiceRequestRTTNanoseconds: 2_000_000
            )
        },
        sleep: { _ in }
    )

    await #expect(throws: SSHPortLatencyError.self) {
        _ = try await runner.run(
            to: SSHSocketEndpoint(host: "example.com", port: 22),
            sampleCount: 0,
            connectTimeoutNanoseconds: 1_000_000_000,
            firstServerByteTimeoutNanoseconds: 1_000_000_000,
            delayBetweenSamplesNanoseconds: 0
        )
    }
}

@Test
func sshPortLatencyOptionsValidationThrowsTypedInvalidInputErrors() async throws {
    try expectInvalidPortLatencyOptions(
        SSHPortLatencyOptions(sampleCount: 0),
        expectedDescription: "invalidSampleCount(0)"
    )
    try expectInvalidPortLatencyOptions(
        SSHPortLatencyOptions(connectTimeout: 0),
        expectedDescription: "invalidConnectTimeout(0.0)"
    )
    try expectInvalidPortLatencyOptions(
        SSHPortLatencyOptions(firstServerByteTimeout: -Double.infinity),
        expectedDescription: "invalidFirstServerByteTimeout(-inf)"
    )
    try expectInvalidPortLatencyOptions(
        SSHPortLatencyOptions(delayBetweenSamples: -0.001),
        expectedDescription: "invalidDelayBetweenSamples(-0.001)"
    )
}

@Test
func sshPortLatencyRunnerValidatesOptionsBeforeMeasuring() async throws {
    let runner = SSHPortLatencyRunner(
        measureSample: { _, _, _ in
            Issue.record("Invalid latency options should fail before sampling.")
            return SSHPortLatencyMeasuredSample(
                connectRTTNanoseconds: 1_000_000,
                sshServiceRequestRTTNanoseconds: 2_000_000
            )
        },
        sleep: { _ in
            Issue.record("Invalid latency options should fail before sleeping.")
        }
    )

    do {
        _ = try await runner.run(
            to: SSHSocketEndpoint(host: "example.com", port: 22),
            options: SSHPortLatencyOptions(sampleCount: 0)
        )
        Issue.record("Expected invalid latency options to throw.")
    } catch let error as SSHPortLatencyError {
        #expect(error.diagnosticDescription == "invalidSampleCount(0)")
    } catch {
        Issue.record("Expected SSHPortLatencyError, got \(String(reflecting: error))")
    }
}

@Test
func sshPortLatencyErrorDiagnosticReportUsesStableSupportShape() {
    let report = SSHPortLatencyError.firstServerByteTimedOut(
        endpointHost: "example.com",
        endpointPort: 22,
        timeout: 2
    ).diagnosticReport

    #expect(report.contains("SSH port latency failure"))
    #expect(report.contains("case: firstServerByteTimedOut"))
    #expect(report.contains("endpoint: example.com:22"))
    #expect(report.contains("measurement-stage: ssh-service-request"))
    #expect(report.contains("timeout: 2s"))
    #expect(report.contains("message: Timed out waiting for SSH service accept"))
}

@Test
func sshPortLatencyRunnerMeasuresDirectRouteWithServiceRequestRTT() async throws {
    let finalTransport = try makeLatencyProbeServiceAcceptTransport()
    let runner = SSHPortLatencyRunner(
        route: SSHPortLatencyRoute(),
        transportFactory: { endpoint in
            #expect(endpoint == SSHSocketEndpoint(host: "db.internal", port: 22))
            return finalTransport
        },
        sleep: { _ in }
    )

    let report = try await runner.run(
        to: SSHSocketEndpoint(host: "db.internal", port: 22),
        sampleCount: 1,
        connectTimeoutNanoseconds: 1_000_000_000,
        firstServerByteTimeoutNanoseconds: 1_000_000_000,
        delayBetweenSamplesNanoseconds: 0
    )

    #expect(report.successfulSampleCount == 1)
    #expect(report.failedSampleCount == 0)
    try await expectLatencyProbeServiceRequestAndDisconnect(on: finalTransport)
    #expect(await finalTransport.closeCountObserved() == 1)
}

@Test
func sshPortLatencyRunnerClosesDirectRouteAfterOpenedSampleFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "unexpected-service"))
    )
    let finalTransport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
        ]
    )
    let runner = SSHPortLatencyRunner(
        route: SSHPortLatencyRoute(),
        transportFactory: { _ in finalTransport },
        sleep: { _ in }
    )

    await #expect(throws: SSHPortLatencyError.self) {
        _ = try await runner.run(
            to: SSHSocketEndpoint(host: "db.internal", port: 22),
            sampleCount: 1,
            connectTimeoutNanoseconds: 1_000_000_000,
            firstServerByteTimeoutNanoseconds: 1_000_000_000,
            delayBetweenSamplesNanoseconds: 0
        )
    }
    #expect(await finalTransport.closeCountObserved() == 1)
}

@Test
func sshPortLatencyRunnerMeasuresThroughConnectionProxyRoute() async throws {
    let finalTransport = try makeLatencyProbeServiceAcceptTransport()
    let proxyTransport = ScriptedProxyHandshakeTransport(
        proxyResponsesBySend: [
            [0x05, 0x00],
            [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        ],
        sshTransport: finalTransport
    )
    let runner = SSHPortLatencyRunner(
        route: SSHPortLatencyRoute(
            connectionProxy: .socks5(
                SSHSOCKS5ConnectionProxy(host: "proxy.example.com")
            )
        ),
        transportFactory: { endpoint in
            #expect(endpoint == SSHSocketEndpoint(host: "proxy.example.com", port: 1080))
            return proxyTransport
        },
        sleep: { _ in }
    )

    let report = try await runner.run(
        to: SSHSocketEndpoint(host: "db.internal", port: 22),
        sampleCount: 1,
        connectTimeoutNanoseconds: 1_000_000_000,
        firstServerByteTimeoutNanoseconds: 1_000_000_000,
        delayBetweenSamplesNanoseconds: 0
    )

    #expect(report.successfulSampleCount == 1)
    #expect(report.failedSampleCount == 0)

    let proxySentPayloads = await proxyTransport.recordedSentPayloads()
    #expect(proxySentPayloads[0] == [0x05, 0x01, 0x00])
    #expect(
        proxySentPayloads[1]
            == [0x05, 0x01, 0x00, 0x03, 11]
            + Array("db.internal".utf8)
            + [0x00, 0x16]
    )

    try await expectLatencyProbeServiceRequestAndDisconnect(on: finalTransport)
    #expect(await proxyTransport.closeCountObserved() == 1)
    #expect(await finalTransport.closeCountObserved() == 1)
}

@Test
func sshPortLatencyRunnerMeasuresProxyJumpFinalEndpointThroughReusableJumpConnection() async throws {
    let jumpTransport = try makeAuthenticatedLatencyJumpTransport()
    let finalTransports = try LatencyProbeTransportQueue([
        makeLatencyProbeServiceAcceptTransport(),
        makeLatencyProbeServiceAcceptTransport(),
    ])
    let recorder = ProxyJumpLatencyRecorder()
    let runner = SSHPortLatencyRunner(
        route: SSHPortLatencyRoute(
            proxyJumpHosts: [
                SSHProxyJumpHost(
                    host: "jump.example.com",
                    username: "jump",
                    authentication: .password("secret"),
                    hostKeyPolicy: .acceptAnyVerifiedHostKey
                ),
            ]
        ),
        transportFactory: { endpoint in
            #expect(endpoint == SSHSocketEndpoint(host: "jump.example.com", port: 22))
            return jumpTransport
        },
        jumpTransportFactory: { upstreamConnection, endpoint in
            await recorder.record(endpoint: endpoint, upstreamConnection: upstreamConnection)
            return SSHClientTransportHandle(transport: await finalTransports.popNext())
        },
        sleep: { _ in }
    )

    let report = try await runner.run(
        to: SSHSocketEndpoint(host: "db.internal", port: 22),
        sampleCount: 2,
        connectTimeoutNanoseconds: 1_000_000_000,
        firstServerByteTimeoutNanoseconds: 1_000_000_000,
        delayBetweenSamplesNanoseconds: 0
    )

    #expect(report.successfulSampleCount == 2)
    #expect(
        await recorder.recordedEndpoints()
            == [
                SSHSocketEndpoint(host: "db.internal", port: 22),
                SSHSocketEndpoint(host: "db.internal", port: 22),
            ]
    )
    #expect(await recorder.recordedUpstreamHosts() == ["jump.example.com", "jump.example.com"])
    #expect(await jumpTransport.closeCountObserved() == 1)

    let sampledTransports = await finalTransports.poppedTransports()
    for transport in sampledTransports {
        try await expectLatencyProbeServiceRequestAndDisconnect(on: transport)
        #expect(await transport.closeCountObserved() == 1)
    }
}

private actor MeasurementState {
    private var index = 0

    func nextIndex() -> Int {
        defer { self.index += 1 }
        return self.index
    }
}

private actor OutcomeState {
    enum Outcome {
        case success(SSHPortLatencyMeasuredSample)
        case failure(String)
    }

    private var outcomes: [Outcome]

    init(_ outcomes: [Outcome]) {
        self.outcomes = outcomes
    }

    func next() throws -> SSHPortLatencyMeasuredSample {
        let outcome = self.outcomes.removeFirst()
        switch outcome {
        case let .success(value):
            return value
        case let .failure(message):
            throw DummyError(message)
        }
    }
}

private actor SleepRecorder {
    private var recordedValues: [UInt64] = []

    func record(_ value: UInt64) {
        self.recordedValues.append(value)
    }

    func values() -> [UInt64] {
        self.recordedValues
    }
}

private struct DummyError: Error, CustomStringConvertible {
    let description: String

    init(_ description: String) {
        self.description = description
    }
}

private func expectInvalidPortLatencyOptions(
    _ options: SSHPortLatencyOptions,
    expectedDescription: String
) throws {
    do {
        try options.validate()
        Issue.record("Expected invalid latency options to throw.")
    } catch let error as SSHPortLatencyError {
        #expect(error.diagnosticDescription == expectedDescription)
    } catch {
        Issue.record("Expected SSHPortLatencyError, got \(String(reflecting: error))")
    }
}

private extension SSHPortLatencyError {
    var diagnosticDescription: String {
        switch self {
        case let .invalidSampleCount(sampleCount):
            return "invalidSampleCount(\(sampleCount))"
        case let .invalidConnectTimeout(timeout):
            return "invalidConnectTimeout(\(timeout))"
        case let .invalidFirstServerByteTimeout(timeout):
            return "invalidFirstServerByteTimeout(\(timeout))"
        case let .invalidDelayBetweenSamples(delay):
            return "invalidDelayBetweenSamples(\(delay))"
        case let .connectionTimedOut(endpointHost, endpointPort, timeout):
            return "connectionTimedOut(\(endpointHost):\(endpointPort), \(timeout))"
        case let .firstServerByteTimedOut(endpointHost, endpointPort, timeout):
            return "firstServerByteTimedOut(\(endpointHost):\(endpointPort), \(timeout))"
        case let .noSuccessfulSamples(endpointHost, endpointPort, failureCount):
            return "noSuccessfulSamples(\(endpointHost):\(endpointPort), \(failureCount))"
        }
    }
}

private func expectLatencyProbeServiceRequestAndDisconnect(
    on transport: ConnectionFixtureMockSSHByteStreamTransport
) async throws {
    let sentPayloads = await transport.sentPayloads()
    let decryptionContext = try makeConnectionFixtureClientToServerDecryptionContext(
        sentPayloads: sentPayloads
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: decryptionContext.algorithms,
        keyMaterial: decryptionContext.keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(4).joined()))

    let serviceRequestPacket = try #require(try parser.nextPacket())
    #expect(
        try SSHTransportMessageParser().parse(serviceRequestPacket.payload)
            == .serviceRequest(
                SSHServiceRequestMessage(serviceName: "ssh-userauth")
            )
    )

    let disconnectPacket = try #require(try parser.nextPacket())
    #expect(
        try SSHTransportMessageParser().parse(disconnectPacket.payload)
            == .disconnect(
                SSHDisconnectMessage(
                    reasonCode: .byApplication,
                    description: "SSH port latency sample complete",
                    languageTag: ""
                )
            )
    )
    #expect(try parser.nextPacket() == nil)
}

private func makeLatencyProbeServiceAcceptTransport() throws
    -> ConnectionFixtureMockSSHByteStreamTransport
{
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    return ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
        ]
    )
}

private actor LatencyProbeTransportQueue {
    private var transports: [ConnectionFixtureMockSSHByteStreamTransport]
    private var popped: [ConnectionFixtureMockSSHByteStreamTransport] = []

    init(_ transports: [ConnectionFixtureMockSSHByteStreamTransport]) {
        self.transports = transports
    }

    func popNext() -> ConnectionFixtureMockSSHByteStreamTransport {
        let transport = self.transports.removeFirst()
        self.popped.append(transport)
        return transport
    }

    func poppedTransports() -> [ConnectionFixtureMockSSHByteStreamTransport] {
        self.popped
    }
}

private actor ProxyJumpLatencyRecorder {
    private var endpoints: [SSHSocketEndpoint] = []
    private var upstreamHosts: [String] = []

    func record(endpoint: SSHSocketEndpoint, upstreamConnection: SSHConnection) {
        self.endpoints.append(endpoint)
        self.upstreamHosts.append(upstreamConnection.metadata.endpointHost)
    }

    func recordedEndpoints() -> [SSHSocketEndpoint] {
        self.endpoints
    }

    func recordedUpstreamHosts() -> [String] {
        self.upstreamHosts
    }
}

private func makeAuthenticatedLatencyJumpTransport() throws -> ConnectionFixtureMockSSHByteStreamTransport {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    return ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ]
    )
}
