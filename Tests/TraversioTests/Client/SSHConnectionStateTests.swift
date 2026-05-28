// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

@Test
func connectionStateEventsReportNetworkPathChangesAndProbeRecovery() async throws {
    let requestSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .requestSuccess(SSHGlobalRequestSuccessMessage(responseData: []))
    )
    let transport = try makeAuthenticatedConnectionStateFixtureTransport(
        additionalServerPayloads: [requestSuccessPayload]
    )
    let connection = try await makeFixtureConnection(transport: transport)
    let collector = ConnectionStateEventCollector(sequence: connection.stateEvents)

    let connectedEvent = try await nextConnectionStateEvent(from: collector)
    #expect(connectedEvent?.trigger == .connected)
    #expect(connectedEvent?.snapshot.state == .ready)

    await transport.emitPathChanged(
        SSHTransportNetworkPath(
            status: .satisfied,
            availableInterfaces: [.wifi],
            isExpensive: false,
            isConstrained: false,
            supportsIPv4: true,
            supportsIPv6: true
        )
    )

    let pathEvent = try await nextConnectionStateEvent(from: collector)
    #expect(pathEvent?.trigger == .networkPathChanged)
    #expect(pathEvent?.snapshot.state == .ready)
    #expect(pathEvent?.snapshot.networkPath?.status == .satisfied)
    #expect(pathEvent?.snapshot.networkPath?.availableInterfaces == [.wifi])

    let probeEvent = try await nextConnectionStateEvent(from: collector)
    #expect(probeEvent?.trigger == .proactiveLivenessCheckSucceeded)
    #expect(probeEvent?.snapshot.state == .ready)
    #expect(probeEvent?.snapshot.detail == nil)

    await connection.close()
}

@Test
func connectionStateEventsReportLostWhenNetworkTransitionProbeFails() async throws {
    let transport = try makeAuthenticatedConnectionStateFixtureTransport()
    let connection = try await makeFixtureConnection(transport: transport)
    let collector = ConnectionStateEventCollector(sequence: connection.stateEvents)

    _ = try await nextConnectionStateEvent(from: collector)

    await transport.enqueueSendFailure(.EPIPE)
    await transport.emitPathChanged(
        SSHTransportNetworkPath(
            status: .satisfied,
            availableInterfaces: [.wifi],
            isExpensive: false,
            isConstrained: false,
            supportsIPv4: true,
            supportsIPv6: true
        )
    )

    let pathEvent = try await nextConnectionStateEvent(from: collector)
    #expect(pathEvent?.trigger == .networkPathChanged)

    let failureEvent = try await nextConnectionStateEvent(from: collector)
    #expect(failureEvent?.trigger == .backgroundFailure)
    #expect(failureEvent?.snapshot.state == .lost)
    #expect(failureEvent?.snapshot.detail != nil)

    try? await Task.sleep(nanoseconds: 50_000_000)

    do {
        _ = try await connection.openShell()
        Issue.record("Expected lost connection lifetime to reject new session work.")
    } catch let error as SSHClientError {
        #expect(error == .connectionScopeEnded)
    }

    #expect(await !transport.hasObservationHandler())
    #expect(await !connection.hasInstalledBackgroundFailureHandler())
    #expect(try await nextConnectionStateEvent(from: collector) == nil)
}

@Test
func closingConnectionPublishesClosedStateEvent() async throws {
    let transport = try makeAuthenticatedConnectionStateFixtureTransport()
    let connection = try await makeFixtureConnection(transport: transport)
    let collector = ConnectionStateEventCollector(sequence: connection.stateEvents)

    _ = try await nextConnectionStateEvent(from: collector)

    await connection.close()

    let closedEvent = try await nextConnectionStateEvent(from: collector)
    #expect(closedEvent?.trigger == .closed)
    #expect(closedEvent?.snapshot.state == .closed)
    #expect(await collector.next() == nil)
    #expect(await connection.currentState().state == .closed)
}

@Test
func backgroundFailureCloseReleasesConnectionLifecycleReferences() async throws {
    let transport = try makeAuthenticatedConnectionStateFixtureTransport()
    var connection: SSHConnection? = try await makeFixtureConnection(transport: transport)
    let probe = connection!.lifecycleRetainProbe()
    let collector = ConnectionStateEventCollector(sequence: connection!.stateEvents)

    _ = try await nextConnectionStateEvent(from: collector)

    await transport.enqueueSendFailure(.EPIPE)
    await transport.emitPathChanged(
        SSHTransportNetworkPath(
            status: .satisfied,
            availableInterfaces: [.wifi],
            isExpensive: false,
            isConstrained: false,
            supportsIPv4: true,
            supportsIPv6: true
        )
    )

    let pathEvent = try await nextConnectionStateEvent(from: collector)
    #expect(pathEvent?.trigger == .networkPathChanged)

    let lostEvent = try await nextConnectionStateEvent(from: collector)
    #expect(lostEvent?.trigger == .backgroundFailure)
    #expect(try await nextConnectionStateEvent(from: collector) == nil)
    #expect(await !transport.hasObservationHandler())

    let hasHandler = await connection?.hasInstalledBackgroundFailureHandler()
    #expect(hasHandler == false)

    connection = nil

    #expect(await eventuallyReleased { probe.client })
    #expect(await eventuallyReleased { probe.stateCoordinator })
    #expect(await eventuallyReleased { probe.lifetime })
}

@Test
func closingConnectionClearsLifecycleHandlers() async throws {
    let transport = try makeAuthenticatedConnectionStateFixtureTransport()
    let connection = try await makeFixtureConnection(transport: transport)

    #expect(await transport.hasObservationHandler())
    #expect(await connection.hasInstalledBackgroundFailureHandler())

    await connection.close()

    #expect(await !transport.hasObservationHandler())
    #expect(await !connection.hasInstalledBackgroundFailureHandler())
}

@Test
func connectionInstallsTransportObservationBeforeProtocolTraffic() async throws {
    let transport = try makeAuthenticatedConnectionStateFixtureTransport()
    let connection = try await makeFixtureConnection(transport: transport)

    #expect(await transport.sendCountBeforeObservationInstall() == 0)

    await connection.close()
}

@Test
func connectionStateErrorDescriptionUsesLocalizedErrorText() {
    #expect(
        SSHConnectionStateErrorDescription.describe(ConnectionStateLocalizedFailure())
            == "localized failure"
    )
}

@Test
func failedTransportObservationPublishesLostAndEndsConnectionLifetime() async throws {
    let transport = try makeAuthenticatedConnectionStateFixtureTransport()
    let connection = try await makeFixtureConnection(transport: transport)
    let collector = ConnectionStateEventCollector(sequence: connection.stateEvents)

    _ = try await nextConnectionStateEvent(from: collector)

    await transport.emitStateChanged(.failed, detail: "vpn switch reset")

    let failedEvent = try await nextConnectionStateEvent(from: collector)
    #expect(failedEvent?.trigger == .transportStateChanged)
    #expect(failedEvent?.snapshot.state == .degraded)
    #expect(failedEvent?.snapshot.transportState == .failed)

    let lostEvent = try await nextConnectionStateEvent(from: collector)
    #expect(lostEvent?.trigger == .backgroundFailure)
    #expect(lostEvent?.snapshot.state == .lost)
    #expect(lostEvent?.snapshot.detail?.contains("vpn switch reset") == true)

    do {
        _ = try await connection.openShell()
        Issue.record("Expected failed transport observation to end the connection lifetime.")
    } catch let error as SSHClientError {
        #expect(error == .connectionScopeEnded)
    }
}

private actor ConnectionStateObservationFixtureTransport: SSHByteStreamTransport {
    private let base: ConnectionFixtureMockSSHByteStreamTransport
    private var observationHandler: (@Sendable (SSHTransportObservationEvent) -> Void)?
    private var sendsBeforeObservationInstall = 0

    init(base: ConnectionFixtureMockSSHByteStreamTransport) {
        self.base = base
    }

    func send(_ bytes: [UInt8], endOfStream: Bool) async throws {
        if self.observationHandler == nil {
            self.sendsBeforeObservationInstall += 1
        }
        try await self.base.send(bytes, endOfStream: endOfStream)
    }

    func receive(
        atLeast minimum: Int,
        atMost maximum: Int
    ) async throws -> SSHByteStreamChunk {
        try await self.base.receive(atLeast: minimum, atMost: maximum)
    }

    func setObservationHandler(
        _ handler: (@Sendable (SSHTransportObservationEvent) -> Void)?
    ) async {
        self.observationHandler = handler
    }

    func hasObservationHandler() -> Bool {
        self.observationHandler != nil
    }

    func sendCountBeforeObservationInstall() -> Int {
        self.sendsBeforeObservationInstall
    }

    func close() async {
        await self.base.close()
    }

    func enqueueSendFailure(_ code: POSIXErrorCode) async {
        await self.base.enqueueSendFailure(code)
    }

    func emitPathChanged(_ path: SSHTransportNetworkPath) {
        self.observationHandler?(.networkPathChanged(path))
    }

    func emitStateChanged(_ state: SSHTransportObservedState, detail: String?) {
        self.observationHandler?(.stateChanged(state: state, detail: detail))
    }
}

private struct ConnectionStateLocalizedFailure: LocalizedError, Sendable {
    var errorDescription: String? {
        "localized failure"
    }
}

private actor ConnectionStateEventCollector {
    private var bufferedEvents: [SSHConnectionStateEvent] = []
    private var waiters: [CheckedContinuation<SSHConnectionStateEvent?, Never>] = []
    private var didFinish = false

    init(sequence: SSHConnectionStateEventSequence) {
        Task {
            for await event in sequence {
                await self.record(event)
            }
            await self.finish()
        }
    }

    func next() async -> SSHConnectionStateEvent? {
        if !self.bufferedEvents.isEmpty {
            return self.bufferedEvents.removeFirst()
        }

        if self.didFinish {
            return nil
        }

        return await withCheckedContinuation { continuation in
            self.waiters.append(continuation)
        }
    }

    private func record(_ event: SSHConnectionStateEvent) {
        if !self.waiters.isEmpty {
            let continuation = self.waiters.removeFirst()
            continuation.resume(returning: event)
            return
        }

        self.bufferedEvents.append(event)
    }

    private func finish() {
        self.didFinish = true
        let waiters = self.waiters
        self.waiters.removeAll(keepingCapacity: false)
        for continuation in waiters {
            continuation.resume(returning: nil)
        }
    }
}

private func nextConnectionStateEvent(
    from collector: ConnectionStateEventCollector,
    timeoutNanoseconds: UInt64 = 1_000_000_000
) async throws -> SSHConnectionStateEvent? {
    try await withOptionalTimeout(
        nanoseconds: timeoutNanoseconds,
        timeoutError: SSHTimeoutError.connectionSetup(
            durationNanoseconds: timeoutNanoseconds
        )
    ) {
        await collector.next()
    }
}

private func eventuallyReleased<Object: AnyObject>(
    _ object: () -> Object?,
    attempts: Int = 20
) async -> Bool {
    for _ in 0..<attempts {
        if object() == nil {
            return true
        }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }

    return object() == nil
}

private func makeFixtureConnection(
    transport: ConnectionStateObservationFixtureTransport
) async throws -> SSHConnection {
    try await SSHClient.connect(
        configuration: SSHClientConfiguration(
            host: "example.com",
            username: "root",
            authentication: .password("s3cr3t"),
            hostKeyPolicy: .acceptAnyVerifiedHostKey
        ),
        logHandler: .disabled,
        transportHandleFactory: { _ in
            SSHClientTransportHandle(transport: transport)
        }
    )
}

private func makeAuthenticatedConnectionStateFixtureTransport(
    additionalServerPayloads: [[UInt8]] = []
) throws -> ConnectionStateObservationFixtureTransport {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let baseTransport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ] + additionalServerPayloads
    )
    return ConnectionStateObservationFixtureTransport(base: baseTransport)
}
