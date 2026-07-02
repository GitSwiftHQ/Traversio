// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

@Test
func sshBufferedByteStreamTransportForwardsObservationHandlerToWrappedBase() async throws {
    let base = ObservationRecordingBaseTransport(
        networkPath: SSHTransportNetworkPath(
            status: .satisfied,
            availableInterfaces: [.wifi],
            isExpensive: false,
            isConstrained: false,
            supportsIPv4: true,
            supportsIPv6: false
        )
    )
    let buffered = SSHBufferedByteStreamTransport(base: base)

    let observations = ObservationSink()
    await buffered.setObservationHandler { event in
        observations.record(event)
    }

    // An event posted by the wrapped base must reach a handler installed on the
    // wrapper, proving the buffered wrapper forwards observation instead of
    // swallowing it via the no-op default.
    let posted = SSHTransportObservationEvent.viabilityChanged(false)
    await base.postObservation(posted)

    #expect(observations.events() == [posted])

    let path = await buffered.currentNetworkPath()
    #expect(path != nil)
    #expect(path?.status == .satisfied)
    #expect(path?.availableInterfaces == [.wifi])

    // Clearing the handler on the wrapper must also propagate to the base.
    await buffered.setObservationHandler(nil)
    await base.postObservation(.viabilityChanged(true))
    #expect(observations.events() == [posted])
}

private final class ObservationSink: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [SSHTransportObservationEvent] = []

    func record(_ event: SSHTransportObservationEvent) {
        self.lock.lock()
        defer { self.lock.unlock() }
        self.recorded.append(event)
    }

    func events() -> [SSHTransportObservationEvent] {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.recorded
    }
}

private actor ObservationRecordingBaseTransport: SSHByteStreamTransport {
    private let networkPath: SSHTransportNetworkPath?
    private var observationHandler: (@Sendable (SSHTransportObservationEvent) -> Void)?

    init(networkPath: SSHTransportNetworkPath?) {
        self.networkPath = networkPath
    }

    func send(_ bytes: [UInt8], endOfStream: Bool) async throws {}

    func receive(atLeast minimum: Int, atMost maximum: Int) async throws -> SSHByteStreamChunk {
        SSHByteStreamChunk(bytes: [], endOfStream: true)
    }

    func setObservationHandler(
        _ handler: (@Sendable (SSHTransportObservationEvent) -> Void)?
    ) async {
        self.observationHandler = handler
    }

    func currentNetworkPath() async -> SSHTransportNetworkPath? {
        self.networkPath
    }

    func postObservation(_ event: SSHTransportObservationEvent) {
        self.observationHandler?(event)
    }

    func close() async {}

    func abort() async {}
}
