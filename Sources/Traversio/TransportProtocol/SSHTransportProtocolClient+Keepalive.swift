// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

extension SSHTransportProtocolClient {
    static let keepaliveRequestName = "keepalive@openssh.com"
    static let defaultNetworkTransitionProbeTimeoutNanoseconds: UInt64 = 5_000_000_000

    func refreshKeepaliveSchedulingIfNeeded() {
        self.keepaliveTaskHandle?.cancel()
        self.keepaliveTaskHandle = nil

        guard self.authenticatedServiceName != nil,
              self.outboundEncryptedPacketSerializer != nil,
              self.inboundEncryptedPacketParser != nil,
              !self.isTransportRekeyInProgress,
              self.keepaliveInFlightTaskHandle == nil,
              let intervalNanoseconds = self.keepalivePolicy.intervalNanoseconds else {
            return
        }

        self.keepaliveTaskGeneration &+= 1
        let generation = self.keepaliveTaskGeneration
        let client = self
        let task = Task { [weak client] in
            do {
                try await Task.sleep(nanoseconds: intervalNanoseconds)
            } catch {
                return
            }

            guard !Task.isCancelled, let client else {
                return
            }

            await client.handleKeepaliveTimerFired(expectedGeneration: generation)
        }
        self.keepaliveTaskHandle = SSHCancellationHandle(cancelOperation: {
            task.cancel()
        })
    }
    func cancelKeepaliveTask() {
        self.keepaliveTaskHandle?.cancel()
        self.keepaliveInFlightTaskHandle?.cancel()
        self.keepaliveTaskHandle = nil
        self.keepaliveInFlightTaskHandle = nil
        self.keepaliveTaskGeneration &+= 1
    }
    func handleKeepaliveTimerFired(expectedGeneration: UInt64) async {
        guard expectedGeneration == self.keepaliveTaskGeneration else {
            return
        }

        self.keepaliveTaskHandle = nil
        guard let intervalNanoseconds = self.keepalivePolicy.intervalNanoseconds else {
            return
        }

        let client = self
        let task = Task { [weak client] in
            guard let client else {
                return
            }
            await client.performKeepaliveSend(
                expectedGeneration: expectedGeneration,
                intervalNanoseconds: intervalNanoseconds
            )
        }
        self.keepaliveInFlightTaskHandle = SSHCancellationHandle(cancelOperation: {
            task.cancel()
        })
    }
    func performKeepaliveSend(
        expectedGeneration: UInt64,
        intervalNanoseconds: UInt64
    ) async {
        if let idleNanoseconds = self.idleNanosecondsSinceLastProtectedActivity(),
           idleNanoseconds < intervalNanoseconds {
            if expectedGeneration == self.keepaliveTaskGeneration {
                self.keepaliveInFlightTaskHandle = nil
                self.refreshKeepaliveSchedulingIfNeeded()
            }
            return
        }

        do {
            try await self.sendKeepalive(
                responseTimeoutNanoseconds: self.keepalivePolicy.responseTimeoutNanoseconds
            )
            if expectedGeneration == self.keepaliveTaskGeneration {
                self.keepaliveInFlightTaskHandle = nil
                self.refreshKeepaliveSchedulingIfNeeded()
            }
        } catch is CancellationError {
            if expectedGeneration == self.keepaliveTaskGeneration {
                self.keepaliveInFlightTaskHandle = nil
            }
        } catch {
            if expectedGeneration == self.keepaliveTaskGeneration {
                self.keepaliveInFlightTaskHandle = nil
            }
            self.recordPendingBackgroundTransportFailure(error)
        }
    }
    func sendKeepalive(
        responseTimeoutNanoseconds: UInt64?
    ) async throws {
        guard self.authenticatedServiceName != nil,
              self.outboundEncryptedPacketSerializer != nil,
              self.inboundEncryptedPacketParser != nil else {
            return
        }

        let timeoutNanoseconds = responseTimeoutNanoseconds
        let reply = try await self.sendGlobalRequestAndAwaitReplyMessage(
            request: SSHGlobalRequestMessage(
                requestName: Self.keepaliveRequestName,
                wantReply: true,
                requestData: []
            ),
            requestType: "keepalive",
            timeoutNanoseconds: timeoutNanoseconds,
            timeoutError: SSHTimeoutError.keepaliveReply(
                durationNanoseconds: timeoutNanoseconds ?? 1
            )
        )

        switch reply {
        case .requestSuccess, .requestFailure:
            return
        default:
            throw SSHConnectionError.unexpectedConnectionMessage(
                expected: .requestSuccess,
                received: reply.messageID
            )
        }
    }

    func withOutboundGlobalRequestTurn<Result>(
        _ operation: () async throws -> Result
    ) async throws -> Result {
        try await self.acquireOutboundGlobalRequestTurn()
        defer {
            self.releaseOutboundGlobalRequestTurn()
        }

        return try await operation()
    }

    func acquireOutboundGlobalRequestTurn() async throws {
        guard self.isOutboundGlobalRequestInFlight else {
            self.isOutboundGlobalRequestInFlight = true
            return
        }

        switch await self.waitOnOutboundGlobalRequestWaiterQueue() {
        case .ready:
            if Task.isCancelled {
                self.releaseOutboundGlobalRequestTurn()
                throw CancellationError()
            }
        case .cancelled:
            throw CancellationError()
        }
    }

    func releaseOutboundGlobalRequestTurn() {
        if self.resumeNextOutboundGlobalRequestWaiterReady() {
            return
        }

        self.isOutboundGlobalRequestInFlight = false
    }

    func sendGlobalRequestAndAwaitReplyMessage(
        request: SSHGlobalRequestMessage,
        requestType: String,
        timeoutNanoseconds: UInt64? = nil,
        timeoutError: SSHTimeoutError? = nil
    ) async throws -> SSHConnectionMessage {
        try await self.withOutboundGlobalRequestTurn {
            let latencyStartNanoseconds = self.latencyMeasurementStartNanoseconds()
            try await self.sendConnectionMessage(.globalRequest(request))
            let reply = try await self.receiveGlobalRequestReplyMessage(
                requestType: requestType,
                timeoutNanoseconds: timeoutNanoseconds,
                timeoutError: timeoutError
            )
            self.recordLatencyMeasurement(
                startedAt: latencyStartNanoseconds,
                source: request.requestName == Self.keepaliveRequestName ? .keepalive : .globalRequest
            )
            return reply
        }
    }

    func probeTransportLivenessAfterNetworkChange() async throws -> Bool {
        guard self.authenticatedServiceName != nil,
              self.outboundEncryptedPacketSerializer != nil,
              self.inboundEncryptedPacketParser != nil,
              !self.isTransportRekeyInProgress,
              !self.networkTransitionProbeInFlight else {
            return false
        }

        self.networkTransitionProbeInFlight = true
        defer {
            self.networkTransitionProbeInFlight = false
        }

        let timeoutNanoseconds = min(
            self.keepalivePolicy.responseTimeoutNanoseconds
                ?? self.responseTimeoutNanoseconds
                ?? Self.defaultNetworkTransitionProbeTimeoutNanoseconds,
            Self.defaultNetworkTransitionProbeTimeoutNanoseconds
        )

        do {
            try await self.sendKeepalive(
                responseTimeoutNanoseconds: timeoutNanoseconds
            )
            return true
        } catch {
            self.recordPendingBackgroundTransportFailure(error)
            throw error
        }
    }
}
