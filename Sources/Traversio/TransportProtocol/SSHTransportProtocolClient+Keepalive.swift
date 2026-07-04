// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

extension SSHTransportProtocolClient {
    static let keepaliveRequestName = "keepalive@openssh.com"
    static let defaultNetworkTransitionProbeTimeoutNanoseconds: UInt64 = 5_000_000_000

    // True on every task spawned as the keepalive timer loop. `withTransportRekeyInProgress`
    // consults it so a rekey initiated from inside the keepalive's own send or reply pump
    // does not cancel the very task that is performing the rekey.
    @TaskLocal static var isRunningOnKeepaliveTimerTask = false

    // Ensures a single long-lived keepalive timer task is running. This is idempotent and cheap:
    // if a timer is already scheduled it returns immediately, so the hot per-packet activity path
    // (`noteProtectedTransportActivity`) no longer cancels and re-spawns a task per packet. The
    // running timer reschedules itself against the stored "last activity" timestamp instead.
    func refreshKeepaliveSchedulingIfNeeded() {
        guard self.authenticatedServiceName != nil,
              self.outboundEncryptedPacketSerializer != nil,
              self.inboundEncryptedPacketParser != nil,
              !self.isTransportRekeyInProgress,
              self.keepalivePolicy.intervalNanoseconds != nil,
              self.keepaliveTaskHandle == nil else {
            return
        }

        self.startKeepaliveTimerTask()
    }

    private func startKeepaliveTimerTask() {
        self.keepaliveTaskGeneration &+= 1
        self.keepaliveTimerScheduleCount &+= 1
        let generation = self.keepaliveTaskGeneration
        let client = self
        let task = Task { [weak client] in
            await Self.$isRunningOnKeepaliveTimerTask.withValue(true) {
                await client?.runKeepaliveTimerLoop(expectedGeneration: generation)
            }
        }
        self.keepaliveTaskHandle = SSHCancellationHandle(cancelOperation: {
            task.cancel()
        })
    }

    // One long-lived loop drives every keepalive for this connection. Each iteration recomputes the
    // deadline from the current "last activity" timestamp: if activity has happened since, it sleeps
    // the remaining time and re-checks (so protected traffic silently defers the keepalive without
    // spawning any task); only once a full idle interval has genuinely elapsed does it send. The
    // send itself awaits the reply under the configured reply timeout, preserving the teardown
    // behavior of the previous design.
    private func runKeepaliveTimerLoop(expectedGeneration: UInt64) async {
        while expectedGeneration == self.keepaliveTaskGeneration {
            guard let intervalNanoseconds = self.keepalivePolicy.intervalNanoseconds else {
                break
            }

            let remainingNanoseconds = self.nanosecondsUntilKeepaliveDeadline(
                intervalNanoseconds: intervalNanoseconds
            )
            if remainingNanoseconds > 0 {
                do {
                    try await Task.sleep(nanoseconds: remainingNanoseconds)
                } catch {
                    return
                }
                continue
            }

            guard expectedGeneration == self.keepaliveTaskGeneration,
                  self.authenticatedServiceName != nil,
                  self.outboundEncryptedPacketSerializer != nil,
                  self.inboundEncryptedPacketParser != nil,
                  !self.isTransportRekeyInProgress else {
                break
            }

            do {
                try await self.sendKeepalive(
                    responseTimeoutNanoseconds: self.keepalivePolicy.responseTimeoutNanoseconds
                )
            } catch is CancellationError {
                return
            } catch {
                // A keepalive reply timeout (or other send failure) is surfaced on the next
                // foreground operation. Stop this timer; a later protected activity re-arms it.
                self.recordPendingBackgroundTransportFailure(error)
                break
            }
        }

        if expectedGeneration == self.keepaliveTaskGeneration {
            self.keepaliveTaskHandle = nil
        }
    }

    func nanosecondsUntilKeepaliveDeadline(intervalNanoseconds: UInt64) -> UInt64 {
        guard let idleNanoseconds = self.idleNanosecondsSinceLastProtectedActivity() else {
            return intervalNanoseconds
        }

        return idleNanoseconds >= intervalNanoseconds
            ? 0
            : intervalNanoseconds - idleNanoseconds
    }

    func cancelKeepaliveTask() {
        self.keepaliveTaskHandle?.cancel()
        self.keepaliveTaskHandle = nil
        self.keepaliveTaskGeneration &+= 1
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
            do {
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
            } catch {
                // The request is already on the wire, but this waiter is abandoning its turn
                // (reply timeout or cancellation). SSH global-request replies are ordered but
                // not id-tagged, and the outbound turn is held until this closure returns, so a
                // reply for THIS request is still coming and strictly precedes any later
                // request's reply. Record it as outstanding-and-abandoned so the router drops it
                // instead of mis-delivering it to the next, unrelated request.
                self.abandonedGlobalRequestReplyCount += 1
                throw error
            }
        }
    }

    // Returns true if the reply the caller just observed must be discarded because it belongs to
    // a request whose waiter already abandoned its turn. Because replies are consumed in arrival
    // (== send) order and every abandoned request precedes the current live one, dropping this
    // many replies before matching guarantees a reply only ever reaches its originating request.
    func consumeAbandonedGlobalRequestReplyIfNeeded() -> Bool {
        guard self.abandonedGlobalRequestReplyCount > 0 else {
            return false
        }
        self.abandonedGlobalRequestReplyCount -= 1
        return true
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
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            self.recordPendingBackgroundTransportFailure(error)
            throw error
        }
    }
}
