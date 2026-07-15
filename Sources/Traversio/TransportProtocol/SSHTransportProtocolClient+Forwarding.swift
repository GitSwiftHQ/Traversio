// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

extension SSHTransportProtocolClient {
    func openDirectTCPIPChannel(
        target: SSHSocketEndpoint,
        originator: SSHSocketEndpoint,
        localInitialWindowSize: UInt32 = 1_048_576,
        localMaximumPacketSize: UInt32 = 32_768,
        outputBufferingMode: SSHSessionOutputBufferingMode = .undecided
    ) async throws -> SSHTCPIPChannelHandle {
        try self.requireAuthenticatedConnectionService()

        let localChannelID = self.allocateLocalChannelID()
        self.pendingManagedSessionLocalChannelIDs.insert(localChannelID)
        do {
            let latencyStartNanoseconds = self.latencyMeasurementStartNanoseconds()
            try await self.sendConnectionMessage(
                self.tcpipForwardingRequestCoder.makeDirectTCPIPChannelOpen(
                    senderChannel: localChannelID,
                    initialWindowSize: localInitialWindowSize,
                    maximumPacketSize: localMaximumPacketSize,
                    request: SSHDirectTCPIPChannelOpenRequest(
                        hostToConnect: target.host,
                        portToConnect: target.port,
                        originatorAddress: originator.host,
                        originatorPort: originator.port
                    )
                )
            )
            let channel = try await self.receiveChannelOpenConfirmation(
                localChannelID: localChannelID,
                localInitialWindowSize: localInitialWindowSize,
                localMaximumPacketSize: localMaximumPacketSize
            )
            self.recordLatencyMeasurement(
                startedAt: latencyStartNanoseconds,
                source: .channelOpen
            )
            let sessionHandle = try await self.registerManagedSession(
                channel: channel,
                outputBufferingMode: outputBufferingMode,
                receiveWindowReplenishThreshold: self.receiveWindowReplenishThreshold(
                    for: localInitialWindowSize,
                    maximumPacketSize: localMaximumPacketSize
                )
            )
            return SSHTCPIPChannelHandle(sessionHandle: sessionHandle)
        } catch {
            self.abandonPendingManagedSessionChannel(localChannelID: localChannelID)
            throw error
        }
    }

    func openDirectStreamLocalChannel(
        socketPath: String,
        originatorAddress: String = "127.0.0.1",
        originatorPort: UInt16 = 0,
        localInitialWindowSize: UInt32 = 1_048_576,
        localMaximumPacketSize: UInt32 = 32_768,
        outputBufferingMode: SSHSessionOutputBufferingMode = .undecided
    ) async throws -> SSHTCPIPChannelHandle {
        try self.requireAuthenticatedConnectionService()

        let localChannelID = self.allocateLocalChannelID()
        self.pendingManagedSessionLocalChannelIDs.insert(localChannelID)
        do {
            let latencyStartNanoseconds = self.latencyMeasurementStartNanoseconds()
            try await self.sendConnectionMessage(
                self.tcpipForwardingRequestCoder.makeDirectStreamLocalChannelOpen(
                    senderChannel: localChannelID,
                    initialWindowSize: localInitialWindowSize,
                    maximumPacketSize: localMaximumPacketSize,
                    request: SSHDirectStreamLocalChannelOpenRequest(
                        socketPath: socketPath,
                        originatorAddress: originatorAddress,
                        originatorPort: originatorPort
                    )
                )
            )
            let channel = try await self.receiveChannelOpenConfirmation(
                localChannelID: localChannelID,
                localInitialWindowSize: localInitialWindowSize,
                localMaximumPacketSize: localMaximumPacketSize
            )
            self.recordLatencyMeasurement(
                startedAt: latencyStartNanoseconds,
                source: .channelOpen
            )
            let sessionHandle = try await self.registerManagedSession(
                channel: channel,
                outputBufferingMode: outputBufferingMode,
                receiveWindowReplenishThreshold: self.receiveWindowReplenishThreshold(
                    for: localInitialWindowSize,
                    maximumPacketSize: localMaximumPacketSize
                )
            )
            return SSHTCPIPChannelHandle(sessionHandle: sessionHandle)
        } catch {
            self.abandonPendingManagedSessionChannel(localChannelID: localChannelID)
            throw error
        }
    }

    func requestTCPIPForward(
        addressToBind: String,
        portToBind: UInt16
    ) async throws -> SSHTCPIPForwardingRequest {
        try self.requireAuthenticatedConnectionService()

        let requestedForward = SSHTCPIPForwardingRequest(
            addressToBind: addressToBind,
            portToBind: portToBind
        )
        let success = try await self.sendGlobalRequestAndAwaitReply(
            self.tcpipForwardingRequestCoder.makeForwardRequest(request: requestedForward),
            requestType: "tcpip-forward"
        )
        let boundPort = try self.resolveBoundForwardPort(
            requestedPort: portToBind,
            success: success,
            requestType: "tcpip-forward"
        )
        let activeForward = SSHTCPIPForwardingRequest(
            addressToBind: addressToBind,
            portToBind: boundPort
        )
        self.activeRemoteTCPIPForwards.insert(activeForward)
        return activeForward
    }

    func cancelTCPIPForward(
        _ activeForward: SSHTCPIPForwardingRequest
    ) async throws {
        try self.requireAuthenticatedConnectionService()

        self.remoteTCPIPForwardCancellationRequestsInFlight.insert(activeForward)
        defer {
            self.remoteTCPIPForwardCancellationRequestsInFlight.remove(activeForward)
        }

        let success = try await self.sendGlobalRequestAndAwaitReply(
            self.tcpipForwardingRequestCoder.makeCancelForwardRequest(request: activeForward),
            requestType: "cancel-tcpip-forward"
        )
        try self.tcpipForwardingRequestCoder.validateEmptySuccessResponse(
            success,
            requestName: "cancel-tcpip-forward"
        )
        self.activeRemoteTCPIPForwards.remove(activeForward)
        // Any forwarded-tcpip opens that were accepted (open-confirmation sent, managed session
        // registered) but never handed to an accept() caller would otherwise stay confirmed-open
        // forever once the forward is gone. Tear them down so no confirmed-open channel is left
        // without an owner.
        await self.drainPendingForwardedTCPIPChannels(for: activeForward)
    }

    func requestStreamLocalForward(
        socketPath: String
    ) async throws -> SSHStreamLocalForwardingRequest {
        try self.requireAuthenticatedConnectionService()

        let requestedForward = SSHStreamLocalForwardingRequest(socketPath: socketPath)
        let success = try await self.sendGlobalRequestAndAwaitReply(
            self.tcpipForwardingRequestCoder.makeStreamLocalForwardRequest(request: requestedForward),
            requestType: "streamlocal-forward@openssh.com"
        )
        try self.tcpipForwardingRequestCoder.validateEmptySuccessResponse(
            success,
            requestName: "streamlocal-forward@openssh.com"
        )
        self.activeRemoteStreamLocalForwards.insert(requestedForward)
        return requestedForward
    }

    func cancelStreamLocalForward(
        _ activeForward: SSHStreamLocalForwardingRequest
    ) async throws {
        try self.requireAuthenticatedConnectionService()

        self.remoteStreamLocalForwardCancellationRequestsInFlight.insert(activeForward)
        defer {
            self.remoteStreamLocalForwardCancellationRequestsInFlight.remove(activeForward)
        }

        let success = try await self.sendGlobalRequestAndAwaitReply(
            self.tcpipForwardingRequestCoder.makeCancelStreamLocalForwardRequest(request: activeForward),
            requestType: "cancel-streamlocal-forward@openssh.com"
        )
        try self.tcpipForwardingRequestCoder.validateEmptySuccessResponse(
            success,
            requestName: "cancel-streamlocal-forward@openssh.com"
        )
        self.activeRemoteStreamLocalForwards.remove(activeForward)
        // See cancelTCPIPForward: drain orphaned confirmed-open channels for this forward.
        await self.drainPendingForwardedStreamLocalChannels(for: activeForward)
    }

    func acceptForwardedTCPIPChannel(
        for activeForward: SSHTCPIPForwardingRequest,
        localInitialWindowSize: UInt32 = 1_048_576,
        localMaximumPacketSize: UInt32 = 32_768
    ) async throws -> SSHAcceptedForwardedTCPIPChannel {
        try self.requireAuthenticatedConnectionService()

        while true {
            guard self.isRemoteTCPIPForwardAccepting(activeForward) else {
                // The forward is being torn down (cancelled / cancellation in flight). This accept
                // loop is giving up, so any channels still queued for it are orphaned — drain them
                // so none is left confirmed-open without an owner.
                await self.drainPendingForwardedTCPIPChannels(for: activeForward)
                throw CancellationError()
            }

            if let pendingChannel = self.popPendingForwardedTCPIPChannel(for: activeForward) {
                return pendingChannel
            }

            try self.checkCancellation()
            if self.activeConnectionMessageWaiterCount > 0 {
                try await self.waitForConnectionMessageWaiterProgress()
                continue
            }

            let outcome = try await self.withConnectionMessageWaiterTurn {
                let message = try await self.receiveConnectionMessage(
                    allowingGlobalRequestReply: true,
                    respectingTransportReceiveCancellation: false
                )
                switch message {
                case let .channelOpen(open):
                    if let acceptedChannel = try await self.processForwardedTCPIPChannelOpen(
                        open,
                        expectedForward: activeForward,
                        localInitialWindowSize: localInitialWindowSize,
                        localMaximumPacketSize: localMaximumPacketSize
                    ) {
                        return SSHInboundWaitOutcome.value(acceptedChannel)
                    }
                    return SSHInboundWaitOutcome.continueWaiting
                case .channelOpenConfirmation:
                    _ = try await self.enqueuePendingChannelOpenResponse(from: message)
                    return SSHInboundWaitOutcome.continueWaiting
                case .channelOpenFailure:
                    _ = try await self.enqueuePendingChannelOpenResponse(from: message)
                    return SSHInboundWaitOutcome.continueWaiting
                case .requestSuccess, .requestFailure:
                    self.appendPendingGlobalRequestReply(message)
                    // A reply is an expected arrival while a cancel request for this forward is
                    // in flight, while a live waiter exists, or while an earlier waiter abandoned
                    // its turn (reply timeout or cancellation) and its late reply is still owed:
                    // the abandoned-reply counter drops it before any future waiter can match.
                    guard
                        self.remoteTCPIPForwardCancellationRequestsInFlight.contains(activeForward) ||
                        self.activeGlobalRequestReplyWaiterCount > 0 ||
                        self.abandonedGlobalRequestReplyCount > 0
                    else {
                        throw CancellationError()
                    }
                    return SSHInboundWaitOutcome.continueWaiting
                default:
                    if try await self.routeManagedSessionMessageIfKnownOrRecentlyCompleted(
                        message
                    ) {
                        return SSHInboundWaitOutcome.continueWaiting
                    }
                    if try await self.enqueuePendingChannelOpenResponse(from: message) {
                        return SSHInboundWaitOutcome.continueWaiting
                    }
                    if self.enqueuePendingChannelRequestReply(from: message) ||
                        self.enqueuePendingPreManagedSessionMessage(from: message) {
                        return SSHInboundWaitOutcome.continueWaiting
                    }

                    throw SSHConnectionError.unexpectedConnectionMessage(
                        expected: .channelOpen,
                        received: message.messageID
                    )
                }
            }

            switch outcome {
            case let .value(acceptedChannel):
                return acceptedChannel
            case .continueWaiting:
                // When an accept loop is waiting for the next forwarded connection, it can
                // still end up routing interleaved data/EOF/close messages for already
                // accepted channels. Yield here so those channel readers get a chance to
                // observe the newly buffered bytes before the accept loop immediately arms
                // another long-lived connection-message wait.
                await Task.yield()
                continue
            }
        }
    }

    func acceptForwardedStreamLocalChannel(
        for activeForward: SSHStreamLocalForwardingRequest,
        localInitialWindowSize: UInt32 = 1_048_576,
        localMaximumPacketSize: UInt32 = 32_768
    ) async throws -> SSHAcceptedForwardedStreamLocalChannel {
        try self.requireAuthenticatedConnectionService()

        while true {
            guard self.isRemoteStreamLocalForwardAccepting(activeForward) else {
                // See acceptForwardedTCPIPChannel: drain orphaned queued channels on teardown.
                await self.drainPendingForwardedStreamLocalChannels(for: activeForward)
                throw CancellationError()
            }

            if let pendingChannel = self.popPendingForwardedStreamLocalChannel(for: activeForward) {
                return pendingChannel
            }

            try self.checkCancellation()
            if self.activeConnectionMessageWaiterCount > 0 {
                try await self.waitForConnectionMessageWaiterProgress()
                continue
            }

            let outcome = try await self.withConnectionMessageWaiterTurn {
                let message = try await self.receiveConnectionMessage(
                    allowingGlobalRequestReply: true,
                    respectingTransportReceiveCancellation: false
                )
                switch message {
                case let .channelOpen(open):
                    if let acceptedChannel = try await self.processForwardedStreamLocalChannelOpen(
                        open,
                        expectedForward: activeForward,
                        localInitialWindowSize: localInitialWindowSize,
                        localMaximumPacketSize: localMaximumPacketSize
                    ) {
                        return SSHInboundWaitOutcome.value(acceptedChannel)
                    }
                    return SSHInboundWaitOutcome.continueWaiting
                case .channelOpenConfirmation:
                    _ = try await self.enqueuePendingChannelOpenResponse(from: message)
                    return SSHInboundWaitOutcome.continueWaiting
                case .channelOpenFailure:
                    _ = try await self.enqueuePendingChannelOpenResponse(from: message)
                    return SSHInboundWaitOutcome.continueWaiting
                case .requestSuccess, .requestFailure:
                    self.appendPendingGlobalRequestReply(message)
                    // See acceptForwardedTCPIPChannel: an abandoned earlier waiter's late reply
                    // is expected here and is dropped by the abandoned-reply counter, not fatal.
                    guard
                        self.remoteStreamLocalForwardCancellationRequestsInFlight.contains(activeForward) ||
                        self.activeGlobalRequestReplyWaiterCount > 0 ||
                        self.abandonedGlobalRequestReplyCount > 0
                    else {
                        throw CancellationError()
                    }
                    return SSHInboundWaitOutcome.continueWaiting
                default:
                    if try await self.routeManagedSessionMessageIfKnownOrRecentlyCompleted(
                        message
                    ) {
                        return SSHInboundWaitOutcome.continueWaiting
                    }
                    if try await self.enqueuePendingChannelOpenResponse(from: message) {
                        return SSHInboundWaitOutcome.continueWaiting
                    }
                    if self.enqueuePendingChannelRequestReply(from: message) ||
                        self.enqueuePendingPreManagedSessionMessage(from: message) {
                        return SSHInboundWaitOutcome.continueWaiting
                    }

                    throw SSHConnectionError.unexpectedConnectionMessage(
                        expected: .channelOpen,
                        received: message.messageID
                    )
                }
            }

            switch outcome {
            case let .value(acceptedChannel):
                return acceptedChannel
            case .continueWaiting:
                await Task.yield()
                continue
            }
        }
    }

    func resolveBoundForwardPort(
        requestedPort: UInt16,
        success: SSHGlobalRequestSuccessMessage,
        requestType: String
    ) throws -> UInt16 {
        let responsePort = try self.tcpipForwardingRequestCoder.parseForwardSuccessPort(
            from: success
        )

        if requestedPort == 0 {
            guard let responsePort else {
                throw SSHConnectionError.invalidGlobalRequestResponse(requestType: requestType)
            }
            return responsePort
        }

        guard let responsePort else {
            return requestedPort
        }
        guard responsePort == requestedPort else {
            throw SSHConnectionError.invalidGlobalRequestResponse(requestType: requestType)
        }
        return responsePort
    }

    // Upper bound on channels queued for a single forward that has no active accept() caller.
    // Inbound forwarded opens are fully accepted (confirmed-open, managed session registered), so
    // an unbounded queue would let a peer flood the client into unbounded memory/window use.
    static let maximumPendingForwardedChannelsPerForward = 256

    func appendPendingForwardedTCPIPChannel(
        _ acceptedChannel: SSHAcceptedForwardedTCPIPChannel,
        for activeForward: SSHTCPIPForwardingRequest
    ) async {
        var pendingChannels = self.pendingForwardedTCPIPChannels[activeForward] ?? []
        guard pendingChannels.count < Self.maximumPendingForwardedChannelsPerForward else {
            // Nobody is accepting fast enough. Rather than grow the queue without bound, close the
            // freshly confirmed channel so the peer's tunnel is torn down cleanly.
            try? await self.closeChannel(
                forLocalChannelID: acceptedChannel.handle.channel.localChannelID,
                respectCancellation: false
            )
            return
        }
        pendingChannels.append(acceptedChannel)
        self.pendingForwardedTCPIPChannels[activeForward] = pendingChannels
    }

    func appendPendingForwardedStreamLocalChannel(
        _ acceptedChannel: SSHAcceptedForwardedStreamLocalChannel,
        for activeForward: SSHStreamLocalForwardingRequest
    ) async {
        var pendingChannels = self.pendingForwardedStreamLocalChannels[activeForward] ?? []
        guard pendingChannels.count < Self.maximumPendingForwardedChannelsPerForward else {
            try? await self.closeChannel(
                forLocalChannelID: acceptedChannel.handle.channel.localChannelID,
                respectCancellation: false
            )
            return
        }
        pendingChannels.append(acceptedChannel)
        self.pendingForwardedStreamLocalChannels[activeForward] = pendingChannels
    }

    func drainPendingForwardedTCPIPChannels(
        for activeForward: SSHTCPIPForwardingRequest
    ) async {
        guard let pendingChannels = self.pendingForwardedTCPIPChannels.removeValue(
            forKey: activeForward
        ) else {
            return
        }

        for pendingChannel in pendingChannels {
            // Send CHANNEL_CLOSE and drop the managed-session state, mirroring closeChannel's
            // teardown, so an orphaned confirmed-open channel is never leaked.
            try? await self.closeChannel(
                forLocalChannelID: pendingChannel.handle.channel.localChannelID,
                respectCancellation: false
            )
        }
    }

    func drainPendingForwardedStreamLocalChannels(
        for activeForward: SSHStreamLocalForwardingRequest
    ) async {
        guard let pendingChannels = self.pendingForwardedStreamLocalChannels.removeValue(
            forKey: activeForward
        ) else {
            return
        }

        for pendingChannel in pendingChannels {
            try? await self.closeChannel(
                forLocalChannelID: pendingChannel.handle.channel.localChannelID,
                respectCancellation: false
            )
        }
    }

    func popPendingForwardedTCPIPChannel(
        for activeForward: SSHTCPIPForwardingRequest
    ) -> SSHAcceptedForwardedTCPIPChannel? {
        guard var pendingChannels = self.pendingForwardedTCPIPChannels[activeForward],
              !pendingChannels.isEmpty else {
            return nil
        }

        let acceptedChannel = pendingChannels.removeFirst()
        if pendingChannels.isEmpty {
            self.pendingForwardedTCPIPChannels.removeValue(forKey: activeForward)
        } else {
            self.pendingForwardedTCPIPChannels[activeForward] = pendingChannels
        }
        return acceptedChannel
    }

    func popPendingForwardedStreamLocalChannel(
        for activeForward: SSHStreamLocalForwardingRequest
    ) -> SSHAcceptedForwardedStreamLocalChannel? {
        guard var pendingChannels = self.pendingForwardedStreamLocalChannels[activeForward],
              !pendingChannels.isEmpty else {
            return nil
        }

        let acceptedChannel = pendingChannels.removeFirst()
        if pendingChannels.isEmpty {
            self.pendingForwardedStreamLocalChannels.removeValue(forKey: activeForward)
        } else {
            self.pendingForwardedStreamLocalChannels[activeForward] = pendingChannels
        }
        return acceptedChannel
    }

    func popPendingGlobalRequestReply() -> SSHConnectionMessage? {
        guard !self.pendingGlobalRequestReplies.isEmpty else {
            return nil
        }
        return self.pendingGlobalRequestReplies.removeFirst()
    }

    func appendPendingGlobalRequestReply(_ message: SSHConnectionMessage) {
        self.pendingGlobalRequestReplies.append(message)
        self.resumeAllConnectionMessageWaiterProgressWaitersReady()
    }

    func sendGlobalRequestAndAwaitReply(
        _ message: SSHConnectionMessage,
        requestType: String
    ) async throws -> SSHGlobalRequestSuccessMessage {
        let request = try self.globalRequest(from: message, requestType: requestType)
        let reply = try await self.sendGlobalRequestAndAwaitReplyMessage(
            request: request,
            requestType: requestType
        )
        switch reply {
        case let .requestSuccess(success):
            return success
        case .requestFailure:
            throw SSHConnectionError.globalRequestFailed(requestType: requestType)
        default:
            throw SSHConnectionError.unexpectedConnectionMessage(
                expected: .requestSuccess,
                received: reply.messageID
            )
        }
    }

    func processForwardedTCPIPChannelOpen(
        _ open: SSHChannelOpenMessage,
        expectedForward: SSHTCPIPForwardingRequest,
        localInitialWindowSize: UInt32,
        localMaximumPacketSize: UInt32
    ) async throws -> SSHAcceptedForwardedTCPIPChannel? {
        guard open.channelType == "forwarded-tcpip" else {
            _ = try await self.queueForwardedStreamLocalChannelOpenIfActive(
                open,
                localInitialWindowSize: localInitialWindowSize,
                localMaximumPacketSize: localMaximumPacketSize
            )
            return nil
        }

        let request = try self.tcpipForwardingRequestCoder.parseForwardedTCPIPChannelOpen(
            from: open
        )
        let activeForward = SSHTCPIPForwardingRequest(
            addressToBind: request.listeningAddress,
            portToBind: request.listeningPort
        )
        guard self.isRemoteTCPIPForwardAccepting(activeForward) else {
            try await self.rejectIncomingChannelOpen(
                open,
                reasonCode: .administrativelyProhibited,
                description: "remote forward not active"
            )
            return nil
        }

        let acceptedChannel = try await self.acceptIncomingForwardedTCPIPChannelOpen(
            open,
            request: request,
            localInitialWindowSize: localInitialWindowSize,
            localMaximumPacketSize: localMaximumPacketSize
        )
        if activeForward == expectedForward {
            return acceptedChannel
        }

        await self.appendPendingForwardedTCPIPChannel(acceptedChannel, for: activeForward)
        return nil
    }

    func processForwardedStreamLocalChannelOpen(
        _ open: SSHChannelOpenMessage,
        expectedForward: SSHStreamLocalForwardingRequest,
        localInitialWindowSize: UInt32,
        localMaximumPacketSize: UInt32
    ) async throws -> SSHAcceptedForwardedStreamLocalChannel? {
        guard open.channelType == "forwarded-streamlocal@openssh.com" else {
            _ = try await self.queueForwardedTCPIPChannelOpenIfActive(
                open,
                localInitialWindowSize: localInitialWindowSize,
                localMaximumPacketSize: localMaximumPacketSize
            )
            return nil
        }

        let request = try self.tcpipForwardingRequestCoder.parseForwardedStreamLocalChannelOpen(
            from: open
        )
        let activeForward = SSHStreamLocalForwardingRequest(socketPath: request.socketPath)
        guard self.isRemoteStreamLocalForwardAccepting(activeForward) else {
            try await self.rejectIncomingChannelOpen(
                open,
                reasonCode: .administrativelyProhibited,
                description: "remote streamlocal forward not active"
            )
            return nil
        }

        let acceptedChannel = try await self.acceptIncomingForwardedStreamLocalChannelOpen(
            open,
            request: request,
            localInitialWindowSize: localInitialWindowSize,
            localMaximumPacketSize: localMaximumPacketSize
        )
        if activeForward == expectedForward {
            return acceptedChannel
        }

        await self.appendPendingForwardedStreamLocalChannel(acceptedChannel, for: activeForward)
        return nil
    }

    func globalRequest(
        from message: SSHConnectionMessage,
        requestType: String
    ) throws -> SSHGlobalRequestMessage {
        guard case let .globalRequest(request) = message else {
            throw SSHConnectionError.invalidGlobalRequest(requestType)
        }
        return request
    }

    func handleIncomingChannelOpenWhileWaiting(
        _ open: SSHChannelOpenMessage,
        localInitialWindowSize: UInt32 = 1_048_576,
        localMaximumPacketSize: UInt32 = 32_768,
        respectCancellation: Bool = false
    ) async throws {
        switch open.channelType {
        case "forwarded-tcpip":
            _ = try await self.queueForwardedTCPIPChannelOpenIfActive(
                open,
                localInitialWindowSize: localInitialWindowSize,
                localMaximumPacketSize: localMaximumPacketSize,
                respectCancellation: respectCancellation
            )
        case "forwarded-streamlocal@openssh.com":
            _ = try await self.queueForwardedStreamLocalChannelOpenIfActive(
                open,
                localInitialWindowSize: localInitialWindowSize,
                localMaximumPacketSize: localMaximumPacketSize,
                respectCancellation: respectCancellation
            )
        default:
            try await self.rejectIncomingChannelOpen(
                open,
                respectCancellation: respectCancellation
            )
            return
        }
    }

    func queueForwardedTCPIPChannelOpenIfActive(
        _ open: SSHChannelOpenMessage,
        localInitialWindowSize: UInt32,
        localMaximumPacketSize: UInt32,
        respectCancellation: Bool = false
    ) async throws -> Bool {
        guard open.channelType == "forwarded-tcpip" else {
            try await self.rejectIncomingChannelOpen(
                open,
                respectCancellation: respectCancellation
            )
            return false
        }

        let request = try self.tcpipForwardingRequestCoder.parseForwardedTCPIPChannelOpen(
            from: open
        )
        let activeForward = SSHTCPIPForwardingRequest(
            addressToBind: request.listeningAddress,
            portToBind: request.listeningPort
        )
        guard self.isRemoteTCPIPForwardAccepting(activeForward) else {
            try await self.rejectIncomingChannelOpen(
                open,
                reasonCode: .administrativelyProhibited,
                description: "remote forward not active",
                respectCancellation: respectCancellation
            )
            return true
        }

        let acceptedChannel = try await self.acceptIncomingForwardedTCPIPChannelOpen(
            open,
            request: request,
            localInitialWindowSize: localInitialWindowSize,
            localMaximumPacketSize: localMaximumPacketSize,
            respectCancellation: respectCancellation
        )
        await self.appendPendingForwardedTCPIPChannel(acceptedChannel, for: activeForward)
        return true
    }

    func queueForwardedStreamLocalChannelOpenIfActive(
        _ open: SSHChannelOpenMessage,
        localInitialWindowSize: UInt32,
        localMaximumPacketSize: UInt32,
        respectCancellation: Bool = false
    ) async throws -> Bool {
        guard open.channelType == "forwarded-streamlocal@openssh.com" else {
            try await self.rejectIncomingChannelOpen(
                open,
                respectCancellation: respectCancellation
            )
            return false
        }

        let request = try self.tcpipForwardingRequestCoder.parseForwardedStreamLocalChannelOpen(
            from: open
        )
        let activeForward = SSHStreamLocalForwardingRequest(socketPath: request.socketPath)
        guard self.isRemoteStreamLocalForwardAccepting(activeForward) else {
            try await self.rejectIncomingChannelOpen(
                open,
                reasonCode: .administrativelyProhibited,
                description: "remote streamlocal forward not active",
                respectCancellation: respectCancellation
            )
            return true
        }

        let acceptedChannel = try await self.acceptIncomingForwardedStreamLocalChannelOpen(
            open,
            request: request,
            localInitialWindowSize: localInitialWindowSize,
            localMaximumPacketSize: localMaximumPacketSize,
            respectCancellation: respectCancellation
        )
        await self.appendPendingForwardedStreamLocalChannel(acceptedChannel, for: activeForward)
        return true
    }

    func isRemoteTCPIPForwardAccepting(
        _ activeForward: SSHTCPIPForwardingRequest
    ) -> Bool {
        self.activeRemoteTCPIPForwards.contains(activeForward)
            && !self.remoteTCPIPForwardCancellationRequestsInFlight.contains(activeForward)
    }

    func isRemoteStreamLocalForwardAccepting(
        _ activeForward: SSHStreamLocalForwardingRequest
    ) -> Bool {
        self.activeRemoteStreamLocalForwards.contains(activeForward)
            && !self.remoteStreamLocalForwardCancellationRequestsInFlight.contains(activeForward)
    }

    func acceptIncomingForwardedTCPIPChannelOpen(
        _ open: SSHChannelOpenMessage,
        request: SSHForwardedTCPIPChannelOpenRequest,
        localInitialWindowSize: UInt32,
        localMaximumPacketSize: UInt32,
        respectCancellation: Bool = false
    ) async throws -> SSHAcceptedForwardedTCPIPChannel {
        let localChannelID = self.allocateLocalChannelID()
        let channel = SSHChannel(
            localChannelID: localChannelID,
            remoteChannelID: open.senderChannel,
            localInitialWindowSize: localInitialWindowSize,
            localMaximumPacketSize: localMaximumPacketSize,
            remoteInitialWindowSize: open.initialWindowSize,
            remoteMaximumPacketSize: open.maximumPacketSize
        )
        self.pendingManagedSessionLocalChannelIDs.insert(localChannelID)

        do {
            try await self.sendConnectionMessage(
                .channelOpenConfirmation(
                    SSHChannelOpenConfirmationMessage(
                        recipientChannel: open.senderChannel,
                        senderChannel: localChannelID,
                        initialWindowSize: localInitialWindowSize,
                        maximumPacketSize: localMaximumPacketSize,
                        channelTypeData: []
                    )
                ),
                respectCancellation: respectCancellation,
                respectTransportSendCancellation: respectCancellation
            )

            let handle = SSHTCPIPChannelHandle(
                sessionHandle: try await self.registerManagedSession(
                    channel: channel,
                    receiveWindowReplenishThreshold: self.receiveWindowReplenishThreshold(
                        for: localInitialWindowSize,
                        maximumPacketSize: localMaximumPacketSize
                    )
                )
            )
            return SSHAcceptedForwardedTCPIPChannel(
                openRequest: request,
                handle: handle
            )
        } catch {
            self.abandonPendingManagedSessionChannel(localChannelID: localChannelID)
            self.removeManagedSessionState(forLocalChannelID: localChannelID)
            throw error
        }
    }

    func acceptIncomingForwardedStreamLocalChannelOpen(
        _ open: SSHChannelOpenMessage,
        request: SSHForwardedStreamLocalChannelOpenRequest,
        localInitialWindowSize: UInt32,
        localMaximumPacketSize: UInt32,
        respectCancellation: Bool = false
    ) async throws -> SSHAcceptedForwardedStreamLocalChannel {
        let localChannelID = self.allocateLocalChannelID()
        let channel = SSHChannel(
            localChannelID: localChannelID,
            remoteChannelID: open.senderChannel,
            localInitialWindowSize: localInitialWindowSize,
            localMaximumPacketSize: localMaximumPacketSize,
            remoteInitialWindowSize: open.initialWindowSize,
            remoteMaximumPacketSize: open.maximumPacketSize
        )
        self.pendingManagedSessionLocalChannelIDs.insert(localChannelID)

        do {
            try await self.sendConnectionMessage(
                .channelOpenConfirmation(
                    SSHChannelOpenConfirmationMessage(
                        recipientChannel: open.senderChannel,
                        senderChannel: localChannelID,
                        initialWindowSize: localInitialWindowSize,
                        maximumPacketSize: localMaximumPacketSize,
                        channelTypeData: []
                    )
                ),
                respectCancellation: respectCancellation,
                respectTransportSendCancellation: respectCancellation
            )

            let handle = SSHTCPIPChannelHandle(
                sessionHandle: try await self.registerManagedSession(
                    channel: channel,
                    receiveWindowReplenishThreshold: self.receiveWindowReplenishThreshold(
                        for: localInitialWindowSize,
                        maximumPacketSize: localMaximumPacketSize
                    )
                )
            )
            return SSHAcceptedForwardedStreamLocalChannel(
                openRequest: request,
                handle: handle
            )
        } catch {
            self.abandonPendingManagedSessionChannel(localChannelID: localChannelID)
            self.removeManagedSessionState(forLocalChannelID: localChannelID)
            throw error
        }
    }

    func rejectIncomingChannelOpen(
        _ open: SSHChannelOpenMessage,
        reasonCode: SSHChannelOpenFailureReasonCode = .unknownChannelType,
        description: String? = nil,
        respectCancellation: Bool = false
    ) async throws {
        try await self.sendConnectionMessage(
            .channelOpenFailure(
                SSHChannelOpenFailureMessage(
                    recipientChannel: open.senderChannel,
                    reasonCode: reasonCode,
                    description: description ?? "unsupported incoming channel type: \(open.channelType)",
                    languageTag: ""
                )
            ),
            respectCancellation: respectCancellation,
            respectTransportSendCancellation: respectCancellation
        )
    }
}
