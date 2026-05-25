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
                    for: localInitialWindowSize
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
                    for: localInitialWindowSize
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
    }

    func acceptForwardedTCPIPChannel(
        for activeForward: SSHTCPIPForwardingRequest,
        localInitialWindowSize: UInt32 = 1_048_576,
        localMaximumPacketSize: UInt32 = 32_768
    ) async throws -> SSHAcceptedForwardedTCPIPChannel {
        try self.requireAuthenticatedConnectionService()

        while true {
            guard self.isRemoteTCPIPForwardAccepting(activeForward) else {
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
                case let .channelOpenConfirmation(confirmation):
                    self.pendingChannelOpenResponses[confirmation.recipientChannel] = .confirmation(
                        confirmation
                    )
                    return SSHInboundWaitOutcome.continueWaiting
                case let .channelOpenFailure(failure):
                    self.pendingChannelOpenResponses[failure.recipientChannel] = .failure(failure)
                    return SSHInboundWaitOutcome.continueWaiting
                case .requestSuccess, .requestFailure:
                    self.appendPendingGlobalRequestReply(message)
                    guard
                        self.remoteTCPIPForwardCancellationRequestsInFlight.contains(activeForward) ||
                        self.activeGlobalRequestReplyWaiterCount > 0
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
                    if self.enqueuePendingChannelOpenResponse(from: message) ||
                        self.enqueuePendingChannelRequestReply(from: message) ||
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
                case let .channelOpenConfirmation(confirmation):
                    self.pendingChannelOpenResponses[confirmation.recipientChannel] = .confirmation(
                        confirmation
                    )
                    return SSHInboundWaitOutcome.continueWaiting
                case let .channelOpenFailure(failure):
                    self.pendingChannelOpenResponses[failure.recipientChannel] = .failure(failure)
                    return SSHInboundWaitOutcome.continueWaiting
                case .requestSuccess, .requestFailure:
                    self.appendPendingGlobalRequestReply(message)
                    guard
                        self.remoteStreamLocalForwardCancellationRequestsInFlight.contains(activeForward) ||
                        self.activeGlobalRequestReplyWaiterCount > 0
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
                    if self.enqueuePendingChannelOpenResponse(from: message) ||
                        self.enqueuePendingChannelRequestReply(from: message) ||
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

        self.pendingForwardedTCPIPChannels[activeForward, default: []].append(acceptedChannel)
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

        self.pendingForwardedStreamLocalChannels[activeForward, default: []].append(acceptedChannel)
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
        self.pendingForwardedTCPIPChannels[activeForward, default: []].append(acceptedChannel)
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
        self.pendingForwardedStreamLocalChannels[activeForward, default: []].append(acceptedChannel)
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
                        for: localInitialWindowSize
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
                        for: localInitialWindowSize
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
