// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

extension SSHTransportProtocolClient {
    package func execute(
        command: String,
        environment: [SSHSessionEnvironmentVariable] = [],
        localInitialWindowSize: UInt32 = 1_048_576,
        localMaximumPacketSize: UInt32 = 32_768
    ) async throws -> SSHSessionExecResult {
        let session = try await self.openExecSession(
            command: command,
            environment: environment,
            localInitialWindowSize: localInitialWindowSize,
            localMaximumPacketSize: localMaximumPacketSize,
            outputBufferingMode: .transcript
        )
        let transcript = try await session.collectOutputUntilClose()
        return SSHSessionExecResult(transcript: transcript)
    }

    package func captureShellStartup(
        pseudoTerminalRequest: SSHPseudoTerminalRequest = .default,
        initialInput: [UInt8] = Array("exit\n".utf8),
        environment: [SSHSessionEnvironmentVariable] = [],
        localInitialWindowSize: UInt32 = 1_048_576,
        localMaximumPacketSize: UInt32 = 32_768
    ) async throws -> SSHSessionShellCaptureResult {
        let session = try await self.openShellSession(
            pseudoTerminalRequest: pseudoTerminalRequest,
            environment: environment,
            localInitialWindowSize: localInitialWindowSize,
            localMaximumPacketSize: localMaximumPacketSize,
            outputBufferingMode: .transcript
        )
        try await session.write(initialInput)
        let transcript = try await session.collectOutputUntilClose()
        return SSHSessionShellCaptureResult(transcript: transcript)
    }

    func openExecSession(
        command: String,
        environment: [SSHSessionEnvironmentVariable] = [],
        localInitialWindowSize: UInt32 = 1_048_576,
        localMaximumPacketSize: UInt32 = 32_768,
        outputBufferingMode: SSHSessionOutputBufferingMode = .undecided
    ) async throws -> SSHSessionHandle {
        try self.requireAuthenticatedConnectionService()

        let channel = try await self.openSessionChannel(
            localInitialWindowSize: localInitialWindowSize,
            localMaximumPacketSize: localMaximumPacketSize
        )

        do {
            let preExecRemoteWindowAdjustment = try await self.sendEnvironmentRequests(
                environment,
                recipientChannel: channel.remoteChannelID,
                localChannelID: channel.localChannelID
            )
            var preSessionRemoteWindowAdjustment = try await self.sendChannelRequestAndAwaitReply(
                self.sessionRequestCoder.makeExecRequest(
                    recipientChannel: channel.remoteChannelID,
                    command: command
                ),
                localChannelID: channel.localChannelID,
                requestType: "exec"
            )
            try self.accumulateRemoteWindowAdjustment(
                preExecRemoteWindowAdjustment,
                total: &preSessionRemoteWindowAdjustment,
                localChannelID: channel.localChannelID
            )
            return try await self.registerManagedSession(
                channel: channel,
                initialRemoteWindowAdjustment: preSessionRemoteWindowAdjustment,
                outputBufferingMode: outputBufferingMode,
                receiveWindowReplenishThreshold: self.receiveWindowReplenishThreshold(
                    for: localInitialWindowSize
                )
            )
        } catch {
            self.abandonPendingManagedSessionChannel(localChannelID: channel.localChannelID)
            throw error
        }
    }

    func openSubsystemSession(
        subsystem: String,
        environment: [SSHSessionEnvironmentVariable] = [],
        localInitialWindowSize: UInt32 = 1_048_576,
        localMaximumPacketSize: UInt32 = 32_768,
        outputBufferingMode: SSHSessionOutputBufferingMode = .undecided
    ) async throws -> SSHSessionHandle {
        try self.requireAuthenticatedConnectionService()

        let channel = try await self.openSessionChannel(
            localInitialWindowSize: localInitialWindowSize,
            localMaximumPacketSize: localMaximumPacketSize
        )

        do {
            let preSubsystemRemoteWindowAdjustment = try await self.sendEnvironmentRequests(
                environment,
                recipientChannel: channel.remoteChannelID,
                localChannelID: channel.localChannelID
            )
            let preSessionRemoteWindowAdjustment = try await self.sendChannelRequestAndAwaitReply(
                self.sessionRequestCoder.makeSubsystemRequest(
                    recipientChannel: channel.remoteChannelID,
                    subsystem: subsystem
                ),
                localChannelID: channel.localChannelID,
                requestType: "subsystem"
            )
            var totalRemoteWindowAdjustment = preSessionRemoteWindowAdjustment
            try self.accumulateRemoteWindowAdjustment(
                preSubsystemRemoteWindowAdjustment,
                total: &totalRemoteWindowAdjustment,
                localChannelID: channel.localChannelID
            )
            return try await self.registerManagedSession(
                channel: channel,
                initialRemoteWindowAdjustment: totalRemoteWindowAdjustment,
                outputBufferingMode: outputBufferingMode,
                receiveWindowReplenishThreshold: self.receiveWindowReplenishThreshold(
                    for: localInitialWindowSize
                )
            )
        } catch {
            self.abandonPendingManagedSessionChannel(localChannelID: channel.localChannelID)
            throw error
        }
    }

    func openShellSession(
        pseudoTerminalRequest: SSHPseudoTerminalRequest = .default,
        environment: [SSHSessionEnvironmentVariable] = [],
        localInitialWindowSize: UInt32 = 1_048_576,
        localMaximumPacketSize: UInt32 = 32_768,
        outputBufferingMode: SSHSessionOutputBufferingMode = .undecided
    ) async throws -> SSHSessionHandle {
        try self.requireAuthenticatedConnectionService()

        let channel = try await self.openSessionChannel(
            localInitialWindowSize: localInitialWindowSize,
            localMaximumPacketSize: localMaximumPacketSize
        )

        do {
            var preSessionRemoteWindowAdjustment = try await self.sendEnvironmentRequests(
                environment,
                recipientChannel: channel.remoteChannelID,
                localChannelID: channel.localChannelID
            )
            let ptyRemoteWindowAdjustment = try await self.sendChannelRequestAndAwaitReply(
                try self.sessionRequestCoder.makePseudoTerminalRequest(
                    recipientChannel: channel.remoteChannelID,
                    request: pseudoTerminalRequest
                ),
                localChannelID: channel.localChannelID,
                requestType: "pty-req"
            )
            try self.accumulateRemoteWindowAdjustment(
                ptyRemoteWindowAdjustment,
                total: &preSessionRemoteWindowAdjustment,
                localChannelID: channel.localChannelID
            )

            let shellRemoteWindowAdjustment = try await self.sendChannelRequestAndAwaitReply(
                self.sessionRequestCoder.makeShellRequest(
                    recipientChannel: channel.remoteChannelID
                ),
                localChannelID: channel.localChannelID,
                requestType: "shell"
            )
            try self.accumulateRemoteWindowAdjustment(
                shellRemoteWindowAdjustment,
                total: &preSessionRemoteWindowAdjustment,
                localChannelID: channel.localChannelID
            )

            return try await self.registerManagedSession(
                channel: channel,
                initialRemoteWindowAdjustment: preSessionRemoteWindowAdjustment,
                outputBufferingMode: outputBufferingMode,
                receiveWindowReplenishThreshold: self.receiveWindowReplenishThreshold(
                    for: localInitialWindowSize
                )
            )
        } catch {
            self.abandonPendingManagedSessionChannel(localChannelID: channel.localChannelID)
            throw error
        }
    }

    private func sendEnvironmentRequests(
        _ environment: [SSHSessionEnvironmentVariable],
        recipientChannel: UInt32,
        localChannelID: UInt32
    ) async throws -> UInt32 {
        var totalRemoteWindowAdjustment: UInt32 = 0

        for environmentVariable in environment {
            let remoteWindowAdjustment = try await self.sendChannelRequestAndAwaitReply(
                self.sessionRequestCoder.makeEnvironmentRequest(
                    recipientChannel: recipientChannel,
                    environmentVariable: environmentVariable
                ),
                localChannelID: localChannelID,
                requestType: "env"
            )
            try self.accumulateRemoteWindowAdjustment(
                remoteWindowAdjustment,
                total: &totalRemoteWindowAdjustment,
                localChannelID: localChannelID
            )
        }

        return totalRemoteWindowAdjustment
    }

    func receiveConnectionMessage(
        allowingGlobalRequestReply: Bool = false,
        respectingTransportReceiveCancellation: Bool = true
    ) async throws -> SSHConnectionMessage {
        while true {
            if let pendingMessage = self.popPendingConnectionMessageAfterTransportRekey() {
                if let message = try await self.processReceivedConnectionMessage(
                    pendingMessage,
                    allowingGlobalRequestReply: allowingGlobalRequestReply
                ) {
                    return message
                }
                continue
            }

            if respectingTransportReceiveCancellation {
                try self.checkCancellation()
            }
            try await self.prepareProtectedReceive(
                respectCancellation: respectingTransportReceiveCancellation
            )
            if let pendingMessage = self.popPendingConnectionMessageAfterTransportRekey() {
                if let message = try await self.processReceivedConnectionMessage(
                    pendingMessage,
                    allowingGlobalRequestReply: allowingGlobalRequestReply
                ) {
                    return message
                }
                continue
            }

            let packet = try await self.receivePacket(
                respectingTransportReceiveCancellation: respectingTransportReceiveCancellation
            )

            if let transportMessage = try self.parseTransportMessageIfPossible(packet.payload) {
                if try await self.handleProtectedTransportMessage(transportMessage) {
                    continue
                }
                throw SSHUserAuthenticationError.unexpectedTransportMessage(
                    transportMessage.messageID
                )
            }

            if let connectionMessage = try self.parseConnectionMessageIfPossible(packet.payload) {
                if let message = try await self.processReceivedConnectionMessage(
                    connectionMessage,
                    allowingGlobalRequestReply: allowingGlobalRequestReply
                ) {
                    return message
                }
                continue
            }

            throw SSHUserAuthenticationError.unexpectedPostAuthenticationMessage(packet.payload[0])
        }
    }

    private func processReceivedConnectionMessage(
        _ connectionMessage: SSHConnectionMessage,
        allowingGlobalRequestReply: Bool
    ) async throws -> SSHConnectionMessage? {
        switch connectionMessage {
        case let .globalRequest(request):
            if request.wantReply {
                try await self.sendConnectionMessage(
                    .requestFailure(SSHGlobalRequestFailureMessage()),
                    respectCancellation: false,
                    respectTransportSendCancellation: false
                )
            }
            return nil
        case .requestSuccess, .requestFailure:
            if allowingGlobalRequestReply {
                return connectionMessage
            }
            self.appendPendingGlobalRequestReply(connectionMessage)
            return nil
        default:
            return connectionMessage
        }
    }

    func receiveGlobalRequestReply(
        requestType: String
    ) async throws -> SSHGlobalRequestSuccessMessage {
        let reply = try await self.receiveGlobalRequestReplyMessage(requestType: requestType)
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

    func receiveGlobalRequestReplyMessage(
        requestType: String,
        timeoutNanoseconds: UInt64? = nil,
        timeoutError: SSHTimeoutError? = nil
    ) async throws -> SSHConnectionMessage {
        self.activeGlobalRequestReplyWaiterCount += 1
        defer {
            self.activeGlobalRequestReplyWaiterCount -= 1
        }
        let timeoutNanoseconds = timeoutNanoseconds ?? self.responseTimeoutNanoseconds
        let client = self
        return try await withOptionalTimeout(
            nanoseconds: timeoutNanoseconds,
            timeoutError: timeoutError ?? SSHTimeoutError.globalRequestReply(
                requestType: requestType,
                durationNanoseconds: timeoutNanoseconds ?? 1
            )
        ) {
            try await client.receiveGlobalRequestReplyMessageWithoutTimeout(
                requestType: requestType
            )
        }
    }

    private func receiveGlobalRequestReplyMessageWithoutTimeout(
        requestType: String
    ) async throws -> SSHConnectionMessage {
        while true {
            if let pendingReply = self.popPendingGlobalRequestReply() {
                switch pendingReply {
                case .requestSuccess, .requestFailure:
                    return pendingReply
                default:
                    break
                }
            }

            try self.checkCancellation()
            if self.activeConnectionMessageWaiterCount > 0 {
                try await self.waitForConnectionMessageWaiterProgress()
                continue
            }

            let outcome: SSHInboundWaitOutcome<SSHConnectionMessage> =
                try await self.withConnectionMessageWaiterTurn {
                let message = try await self.receiveConnectionMessage(
                    allowingGlobalRequestReply: true
                )
                if try await self.routeManagedSessionMessageIfKnownOrRecentlyCompleted(message) {
                    return .continueWaiting
                }

                switch message {
                case .requestSuccess, .requestFailure:
                    return SSHInboundWaitOutcome.value(message)
                case let .channelOpen(open):
                    try await self.handleIncomingChannelOpenWhileWaiting(open)
                    return SSHInboundWaitOutcome.continueWaiting
                default:
                    if let localChannelID = self.managedSessionLocalChannelIDIfPresent(from: message),
                       self.managedSessionStates[localChannelID] != nil ||
                        self.recentlyCompletedManagedSessionChannelIDs.contains(
                            localChannelID
                        ) {
                        _ = try await self.routeManagedSessionMessage(message)
                        return SSHInboundWaitOutcome.continueWaiting
                    }
                    if self.enqueuePendingChannelOpenResponse(from: message) ||
                        self.enqueuePendingChannelRequestReply(from: message) ||
                        self.enqueuePendingPreManagedSessionMessage(from: message) {
                        return SSHInboundWaitOutcome.continueWaiting
                    }

                    throw SSHConnectionError.unexpectedConnectionMessage(
                        expected: .requestSuccess,
                        received: message.messageID
                    )
                }
            }

            switch outcome {
            case let .value(reply):
                return reply
            case .continueWaiting:
                await Task.yield()
                continue
            }
        }
    }

    func receiveChannelOpenConfirmation(
        localChannelID: UInt32,
        localInitialWindowSize: UInt32,
        localMaximumPacketSize: UInt32
    ) async throws -> SSHChannel {
        let timeoutNanoseconds = self.responseTimeoutNanoseconds
        let client = self
        return try await withOptionalTimeout(
            nanoseconds: timeoutNanoseconds,
            timeoutError: SSHTimeoutError.channelOpenResponse(
                durationNanoseconds: timeoutNanoseconds ?? 1
            )
        ) {
            try await client.receiveChannelOpenConfirmationWithoutTimeout(
                localChannelID: localChannelID,
                localInitialWindowSize: localInitialWindowSize,
                localMaximumPacketSize: localMaximumPacketSize
            )
        }
    }

    private func receiveChannelOpenConfirmationWithoutTimeout(
        localChannelID: UInt32,
        localInitialWindowSize: UInt32,
        localMaximumPacketSize: UInt32
    ) async throws -> SSHChannel {
        while true {
            if let pendingResponse = self.popPendingChannelOpenResponse(
                forLocalChannelID: localChannelID
            ) {
                switch pendingResponse {
                case let .confirmation(confirmation):
                    return SSHChannel(
                        localChannelID: localChannelID,
                        remoteChannelID: confirmation.senderChannel,
                        localInitialWindowSize: localInitialWindowSize,
                        localMaximumPacketSize: localMaximumPacketSize,
                        remoteInitialWindowSize: confirmation.initialWindowSize,
                        remoteMaximumPacketSize: confirmation.maximumPacketSize
                    )
                case let .failure(failure):
                    throw SSHConnectionError.channelOpenFailure(failure)
                }
            }

            try self.checkCancellation()
            if self.activeConnectionMessageWaiterCount > 0 {
                try await self.waitForConnectionMessageWaiterProgress()
                continue
            }

            let outcome: SSHInboundWaitOutcome<SSHChannel> =
                try await self.withConnectionMessageWaiterTurn {
                let message = try await self.receiveConnectionMessage()
                if try await self.routeManagedSessionMessageIfKnownOrRecentlyCompleted(message) {
                    return .continueWaiting
                }
                switch message {
                case let .channelOpenConfirmation(confirmation):
                    guard confirmation.recipientChannel == localChannelID else {
                        self.pendingChannelOpenResponses[confirmation.recipientChannel] = .confirmation(
                            confirmation
                        )
                        return SSHInboundWaitOutcome<SSHChannel>.continueWaiting
                    }

                    return SSHInboundWaitOutcome.value(
                        SSHChannel(
                            localChannelID: localChannelID,
                            remoteChannelID: confirmation.senderChannel,
                            localInitialWindowSize: localInitialWindowSize,
                            localMaximumPacketSize: localMaximumPacketSize,
                            remoteInitialWindowSize: confirmation.initialWindowSize,
                            remoteMaximumPacketSize: confirmation.maximumPacketSize
                        )
                    )
                case let .channelOpenFailure(failure):
                    guard failure.recipientChannel == localChannelID else {
                        self.pendingChannelOpenResponses[failure.recipientChannel] = .failure(
                            failure
                        )
                        return SSHInboundWaitOutcome<SSHChannel>.continueWaiting
                    }

                    throw SSHConnectionError.channelOpenFailure(failure)
                case .channelSuccess, .channelFailure, .channelWindowAdjust:
                    if self.enqueuePendingChannelRequestReply(from: message) {
                        return SSHInboundWaitOutcome.continueWaiting
                    }
                    throw SSHConnectionError.unexpectedConnectionMessage(
                        expected: .channelOpenConfirmation,
                        received: message.messageID
                    )
                case let .channelOpen(open):
                    try await self.handleIncomingChannelOpenWhileWaiting(open)
                    return SSHInboundWaitOutcome.continueWaiting
                default:
                    if let interleavedLocalChannelID = self.managedSessionLocalChannelIDIfPresent(from: message),
                       self.managedSessionStates[interleavedLocalChannelID] != nil ||
                        self.recentlyCompletedManagedSessionChannelIDs.contains(
                            interleavedLocalChannelID
                        ) {
                        _ = try await self.routeManagedSessionMessage(message)
                        return SSHInboundWaitOutcome.continueWaiting
                    }
                    if self.enqueuePendingPreManagedSessionMessage(from: message) {
                        return SSHInboundWaitOutcome.continueWaiting
                    }

                    throw SSHConnectionError.unexpectedConnectionMessage(
                        expected: .channelOpenConfirmation,
                        received: message.messageID
                    )
                }
            }

            switch outcome {
            case let .value(channel):
                return channel
            case .continueWaiting:
                await Task.yield()
                continue
            }
        }
    }

    func openSessionChannel(
        localInitialWindowSize: UInt32,
        localMaximumPacketSize: UInt32
    ) async throws -> SSHChannel {
        let localChannelID = self.allocateLocalChannelID()
        self.pendingManagedSessionLocalChannelIDs.insert(localChannelID)

        do {
            let latencyStartNanoseconds = self.latencyMeasurementStartNanoseconds()
            try await self.sendConnectionMessage(
                .channelOpen(
                    SSHChannelOpenMessage(
                        channelType: "session",
                        senderChannel: localChannelID,
                        initialWindowSize: localInitialWindowSize,
                        maximumPacketSize: localMaximumPacketSize,
                        channelTypeData: []
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
            return channel
        } catch {
            self.abandonPendingManagedSessionChannel(localChannelID: localChannelID)
            throw error
        }
    }

    func sendChannelRequestAndAwaitReply(
        _ message: SSHConnectionMessage,
        localChannelID: UInt32,
        requestType: String
    ) async throws -> UInt32 {
        let latencyStartNanoseconds = self.latencyMeasurementStartNanoseconds()
        try await self.sendConnectionMessage(message)
        let remoteWindowAdjustment = try await self.receiveChannelRequestReply(
            localChannelID: localChannelID,
            requestType: requestType
        )
        self.recordLatencyMeasurement(
            startedAt: latencyStartNanoseconds,
            source: .channelRequest
        )
        return remoteWindowAdjustment
    }

    func receiveChannelRequestReply(
        localChannelID: UInt32,
        requestType: String
    ) async throws -> UInt32 {
        let timeoutNanoseconds = self.responseTimeoutNanoseconds
        let client = self
        return try await withOptionalTimeout(
            nanoseconds: timeoutNanoseconds,
            timeoutError: SSHTimeoutError.channelRequestReply(
                requestType: requestType,
                durationNanoseconds: timeoutNanoseconds ?? 1
            )
        ) {
            try await client.receiveChannelRequestReplyWithoutTimeout(
                localChannelID: localChannelID,
                requestType: requestType
            )
        }
    }

    private func receiveChannelRequestReplyWithoutTimeout(
        localChannelID: UInt32,
        requestType: String
    ) async throws -> UInt32 {
        var remoteWindowAdjustment: UInt32 = 0

        while true {
            while let pendingReply = self.popPendingChannelRequestReply(
                forLocalChannelID: localChannelID
            ) {
                switch pendingReply {
                case .success:
                    return remoteWindowAdjustment
                case .failure:
                    throw SSHConnectionError.channelRequestFailed(
                        channelID: localChannelID,
                        requestType: requestType
                    )
                case let .windowAdjust(adjust):
                    try self.accumulateRemoteWindowAdjustment(
                        adjust.bytesToAdd,
                        total: &remoteWindowAdjustment,
                        localChannelID: localChannelID
                    )
                }
            }

            try self.checkCancellation()
            if self.activeConnectionMessageWaiterCount > 0 {
                try await self.waitForConnectionMessageWaiterProgress()
                continue
            }

            let outcome: SSHInboundWaitOutcome<UInt32> =
                try await self.withConnectionMessageWaiterTurn {
                let message = try await self.receiveConnectionMessage()
                if try await self.routeManagedSessionMessageIfKnownOrRecentlyCompleted(message) {
                    return .continueWaiting
                }
                switch message {
                case let .channelSuccess(success):
                    guard success.recipientChannel == localChannelID else {
                        self.pendingChannelRequestReplies[success.recipientChannel, default: []]
                            .append(.success(success))
                        return SSHInboundWaitOutcome<UInt32>.continueWaiting
                    }

                    return SSHInboundWaitOutcome.value(remoteWindowAdjustment)
                case let .channelFailure(failure):
                    guard failure.recipientChannel == localChannelID else {
                        self.pendingChannelRequestReplies[failure.recipientChannel, default: []]
                            .append(.failure(failure))
                        return SSHInboundWaitOutcome<UInt32>.continueWaiting
                    }

                    throw SSHConnectionError.channelRequestFailed(
                        channelID: localChannelID,
                        requestType: requestType
                    )
                case let .channelWindowAdjust(adjust):
                    self.pendingChannelRequestReplies[adjust.recipientChannel, default: []].append(
                        .windowAdjust(adjust)
                    )
                    return SSHInboundWaitOutcome<UInt32>.continueWaiting
                case let .channelOpenConfirmation(confirmation):
                    self.pendingChannelOpenResponses[confirmation.recipientChannel] = .confirmation(
                        confirmation
                    )
                    return SSHInboundWaitOutcome<UInt32>.continueWaiting
                case let .channelOpenFailure(failure):
                    self.pendingChannelOpenResponses[failure.recipientChannel] = .failure(
                        failure
                    )
                    return SSHInboundWaitOutcome<UInt32>.continueWaiting
                case let .channelOpen(open):
                    try await self.handleIncomingChannelOpenWhileWaiting(open)
                    return SSHInboundWaitOutcome<UInt32>.continueWaiting
                default:
                    if let interleavedLocalChannelID = self.managedSessionLocalChannelIDIfPresent(
                        from: message
                    ),
                        self.managedSessionStates[interleavedLocalChannelID] != nil ||
                        self.recentlyCompletedManagedSessionChannelIDs.contains(
                            interleavedLocalChannelID
                        ) {
                        _ = try await self.routeManagedSessionMessage(message)
                        return SSHInboundWaitOutcome<UInt32>.continueWaiting
                    }
                    if self.enqueuePendingPreManagedSessionMessage(from: message) {
                        return SSHInboundWaitOutcome<UInt32>.continueWaiting
                    }

                    throw SSHConnectionError.unexpectedConnectionMessage(
                        expected: .channelSuccess,
                        received: message.messageID
                    )
                }
            }

            switch outcome {
            case let .value(adjustment):
                return adjustment
            case .continueWaiting:
                await Task.yield()
                continue
            }
        }
    }

    func registerManagedSession(
        channel: SSHChannel,
        initialRemoteWindowAdjustment: UInt32 = 0,
        outputBufferingMode: SSHSessionOutputBufferingMode = .undecided,
        receiveWindowReplenishThreshold: UInt32
    ) async throws -> SSHSessionHandle {
        var remoteWindowState = SSHSessionRemoteWindowState(
            initialWindowSize: channel.remoteInitialWindowSize,
            maximumPacketSize: channel.remoteMaximumPacketSize
        )
        try remoteWindowState.applyWindowAdjust(
            initialRemoteWindowAdjustment,
            localChannelID: channel.localChannelID
        )

        self.pendingManagedSessionLocalChannelIDs.remove(channel.localChannelID)
        var sessionState = SSHManagedSessionState(
            channel: channel,
            receiveWindowState: SSHSessionReceiveWindowState(
                initialWindowSize: channel.localInitialWindowSize,
                replenishThreshold: receiveWindowReplenishThreshold
            ),
            remoteWindowState: remoteWindowState
        )
        sessionState.outputState.bufferingMode = outputBufferingMode
        self.managedSessionStates[channel.localChannelID] = sessionState
        try await self.replayPendingPreManagedSessionMessages(
            forLocalChannelID: channel.localChannelID
        )
        return SSHSessionHandle(client: self, channel: channel)
    }

    func writeChannelData(
        _ bytes: [UInt8],
        forLocalChannelID localChannelID: UInt32,
        respectCancellation: Bool = true,
        respectTransportSendCancellation: Bool? = nil
    ) async throws {
        try await self.writeManagedSessionChannelBytes(
            bytes,
            forLocalChannelID: localChannelID,
            respectCancellation: respectCancellation,
            respectTransportSendCancellation: respectTransportSendCancellation
        ) { remoteChannelID, chunk in
            .channelData(
                SSHChannelDataMessage(
                    recipientChannel: remoteChannelID,
                    data: chunk
                )
            )
        }
    }

    func writeChannelExtendedData(
        _ bytes: [UInt8],
        dataTypeCode: UInt32,
        forLocalChannelID localChannelID: UInt32,
        respectCancellation: Bool = true,
        respectTransportSendCancellation: Bool? = nil
    ) async throws {
        try await self.writeManagedSessionChannelBytes(
            bytes,
            forLocalChannelID: localChannelID,
            respectCancellation: respectCancellation,
            respectTransportSendCancellation: respectTransportSendCancellation
        ) { remoteChannelID, chunk in
            .channelExtendedData(
                SSHChannelExtendedDataMessage(
                    recipientChannel: remoteChannelID,
                    dataTypeCode: dataTypeCode,
                    data: chunk
                )
            )
        }
    }

    private func writeManagedSessionChannelBytes(
        _ bytes: [UInt8],
        forLocalChannelID localChannelID: UInt32,
        respectCancellation: Bool,
        respectTransportSendCancellation: Bool?,
        makeMessage: (UInt32, [UInt8]) -> SSHConnectionMessage
    ) async throws {
        guard !bytes.isEmpty else {
            return
        }

        try self.beginManagedSessionWrite(forLocalChannelID: localChannelID)
        defer {
            self.endManagedSessionWrite(forLocalChannelID: localChannelID)
        }

        var outboundOffset = 0
        while outboundOffset < bytes.count {
            if respectCancellation {
                try self.checkCancellation()
            }
            var sessionState = try self.requireManagedSessionState(forLocalChannelID: localChannelID)
            guard !sessionState.outputState.didReceiveClose else {
                throw SSHConnectionError.channelClosedBeforeSending(
                    channelID: localChannelID,
                    unsentByteCount: UInt32(bytes.count - outboundOffset)
                )
            }

            let chunkByteCount = sessionState.remoteWindowState.reserveSendChunk(
                remainingByteCount: bytes.count - outboundOffset
            )
            self.managedSessionStates[localChannelID] = sessionState

            if chunkByteCount > 0 {
                let chunk = Array(bytes[outboundOffset..<(outboundOffset + chunkByteCount)])
                try await self.sendConnectionMessage(
                    makeMessage(sessionState.channel.remoteChannelID, chunk),
                    respectCancellation: respectCancellation,
                    respectTransportSendCancellation: respectTransportSendCancellation
                )
                outboundOffset += chunkByteCount
                continue
            }

            _ = try await self.receiveAndRouteManagedSessionMessage(
                respectCancellation: respectCancellation
            )
        }
    }

    func sendChannelEOF(
        forLocalChannelID localChannelID: UInt32,
        respectCancellation: Bool = true
    ) async throws {
        var sessionState = try self.requireManagedSessionState(forLocalChannelID: localChannelID)
        guard !sessionState.outputState.didSendEOF,
              !sessionState.outputState.didReceiveClose else {
            return
        }

        sessionState.outputState.didSendEOF = true
        self.managedSessionStates[localChannelID] = sessionState

        try await self.sendConnectionMessage(
            .channelEOF(
                SSHChannelEOFMessage(recipientChannel: sessionState.channel.remoteChannelID)
            ),
            respectCancellation: respectCancellation,
            respectTransportSendCancellation: respectCancellation
        )
    }

    func closeChannel(
        forLocalChannelID localChannelID: UInt32,
        respectCancellation: Bool = true
    ) async throws {
        var sessionState = try self.requireManagedSessionState(forLocalChannelID: localChannelID)
        guard !sessionState.outputState.didSendClose else {
            self.removeManagedSessionState(forLocalChannelID: localChannelID)
            return
        }

        sessionState.outputState.didSendClose = true
        self.managedSessionStates[localChannelID] = sessionState
        defer {
            self.removeManagedSessionState(forLocalChannelID: localChannelID)
        }

        try await self.sendConnectionMessage(
            .channelClose(
                SSHChannelCloseMessage(recipientChannel: sessionState.channel.remoteChannelID)
            ),
            respectCancellation: respectCancellation
        )
    }

    func resizePseudoTerminal(
        _ windowChange: SSHPseudoTerminalWindowChange,
        forLocalChannelID localChannelID: UInt32
    ) async throws {
        let sessionState = try self.requireManagedSessionState(forLocalChannelID: localChannelID)
        guard !sessionState.outputState.didReceiveClose,
              !sessionState.outputState.didSendClose else {
            return
        }

        try await self.sendConnectionMessage(
            self.sessionRequestCoder.makeWindowChangeRequest(
                recipientChannel: sessionState.channel.remoteChannelID,
                windowChange: windowChange
            ),
            respectTransportSendCancellation: false
        )
    }

    func sendSignal(
        _ signal: SSHSessionSignal,
        forLocalChannelID localChannelID: UInt32
    ) async throws {
        let sessionState = try self.requireManagedSessionState(forLocalChannelID: localChannelID)
        guard !sessionState.outputState.didReceiveClose,
              !sessionState.outputState.didSendClose else {
            return
        }

        try await self.sendConnectionMessage(
            self.sessionRequestCoder.makeSignalRequest(
                recipientChannel: sessionState.channel.remoteChannelID,
                signal: signal
            )
        )
    }

    func channelWindowSnapshot(
        forLocalChannelID localChannelID: UInt32
    ) throws -> SSHChannelWindowSnapshot {
        let sessionState = try self.requireManagedSessionState(forLocalChannelID: localChannelID)
        return self.makeChannelWindowSnapshot(from: sessionState)
    }

    func adjustReceiveWindow(
        by byteCount: UInt32,
        forLocalChannelID localChannelID: UInt32,
        respectCancellation: Bool = true
    ) async throws -> SSHChannelWindowSnapshot {
        if respectCancellation {
            try self.checkCancellation()
        }

        var sessionState = try self.requireManagedSessionState(forLocalChannelID: localChannelID)
        guard !sessionState.outputState.didReceiveClose,
              !sessionState.outputState.didSendClose else {
            throw SSHConnectionError.channelClosedBeforeReceiving(channelID: localChannelID)
        }

        let windowAdjust = try sessionState.receiveWindowState.adjust(
            byteCount: byteCount,
            localChannelID: localChannelID,
            remoteChannelID: sessionState.channel.remoteChannelID
        )
        self.managedSessionStates[localChannelID] = sessionState

        if let windowAdjust {
            try await self.sendConnectionMessage(
                .channelWindowAdjust(windowAdjust),
                respectCancellation: respectCancellation,
                respectTransportSendCancellation: false
            )
        }

        return try self.channelWindowSnapshot(forLocalChannelID: localChannelID)
    }

    func collectSessionTranscript(
        forLocalChannelID localChannelID: UInt32
    ) async throws -> SSHSessionTranscript {
        return try await withTaskCancellationHandler {
            try await self.collectSessionTranscriptUntilClose(
                forLocalChannelID: localChannelID
            )
        } onCancel: {
            Task {
                await self.bestEffortCloseManagedSessionOnCancellation(
                    forLocalChannelID: localChannelID
                )
            }
        }
    }

    private func collectSessionTranscriptUntilClose(
        forLocalChannelID localChannelID: UInt32
    ) async throws -> SSHSessionTranscript {
        while true {
            try self.checkCancellation()
            var sessionState = try self.requireManagedSessionState(forLocalChannelID: localChannelID)
            try sessionState.outputState.activateBufferingMode(
                .transcript,
                channelID: localChannelID
            )
            if sessionState.isComplete {
                self.removeManagedSessionState(forLocalChannelID: localChannelID)
                return sessionState.transcript
            }
            let observationGeneration = sessionState.outputState.observationGeneration
            self.managedSessionStates[localChannelID] = sessionState

            let completedChannelID = try await self.receiveAndRouteManagedSessionMessage()
            if completedChannelID == localChannelID {
                let completedState = try self.requireManagedSessionState(
                    forLocalChannelID: localChannelID
                )
                self.removeManagedSessionState(forLocalChannelID: localChannelID)
                return completedState.transcript
            }
            if self.managedSessionObservationGeneration(
                forLocalChannelID: localChannelID
            ) == observationGeneration {
                await Task.yield()
            }
        }
    }

    private func bestEffortCloseManagedSessionOnCancellation(
        forLocalChannelID localChannelID: UInt32
    ) async {
        do {
            try await self.closeChannel(
                forLocalChannelID: localChannelID,
                respectCancellation: false
            )
        } catch {
            // Transcript cancellation should still surface CancellationError to the caller.
        }
    }

    func readChannelStandardOutputChunk(
        forLocalChannelID localChannelID: UInt32,
        respectCancellation: Bool = true
    ) async throws -> [UInt8]? {
        while true {
            if respectCancellation {
                try self.checkCancellation()
            }
            var sessionState = try self.requireManagedSessionState(forLocalChannelID: localChannelID)
            try sessionState.outputState.activateBufferingMode(
                .standardOutputChunks,
                channelID: localChannelID
            )
            let observationGeneration = sessionState.outputState.observationGeneration

            if !sessionState.outputState.unreadStandardOutput.isEmpty {
                let unreadChunk = sessionState.outputState.unreadStandardOutput
                sessionState.outputState.unreadStandardOutput.removeAll(keepingCapacity: true)
                self.managedSessionStates[localChannelID] = sessionState
                return unreadChunk
            }

            if sessionState.outputState.didReceiveClose {
                self.removeManagedSessionState(forLocalChannelID: localChannelID)
                return nil
            }
            self.managedSessionStates[localChannelID] = sessionState

            _ = try await self.receiveAndRouteManagedSessionMessage(
                respectCancellation: respectCancellation
            )
            if self.managedSessionObservationGeneration(
                forLocalChannelID: localChannelID
            ) == observationGeneration {
                await Task.yield()
            }
        }
    }

    func readSessionEvent(
        forLocalChannelID localChannelID: UInt32,
        respectCancellation: Bool = true
    ) async throws -> SSHSessionEvent? {
        while true {
            if respectCancellation {
                try self.checkCancellation()
            }
            var sessionState = try self.requireManagedSessionState(forLocalChannelID: localChannelID)
            try sessionState.outputState.activateBufferingMode(
                .events,
                channelID: localChannelID
            )
            let observationGeneration = sessionState.outputState.observationGeneration

            if let nextEvent = sessionState.outputState.pendingEvents.first {
                sessionState.outputState.pendingEvents.removeFirst()
                self.managedSessionStates[localChannelID] = sessionState
                return nextEvent
            }

            if sessionState.outputState.didReceiveClose {
                self.removeManagedSessionState(forLocalChannelID: localChannelID)
                return nil
            }
            self.managedSessionStates[localChannelID] = sessionState

            _ = try await self.receiveAndRouteManagedSessionMessage(
                respectCancellation: respectCancellation
            )
            if self.managedSessionObservationGeneration(
                forLocalChannelID: localChannelID
            ) == observationGeneration {
                await Task.yield()
            }
        }
    }

    func beginManagedSessionWrite(forLocalChannelID localChannelID: UInt32) throws {
        var sessionState = try self.requireManagedSessionState(forLocalChannelID: localChannelID)
        guard !sessionState.isWriting else {
            throw SSHConnectionError.concurrentChannelWrite(channelID: localChannelID)
        }

        sessionState.isWriting = true
        self.managedSessionStates[localChannelID] = sessionState
    }

    func endManagedSessionWrite(forLocalChannelID localChannelID: UInt32) {
        guard var sessionState = self.managedSessionStates[localChannelID] else {
            return
        }

        sessionState.isWriting = false
        self.managedSessionStates[localChannelID] = sessionState
    }

    func allocateLocalChannelID() -> UInt32 {
        let channelID = self.nextLocalChannelID
        self.nextLocalChannelID &+= 1
        return channelID
    }

    func receiveWindowReplenishThreshold(for localInitialWindowSize: UInt32) -> UInt32 {
        max(1, localInitialWindowSize / 2)
    }

    private func makeChannelWindowSnapshot(
        from sessionState: SSHManagedSessionState
    ) -> SSHChannelWindowSnapshot {
        SSHChannelWindowSnapshot(
            localChannelID: sessionState.channel.localChannelID,
            remoteChannelID: sessionState.channel.remoteChannelID,
            receiveWindowByteCount: sessionState.receiveWindowState.remainingWindowSize,
            receiveInitialWindowByteCount: sessionState.receiveWindowState.initialWindowSize,
            sendWindowByteCount: sessionState.remoteWindowState.remainingWindowSize,
            sendInitialWindowByteCount: sessionState.remoteWindowState.initialWindowSize,
            sendMaximumPacketByteCount: sessionState.remoteWindowState.maximumPacketSize
        )
    }

    func accumulateRemoteWindowAdjustment(
        _ adjustment: UInt32,
        total: inout UInt32,
        localChannelID: UInt32
    ) throws {
        let (updatedTotal, overflow) = total.addingReportingOverflow(adjustment)
        guard !overflow else {
            throw SSHConnectionError.channelSendWindowOverflow(
                channelID: localChannelID,
                current: total,
                adjustment: adjustment
            )
        }

        total = updatedTotal
    }
}
