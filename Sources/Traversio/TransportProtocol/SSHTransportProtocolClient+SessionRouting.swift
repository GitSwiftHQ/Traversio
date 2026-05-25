// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

extension SSHTransportProtocolClient {
    // Keep interleaved session routing in one place so waiter code can focus on its expected reply.
    func routeManagedSessionMessage(
        _ message: SSHConnectionMessage,
        respectCancellation: Bool = false
    ) async throws -> UInt32? {
        let localChannelID = try self.extractManagedSessionLocalChannelID(from: message)
        guard var sessionState = self.managedSessionStates[localChannelID] else {
            if self.shouldIgnoreLateManagedSessionMessage(
                message,
                forRecentlyCompletedLocalChannelID: localChannelID
            ) {
                return nil
            }

            throw SSHConnectionError.unknownChannel(channelID: localChannelID)
        }
        let action = try self.processSessionMessage(
            message,
            sessionState: &sessionState
        )
        self.managedSessionStates[localChannelID] = sessionState

        switch action {
        case .none:
            return nil
        case let .sendChannelSuccess(success):
            try await self.sendConnectionMessage(
                .channelSuccess(success),
                respectCancellation: respectCancellation,
                respectTransportSendCancellation: respectCancellation
            )
            return nil
        case let .sendChannelFailure(failure):
            try await self.sendConnectionMessage(
                .channelFailure(failure),
                respectCancellation: respectCancellation,
                respectTransportSendCancellation: respectCancellation
            )
            return nil
        case let .sendWindowAdjust(windowAdjust):
            try await self.sendConnectionMessage(
                .channelWindowAdjust(windowAdjust),
                respectCancellation: respectCancellation,
                respectTransportSendCancellation: respectCancellation
            )
            return nil
        case .sendClose:
            sessionState.outputState.didSendClose = true
            self.managedSessionStates[localChannelID] = sessionState
            try await self.sendConnectionMessage(
                .channelClose(
                    SSHChannelCloseMessage(
                        recipientChannel: sessionState.channel.remoteChannelID
                    )
                ),
                respectCancellation: respectCancellation,
                respectTransportSendCancellation: respectCancellation
            )
            return localChannelID
        case .complete:
            return localChannelID
        }
    }

    func routeManagedSessionMessageIfKnownOrRecentlyCompleted(
        _ message: SSHConnectionMessage,
        respectCancellation: Bool = false
    ) async throws -> Bool {
        guard let localChannelID = self.managedSessionLocalChannelIDIfPresent(from: message),
              self.managedSessionStates[localChannelID] != nil ||
                self.recentlyCompletedManagedSessionChannelIDs.contains(localChannelID) else {
            return false
        }

        _ = try await self.routeManagedSessionMessage(
            message,
            respectCancellation: respectCancellation
        )
        return true
    }

    func receiveAndRouteManagedSessionMessage(
        respectCancellation: Bool = true
    ) async throws -> UInt32? {
        while true {
            if respectCancellation {
                try self.checkCancellation()
            }
            if self.activeConnectionMessageWaiterCount > 0 {
                try await self.waitForConnectionMessageWaiterProgress(
                    respectCancellation: respectCancellation
                )
                return nil
            }

            let outcome: SSHInboundWaitOutcome<UInt32?>
            do {
                outcome = try await self.withConnectionMessageWaiterTurn {
                    let message = try await self.receiveConnectionMessage(
                        allowingGlobalRequestReply: true,
                        respectingTransportReceiveCancellation: false
                    )
                    switch message {
                    case let .channelOpen(open):
                        try await self.handleIncomingChannelOpenWhileWaiting(open)
                        return .value(nil)
                    case .requestSuccess, .requestFailure:
                        self.appendPendingGlobalRequestReply(message)
                        return .value(nil)
                    default:
                        if let localChannelID = self.managedSessionLocalChannelIDIfPresent(
                            from: message
                        ),
                            self.managedSessionStates[localChannelID] != nil ||
                            self.recentlyCompletedManagedSessionChannelIDs.contains(
                                localChannelID
                            ) {
                            return SSHInboundWaitOutcome.value(
                                try await self.routeManagedSessionMessage(
                                    message,
                                    respectCancellation: false
                                )
                            )
                        }
                        if self.enqueuePendingChannelOpenResponse(from: message) ||
                            self.enqueuePendingChannelRequestReply(from: message) ||
                            self.enqueuePendingPreManagedSessionMessage(from: message) {
                            return .value(nil)
                        }

                        throw SSHConnectionError.unexpectedConnectionMessage(
                            expected: .channelData,
                            received: message.messageID
                        )
                    }
                }
            } catch {
                if respectCancellation && Task.isCancelled {
                    throw CancellationError()
                }
                throw error
            }

            switch outcome {
            case let .value(localChannelID):
                return localChannelID
            case .continueWaiting:
                continue
            }
        }
    }

    func flushDeferredConnectionMessagesAfterTransportRekey() async throws {
        guard !self.deferredConnectionMessagesDuringTransportRekey.isEmpty else {
            return
        }

        let deferredMessages = self.deferredConnectionMessagesDuringTransportRekey
        self.deferredConnectionMessagesDuringTransportRekey.removeAll(keepingCapacity: true)

        guard self.activeConnectionMessageWaiterCount == 0 else {
            self.pendingConnectionMessagesAfterTransportRekey.append(contentsOf: deferredMessages)
            return
        }

        for message in deferredMessages {
            switch message {
            case let .globalRequest(request):
                if request.wantReply {
                    try await self.sendConnectionMessage(
                        .requestFailure(SSHGlobalRequestFailureMessage())
                    )
                }
            case .requestSuccess, .requestFailure:
                self.appendPendingGlobalRequestReply(message)
            case let .channelOpen(open):
                try await self.handleIncomingChannelOpenWhileWaiting(open)
            default:
                if let localChannelID = self.managedSessionLocalChannelIDIfPresent(from: message),
                   self.managedSessionStates[localChannelID] != nil ||
                    self.recentlyCompletedManagedSessionChannelIDs.contains(localChannelID) {
                    _ = try await self.routeManagedSessionMessage(message)
                    continue
                }
                if self.enqueuePendingChannelOpenResponse(from: message) ||
                    self.enqueuePendingChannelRequestReply(from: message) ||
                    self.enqueuePendingPreManagedSessionMessage(from: message) {
                    continue
                }

                throw SSHConnectionError.unexpectedConnectionMessage(
                    expected: .channelData,
                    received: message.messageID
                )
            }
        }
    }

    func popPendingConnectionMessageAfterTransportRekey() -> SSHConnectionMessage? {
        guard !self.pendingConnectionMessagesAfterTransportRekey.isEmpty else {
            return nil
        }

        return self.pendingConnectionMessagesAfterTransportRekey.removeFirst()
    }

    func extractManagedSessionLocalChannelID(
        from message: SSHConnectionMessage
    ) throws -> UInt32 {
        guard let localChannelID = self.managedSessionLocalChannelIDIfPresent(from: message) else {
            throw SSHConnectionError.unexpectedConnectionMessage(
                expected: .channelData,
                received: message.messageID
            )
        }

        return localChannelID
    }

    func managedSessionLocalChannelIDIfPresent(
        from message: SSHConnectionMessage
    ) -> UInt32? {
        switch message {
        case let .channelData(data):
            return data.recipientChannel
        case let .channelExtendedData(data):
            return data.recipientChannel
        case let .channelRequest(request):
            return request.recipientChannel
        case let .channelEOF(eof):
            return eof.recipientChannel
        case let .channelClose(close):
            return close.recipientChannel
        case let .channelWindowAdjust(adjust):
            return adjust.recipientChannel
        case let .channelSuccess(success):
            return success.recipientChannel
        case let .channelFailure(failure):
            return failure.recipientChannel
        default:
            return nil
        }
    }

    func popPendingChannelOpenResponse(
        forLocalChannelID localChannelID: UInt32
    ) -> SSHPendingChannelOpenResponse? {
        self.pendingChannelOpenResponses.removeValue(forKey: localChannelID)
    }

    func popPendingChannelRequestReply(
        forLocalChannelID localChannelID: UInt32
    ) -> SSHPendingChannelRequestReply? {
        guard var pendingReplies = self.pendingChannelRequestReplies[localChannelID],
              !pendingReplies.isEmpty else {
            return nil
        }

        let pendingReply = pendingReplies.removeFirst()
        if pendingReplies.isEmpty {
            self.pendingChannelRequestReplies.removeValue(forKey: localChannelID)
        } else {
            self.pendingChannelRequestReplies[localChannelID] = pendingReplies
        }

        return pendingReply
    }

    func replayPendingPreManagedSessionMessages(
        forLocalChannelID localChannelID: UInt32
    ) async throws {
        guard let pendingMessages = self.pendingPreManagedSessionMessages.removeValue(
            forKey: localChannelID
        ) else {
            return
        }

        for message in pendingMessages {
            _ = try await self.routeManagedSessionMessage(message)
        }
    }

    func removeManagedSessionState(
        forLocalChannelID localChannelID: UInt32
    ) {
        guard self.managedSessionStates.removeValue(forKey: localChannelID) != nil else {
            return
        }

        self.recentlyCompletedManagedSessionChannelIDs.insert(localChannelID)
        self.recentlyCompletedManagedSessionChannelIDOrder.append(localChannelID)

        if self.recentlyCompletedManagedSessionChannelIDOrder.count >
            Self.maximumRecentlyCompletedManagedSessionChannelIDs {
            let evictedLocalChannelID =
                self.recentlyCompletedManagedSessionChannelIDOrder.removeFirst()
            self.recentlyCompletedManagedSessionChannelIDs.remove(evictedLocalChannelID)
        }
    }

    func shouldIgnoreLateManagedSessionMessage(
        _ message: SSHConnectionMessage,
        forRecentlyCompletedLocalChannelID localChannelID: UInt32
    ) -> Bool {
        guard self.recentlyCompletedManagedSessionChannelIDs.contains(localChannelID) else {
            return false
        }

        switch message {
        case .channelData, .channelExtendedData, .channelRequest, .channelEOF, .channelClose, .channelWindowAdjust,
             .channelSuccess, .channelFailure:
            return true
        default:
            return false
        }
    }

    func enqueuePendingChannelOpenResponse(
        from message: SSHConnectionMessage
    ) -> Bool {
        switch message {
        case let .channelOpenConfirmation(confirmation):
            self.pendingChannelOpenResponses[confirmation.recipientChannel] = .confirmation(
                confirmation
            )
            return true
        case let .channelOpenFailure(failure):
            self.pendingChannelOpenResponses[failure.recipientChannel] = .failure(failure)
            return true
        default:
            return false
        }
    }

    func enqueuePendingChannelRequestReply(
        from message: SSHConnectionMessage
    ) -> Bool {
        switch message {
        case let .channelWindowAdjust(adjust):
            self.pendingChannelRequestReplies[adjust.recipientChannel, default: []].append(
                .windowAdjust(adjust)
            )
            return true
        case let .channelSuccess(success):
            self.pendingChannelRequestReplies[success.recipientChannel, default: []].append(
                .success(success)
            )
            return true
        case let .channelFailure(failure):
            self.pendingChannelRequestReplies[failure.recipientChannel, default: []].append(
                .failure(failure)
            )
            return true
        default:
            return false
        }
    }

    func enqueuePendingPreManagedSessionMessage(
        from message: SSHConnectionMessage
    ) -> Bool {
        guard let localChannelID = self.managedSessionLocalChannelIDIfPresent(from: message),
              self.managedSessionStates[localChannelID] == nil,
              self.pendingManagedSessionLocalChannelIDs.contains(localChannelID) else {
            return false
        }

        switch message {
        case .channelData, .channelExtendedData, .channelRequest, .channelEOF, .channelClose:
            self.pendingPreManagedSessionMessages[localChannelID, default: []].append(message)
            return true
        default:
            return false
        }
    }

    func abandonPendingManagedSessionChannel(localChannelID: UInt32) {
        self.pendingManagedSessionLocalChannelIDs.remove(localChannelID)
        self.pendingChannelOpenResponses.removeValue(forKey: localChannelID)
        self.pendingChannelRequestReplies.removeValue(forKey: localChannelID)
        self.pendingPreManagedSessionMessages.removeValue(forKey: localChannelID)
    }

    func requireManagedSessionState(
        forLocalChannelID localChannelID: UInt32
    ) throws -> SSHManagedSessionState {
        guard let sessionState = self.managedSessionStates[localChannelID] else {
            throw SSHConnectionError.unknownChannel(channelID: localChannelID)
        }

        return sessionState
    }

    func managedSessionObservationGeneration(
        forLocalChannelID localChannelID: UInt32
    ) -> UInt64? {
        self.managedSessionStates[localChannelID]?.outputState.observationGeneration
    }

    func processSessionMessage(
        _ message: SSHConnectionMessage,
        sessionState: inout SSHManagedSessionState
    ) throws -> SSHSessionMessageAction {
        let channel = sessionState.channel
        switch message {
        case let .channelData(data):
            guard data.recipientChannel == channel.localChannelID else {
                throw SSHConnectionError.unexpectedChannelMessage(
                    expected: channel.localChannelID,
                    received: data.recipientChannel
                )
            }
            let windowAdjust = try sessionState.receiveWindowState.consume(
                byteCount: data.data.count,
                localChannelID: channel.localChannelID,
                remoteChannelID: channel.remoteChannelID
            )
            sessionState.outputState.appendStandardOutput(data.data)
            if let windowAdjust {
                return .sendWindowAdjust(windowAdjust)
            }
            return .none
        case let .channelExtendedData(data):
            guard data.recipientChannel == channel.localChannelID else {
                throw SSHConnectionError.unexpectedChannelMessage(
                    expected: channel.localChannelID,
                    received: data.recipientChannel
                )
            }
            let windowAdjust = try sessionState.receiveWindowState.consume(
                byteCount: data.data.count,
                localChannelID: channel.localChannelID,
                remoteChannelID: channel.remoteChannelID
            )
            if data.dataTypeCode == SSHChannelExtendedDataMessage.standardErrorDataTypeCode {
                sessionState.outputState.appendStandardError(data.data)
            }
            if let windowAdjust {
                return .sendWindowAdjust(windowAdjust)
            }
            return .none
        case let .channelRequest(request):
            guard request.recipientChannel == channel.localChannelID else {
                throw SSHConnectionError.unexpectedChannelMessage(
                    expected: channel.localChannelID,
                    received: request.recipientChannel
                )
            }
            var acceptedRequest = false
            if request.requestType == "exit-status" {
                let exitStatus = try self.sessionRequestCoder.parseExitStatus(
                    from: request
                )
                sessionState.outputState.recordExitStatus(exitStatus)
                acceptedRequest = true
            } else if request.requestType == "exit-signal" {
                let exitSignal = try self.sessionRequestCoder.parseExitSignal(
                    from: request
                )
                sessionState.outputState.recordExitSignal(exitSignal)
                acceptedRequest = true
            }

            guard request.wantReply else {
                return .none
            }

            if acceptedRequest {
                return .sendChannelSuccess(
                    SSHChannelSuccessMessage(recipientChannel: channel.remoteChannelID)
                )
            }

            return .sendChannelFailure(
                SSHChannelFailureMessage(recipientChannel: channel.remoteChannelID)
            )
        case let .channelEOF(eof):
            guard eof.recipientChannel == channel.localChannelID else {
                throw SSHConnectionError.unexpectedChannelMessage(
                    expected: channel.localChannelID,
                    received: eof.recipientChannel
                )
            }
            sessionState.outputState.recordEndOfFile()
            return .none
        case let .channelClose(close):
            guard close.recipientChannel == channel.localChannelID else {
                throw SSHConnectionError.unexpectedChannelMessage(
                    expected: channel.localChannelID,
                    received: close.recipientChannel
                )
            }
            sessionState.outputState.recordClose()
            return sessionState.outputState.didSendClose ? .complete : .sendClose
        case let .channelWindowAdjust(adjust):
            guard adjust.recipientChannel == channel.localChannelID else {
                throw SSHConnectionError.unexpectedChannelMessage(
                    expected: channel.localChannelID,
                    received: adjust.recipientChannel
                )
            }
            try sessionState.remoteWindowState.applyWindowAdjust(
                adjust.bytesToAdd,
                localChannelID: channel.localChannelID
            )
            return .none
        case let .channelSuccess(success):
            guard success.recipientChannel == channel.localChannelID else {
                throw SSHConnectionError.unexpectedChannelMessage(
                    expected: channel.localChannelID,
                    received: success.recipientChannel
                )
            }
            return .none
        case let .channelFailure(failure):
            guard failure.recipientChannel == channel.localChannelID else {
                throw SSHConnectionError.unexpectedChannelMessage(
                    expected: channel.localChannelID,
                    received: failure.recipientChannel
                )
            }
            return .none
        default:
            throw SSHConnectionError.unexpectedConnectionMessage(
                expected: .channelData,
                received: message.messageID
            )
        }
    }
}
