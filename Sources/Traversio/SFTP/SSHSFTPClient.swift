// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package actor SSHSFTPClient {
    enum SymbolicLinkWireFormat: Sendable {
        case standard
        case openSSHCompatible
    }

    private final class ResponseRouter {
        enum PendingResponse {
            case awaitingWaiter
            case waiting(CheckedContinuation<SSHSFTPMessage, Error>)
            case buffered(Result<SSHSFTPMessage, Error>)
            case ignoringResponse
        }

        var pendingResponses: [UInt32: PendingResponse] = [:]
        var receiveResponsesTask: Task<Void, Never>?
        var terminalReceiveError: Error?
    }

    static let posixRenameExtensionName = "posix-rename@openssh.com"
    static let statVFSExtensionName = "statvfs@openssh.com"
    static let fstatVFSExtensionName = "fstatvfs@openssh.com"
    static let fsyncExtensionName = "fsync@openssh.com"

    private let session: SSHSessionHandle
    private let packetSerializer: SSHSFTPPacketSerializer
    private let messageSerializer: SSHSFTPMessageSerializer
    private let messageParser: SSHSFTPMessageParser
    private let responseTimeoutNanoseconds: UInt64?
    private var packetParser: SSHSFTPPacketParser
    private var versionExchange: SSHSFTPVersionExchange?
    private var nextRequestID: UInt32 = 0
    private var storedResponseRouter: ResponseRouter?
    private var nextSendTurnWaiterID: UInt64 = 0
    private var isSendingPacket = false
    private var sendTurnWaiters = SSHActorWaiterQueue()

    init(
        session: SSHSessionHandle,
        responseTimeoutNanoseconds: UInt64? = nil,
        packetSerializer: SSHSFTPPacketSerializer = SSHSFTPPacketSerializer(),
        messageSerializer: SSHSFTPMessageSerializer = SSHSFTPMessageSerializer(),
        messageParser: SSHSFTPMessageParser = SSHSFTPMessageParser(),
        packetParser: SSHSFTPPacketParser = SSHSFTPPacketParser()
    ) {
        self.session = session
        self.packetSerializer = packetSerializer
        self.messageSerializer = messageSerializer
        self.messageParser = messageParser
        self.responseTimeoutNanoseconds = responseTimeoutNanoseconds
        self.packetParser = packetParser
    }

    func initialize(clientVersion: UInt32 = 3) async throws -> SSHSFTPVersionExchange {
        if let versionExchange = self.versionExchange {
            return versionExchange
        }

        try await self.send(
            .initialize(SSHSFTPInitializeMessage(version: clientVersion))
        )
        let message = try await self.receiveMessage()
        guard case let .version(versionMessage) = message else {
            throw SSHSFTPError.unexpectedMessage(
                expected: .version,
                received: message.messageID
            )
        }

        let versionExchange = SSHSFTPVersionExchange(
            clientVersion: clientVersion,
            serverVersion: versionMessage.version,
            extensions: versionMessage.extensions
        )
        self.versionExchange = versionExchange
        return versionExchange
    }

    package func currentVersionExchange() throws -> SSHSFTPVersionExchange {
        guard let versionExchange = self.versionExchange else {
            throw SSHSFTPError.versionExchangeRequired
        }
        return versionExchange
    }

    func diagnosticsSnapshot() async -> SSHTransportProtocolDiagnosticsSnapshot {
        await self.session.diagnosticsSnapshot()
    }

    static func symbolicLinkWireFormat(
        for remoteIdentification: String?
    ) -> SymbolicLinkWireFormat {
        guard let remoteIdentification else {
            return .standard
        }

        let folded = remoteIdentification.lowercased()
        if folded.contains("openssh")
            || folded.contains("paramiko")
            || folded.contains("dropbear")
        {
            return .openSSHCompatible
        }

        return .standard
    }

    func currentSymbolicLinkWireFormat() async -> SymbolicLinkWireFormat {
        let snapshot = await self.diagnosticsSnapshot()
        return Self.symbolicLinkWireFormat(for: snapshot.remoteIdentification)
    }

    package func close() async throws {
        self.failPendingResponses(
            using: self.responseRouter(),
            with: SSHSFTPError.channelClosedBeforePacket,
            cancelReceiveLoop: true
        )
        try await self.session.close()
    }

    func send(_ message: SSHSFTPMessage) async throws {
        try self.checkCancellation()
        let payload = self.messageSerializer.serialize(message)
        let packet = try self.packetSerializer.serialize(payload: payload)
        try await self.sendPacket(packet)
        try self.checkCancellation()
    }

    func sendRequest(
        _ message: SSHSFTPMessage,
        requestID: UInt32
    ) async throws -> SSHSFTPMessage {
        try await self.sendRequestWithoutWaiting(
            message,
            requestID: requestID
        )
        return try await self.receiveResponse(for: requestID)
    }

    func sendRequestWithoutWaiting(
        _ message: SSHSFTPMessage,
        requestID: UInt32
    ) async throws {
        let router = self.responseRouter()
        try self.preparePendingResponse(for: requestID, using: router)

        do {
            try await self.send(message)
            self.ensureReceiveLoopStarted()
        } catch {
            router.pendingResponses.removeValue(forKey: requestID)
            throw error
        }
    }

    func sendSerializedRequest(
        _ payload: [UInt8],
        requestID: UInt32
    ) async throws -> SSHSFTPMessage {
        try await self.sendSerializedRequestWithoutWaiting(
            payload,
            requestID: requestID
        )
        return try await self.receiveResponse(for: requestID)
    }

    func sendSerializedRequestWithoutWaiting(
        _ payload: [UInt8],
        requestID: UInt32
    ) async throws {
        let router = self.responseRouter()
        try self.preparePendingResponse(for: requestID, using: router)

        do {
            let packet = try self.packetSerializer.serialize(payload: payload)
            try await self.sendPacket(packet)
            try self.checkCancellation()
            self.ensureReceiveLoopStarted()
        } catch {
            router.pendingResponses.removeValue(forKey: requestID)
            throw error
        }
    }

    func sendReadRequest(
        handle: SSHSFTPHandle,
        offset: UInt64,
        length: UInt32
    ) async throws -> UInt32 {
        let requestID = self.allocateRequestID()
        let message = SSHSFTPMessage.readFile(
            SSHSFTPReadFileMessage(
                requestID: requestID,
                handle: handle,
                offset: offset,
                length: length
            )
        )

        try await self.sendRequestWithoutWaiting(
            message,
            requestID: requestID
        )

        return requestID
    }

    func sendWriteRequest(
        handle: SSHSFTPHandle,
        offset: UInt64,
        data: [UInt8]
    ) async throws -> UInt32 {
        let requestID = self.allocateRequestID()
        let message = SSHSFTPMessage.writeFile(
            SSHSFTPWriteFileMessage(
                requestID: requestID,
                handle: handle,
                offset: offset,
                data: data
            )
        )

        try await self.sendRequestWithoutWaiting(
            message,
            requestID: requestID
        )

        return requestID
    }

    func serializeSymbolicLinkRequest(
        requestID: UInt32,
        targetPath: String,
        linkPath: String,
        wireFormat: SymbolicLinkWireFormat
    ) -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(byte: SSHSFTPMessageID.symbolicLink.rawValue)
        writer.write(uint32: requestID)

        switch wireFormat {
        case .standard:
            writer.write(utf8: linkPath)
            writer.write(utf8: targetPath)
        case .openSSHCompatible:
            writer.write(utf8: targetPath)
            writer.write(utf8: linkPath)
        }

        return writer.bytes
    }

    func maximumWriteDataLength(for handle: SSHSFTPHandle) -> Int {
        let fixedPayloadOverhead = 1 + 4 + 4 + 8 + 4
        let maximumPayloadLength = Int(self.packetSerializer.maximumPacketLength)
        return max(maximumPayloadLength - fixedPayloadOverhead - handle.bytes.count, 1)
    }

    func maximumReadDataLength() -> Int {
        let fixedPayloadOverhead = 1 + 4 + 4
        let maximumPayloadLength = Int(
            min(self.packetSerializer.maximumPacketLength, self.packetParser.maximumPacketLength)
        )
        return max(maximumPayloadLength - fixedPayloadOverhead, 1)
    }

    func effectiveReadLength(_ requestedLength: UInt32) -> UInt32 {
        UInt32(min(max(Int(requestedLength), 1), self.maximumReadDataLength()))
    }

    func receiveReadResponse(
        for requestID: UInt32,
        length: UInt32
    ) async throws -> [UInt8]? {
        let response = try await self.receiveResponse(for: requestID)

        switch response {
        case let .data(dataMessage):
            try self.requireRequestID(
                expected: requestID,
                received: dataMessage.requestID
            )
            guard dataMessage.data.count <= Int(length) else {
                throw SSHSFTPError.unexpectedDataLength(
                    maximum: length,
                    received: UInt32(dataMessage.data.count)
                )
            }
            return dataMessage.data
        case let .status(statusMessage):
            try self.requireRequestID(
                expected: requestID,
                received: statusMessage.requestID
            )
            if statusMessage.statusCode == .endOfFile {
                return nil
            }
            throw SSHSFTPError.status(statusMessage)
        default:
            throw SSHSFTPError.unexpectedMessage(
                expected: .data,
                received: response.messageID
            )
        }
    }

    func receiveWriteResponse(for requestID: UInt32) async throws {
        let response = try await self.receiveResponse(for: requestID)
        try self.requireSuccessfulStatusResponse(response, for: requestID)
    }

    func receiveMessage() async throws -> SSHSFTPMessage {
        let timeoutNanoseconds = self.responseTimeoutNanoseconds
        let client = self
        return try await withOptionalTimeout(
            nanoseconds: timeoutNanoseconds,
            timeoutError: SSHTimeoutError.sftpResponse(
                durationNanoseconds: timeoutNanoseconds ?? 1
            )
        ) {
            try await client.receiveMessageWithoutTimeout()
        }
    }

    func receiveResponse(for requestID: UInt32) async throws -> SSHSFTPMessage {
        let timeoutNanoseconds = self.responseTimeoutNanoseconds
        let client = self
        return try await withOptionalTimeout(
            nanoseconds: timeoutNanoseconds,
            timeoutError: SSHTimeoutError.sftpResponse(
                durationNanoseconds: timeoutNanoseconds ?? 1
            )
        ) {
            try await client.receiveResponseWithoutTimeout(for: requestID)
        }
    }

    private func receiveMessageWithoutTimeout() async throws -> SSHSFTPMessage {
        while true {
            try self.checkCancellation()
            if let payload = try self.packetParser.nextPayload() {
                return try self.messageParser.parse(payload)
            }

            guard let nextChunk = try await self.session.readStandardOutputChunk() else {
                throw SSHSFTPError.channelClosedBeforePacket
            }
            try self.checkCancellation()
            self.packetParser.append(bytes: nextChunk)
        }
    }

    func allocateRequestID() -> UInt32 {
        let requestID = self.nextRequestID
        self.nextRequestID &+= 1
        return requestID
    }

    private func sendPacket(_ packet: [UInt8]) async throws {
        try await self.acquireSendTurn()
        defer {
            self.releaseSendTurn()
        }

        try await self.session.write(packet)
    }

    private func acquireSendTurn() async throws {
        guard self.isSendingPacket else {
            self.isSendingPacket = true
            return
        }

        switch await self.waitOnSendTurnWaiterQueue() {
        case .ready:
            if Task.isCancelled {
                self.releaseSendTurn()
                throw CancellationError()
            }
        case .cancelled:
            throw CancellationError()
        }
    }

    private func releaseSendTurn() {
        guard let continuation = self.sendTurnWaiters.popNext() else {
            self.isSendingPacket = false
            return
        }

        continuation.resume(returning: .ready)
    }

    private func waitOnSendTurnWaiterQueue() async -> SSHActorWaiterResume {
        let waiterID = self.allocateSendTurnWaiterID()
        let client = self

        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                self.sendTurnWaiters.install(
                    waiterID: waiterID,
                    continuation: continuation
                )
            }
        } onCancel: {
            Task {
                await client.cancelSendTurnWaiter(waiterID: waiterID)
            }
        }
    }

    private func allocateSendTurnWaiterID() -> SSHActorWaiterQueue.WaiterID {
        let waiterID = self.nextSendTurnWaiterID
        self.nextSendTurnWaiterID &+= 1
        return waiterID
    }

    private func cancelSendTurnWaiter(waiterID: SSHActorWaiterQueue.WaiterID) {
        guard let continuation = self.sendTurnWaiters.remove(waiterID: waiterID) else {
            return
        }

        continuation.resume(returning: .cancelled)
    }

    private func responseRouter() -> ResponseRouter {
        if let responseRouter = self.storedResponseRouter {
            return responseRouter
        }

        let responseRouter = ResponseRouter()
        self.storedResponseRouter = responseRouter
        return responseRouter
    }

    private func preparePendingResponse(
        for requestID: UInt32,
        using router: ResponseRouter
    ) throws {
        try self.checkCancellation()
        if let terminalReceiveError = router.terminalReceiveError {
            throw terminalReceiveError
        }
        precondition(
            router.pendingResponses[requestID] == nil,
            "pending SFTP response already registered for request \(requestID)"
        )
        router.pendingResponses[requestID] = .awaitingWaiter
    }

    private func receiveResponseWithoutTimeout(for requestID: UInt32) async throws -> SSHSFTPMessage {
        try self.checkCancellation()
        return try await withTaskCancellationHandler {
            try await self.awaitPendingResponse(
                for: requestID,
                using: self.responseRouter()
            )
        } onCancel: {
            let client = self
            Task {
                await client.cancelPendingResponse(for: requestID)
            }
        }
    }

    private func awaitPendingResponse(
        for requestID: UInt32,
        using router: ResponseRouter
    ) async throws -> SSHSFTPMessage {
        if let pending = router.pendingResponses[requestID] {
            switch pending {
            case let .buffered(result):
                router.pendingResponses.removeValue(forKey: requestID)
                return try result.get()
            case .awaitingWaiter:
                return try await withCheckedThrowingContinuation { continuation in
                    router.pendingResponses[requestID] = .waiting(continuation)
                }
            case .ignoringResponse:
                router.pendingResponses.removeValue(forKey: requestID)
                throw CancellationError()
            case .waiting:
                preconditionFailure("duplicate SFTP waiter installed for request \(requestID)")
            }
        }

        if let terminalReceiveError = router.terminalReceiveError {
            throw terminalReceiveError
        }

        throw SSHSFTPError.unexpectedResponseWithoutPendingRequest(received: requestID)
    }

    func cancelPendingResponse(for requestID: UInt32) {
        let router = self.responseRouter()
        switch router.pendingResponses[requestID] {
        case let .waiting(continuation):
            router.pendingResponses[requestID] = .ignoringResponse
            continuation.resume(throwing: CancellationError())
        case .awaitingWaiter:
            router.pendingResponses[requestID] = .ignoringResponse
        case .buffered:
            router.pendingResponses.removeValue(forKey: requestID)
        case .ignoringResponse, nil:
            break
        }
    }

    private func receiveLoopNeedsMoreResponses(using router: ResponseRouter) -> Bool {
        for pendingResponse in router.pendingResponses.values {
            switch pendingResponse {
            case .awaitingWaiter, .waiting, .ignoringResponse:
                return true
            case .buffered:
                continue
            }
        }

        return false
    }

    private func ensureReceiveLoopStarted() {
        let router = self.responseRouter()
        guard router.receiveResponsesTask == nil,
              router.terminalReceiveError == nil,
              self.receiveLoopNeedsMoreResponses(using: router) else {
            return
        }

        let client = self
        router.receiveResponsesTask = Task {
            await client.runReceiveLoop()
        }
    }

    private func runReceiveLoop() async {
        let router = self.responseRouter()
        defer {
            router.receiveResponsesTask = nil
        }

        do {
            while self.receiveLoopNeedsMoreResponses(using: router) {
                let response = try await self.receiveMessageWithoutTimeout()
                try self.routeReceivedResponse(response, using: router)
            }
        } catch is CancellationError {
            self.failPendingResponses(
                using: router,
                with: router.terminalReceiveError ?? SSHSFTPError.channelClosedBeforePacket
            )
        } catch {
            self.failPendingResponses(using: router, with: error)
        }
    }

    private func routeReceivedResponse(
        _ response: SSHSFTPMessage,
        using router: ResponseRouter
    ) throws {
        guard let requestID = response.responseRequestID else {
            throw SSHSFTPError.unexpectedMessage(
                expected: .status,
                received: response.messageID
            )
        }

        switch router.pendingResponses[requestID] {
        case let .waiting(continuation):
            router.pendingResponses.removeValue(forKey: requestID)
            continuation.resume(returning: response)
        case .awaitingWaiter:
            router.pendingResponses[requestID] = .buffered(.success(response))
        case .ignoringResponse:
            router.pendingResponses.removeValue(forKey: requestID)
        case .buffered:
            throw SSHSFTPError.unexpectedResponseWithoutPendingRequest(received: requestID)
        case nil:
            throw SSHSFTPError.unexpectedResponseWithoutPendingRequest(received: requestID)
        }
    }

    private func failPendingResponses(
        using router: ResponseRouter,
        with error: Error,
        cancelReceiveLoop: Bool = false
    ) {
        if cancelReceiveLoop {
            router.receiveResponsesTask?.cancel()
            router.receiveResponsesTask = nil
        }

        if router.terminalReceiveError == nil {
            router.terminalReceiveError = error
        }
        let terminalReceiveError = router.terminalReceiveError ?? error

        for requestID in Array(router.pendingResponses.keys) {
            switch router.pendingResponses[requestID] {
            case let .waiting(continuation):
                router.pendingResponses.removeValue(forKey: requestID)
                continuation.resume(throwing: terminalReceiveError)
            case .awaitingWaiter:
                router.pendingResponses[requestID] = .buffered(.failure(terminalReceiveError))
            case .buffered:
                break
            case .ignoringResponse:
                router.pendingResponses.removeValue(forKey: requestID)
            case nil:
                break
            }
        }
    }

    func receiveStatusResponse(
        _ response: SSHSFTPMessage,
        for requestID: UInt32
    ) throws -> SSHSFTPStatusMessage {
        guard case let .status(statusMessage) = response else {
            throw SSHSFTPError.unexpectedMessage(
                expected: .status,
                received: response.messageID
            )
        }
        try self.requireRequestID(
            expected: requestID,
            received: statusMessage.requestID
        )
        return statusMessage
    }

    func requireSuccessfulStatusResponse(
        _ response: SSHSFTPMessage,
        for requestID: UInt32
    ) throws {
        let statusMessage = try self.receiveStatusResponse(response, for: requestID)
        guard statusMessage.statusCode == .ok else {
            throw SSHSFTPError.status(statusMessage)
        }
    }

    func requireRequestID(expected: UInt32, received: UInt32) throws {
        guard expected == received else {
            throw SSHSFTPError.unexpectedResponseRequestID(
                expected: expected,
                received: received
            )
        }
    }

    func requireSupportedExtension(
        named name: String,
        minimumVersion: UInt32
    ) throws {
        let versionExchange = try self.currentVersionExchange()
        guard versionExchange.supportsExtension(named: name, minimumVersion: minimumVersion) else {
            throw SSHSFTPError.unsupportedExtendedRequest(name)
        }
    }

    func parseFileSystemAttributes(
        from bytes: [UInt8]
    ) throws -> SSHSFTPFileSystemAttributes {
        var reader = SSHWireReader(bytes: bytes)
        let attributes = try SSHSFTPFileSystemAttributes(
            blockSize: reader.readUInt64(),
            fundamentalBlockSize: reader.readUInt64(),
            totalBlocks: reader.readUInt64(),
            freeBlocks: reader.readUInt64(),
            availableBlocks: reader.readUInt64(),
            totalFileNodes: reader.readUInt64(),
            freeFileNodes: reader.readUInt64(),
            availableFileNodes: reader.readUInt64(),
            fileSystemID: reader.readUInt64(),
            flags: SSHSFTPFileSystemFlags(rawValue: reader.readUInt64()),
            maximumFilenameLength: reader.readUInt64()
        )
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return attributes
    }

    func checkCancellation() throws {
        try Task.checkCancellation()
    }
}

extension SSHTransportProtocolClient {
    func openSFTPSubsystemSession(
        localInitialWindowSize: UInt32 = 1_048_576,
        localMaximumPacketSize: UInt32 = 32_768
    ) async throws -> SSHSessionHandle {
        try await self.openSubsystemSession(
            subsystem: "sftp",
            localInitialWindowSize: localInitialWindowSize,
            localMaximumPacketSize: localMaximumPacketSize,
            outputBufferingMode: .standardOutputChunks
        )
    }

    package func openSFTPClient(
        clientVersion: UInt32 = 3,
        localInitialWindowSize: UInt32 = 1_048_576,
        localMaximumPacketSize: UInt32 = 32_768
    ) async throws -> SSHSFTPClient {
        let session = try await self.openSFTPSubsystemSession(
            localInitialWindowSize: localInitialWindowSize,
            localMaximumPacketSize: localMaximumPacketSize
        )
        let client = SSHSFTPClient(
            session: session,
            responseTimeoutNanoseconds: self.responseTimeoutNanoseconds
        )
        _ = try await client.initialize(clientVersion: clientVersion)
        return client
    }
}
