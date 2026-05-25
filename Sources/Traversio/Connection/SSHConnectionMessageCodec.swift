// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

struct SSHConnectionMessageSerializer: Sendable {
    func serialize(_ message: SSHConnectionMessage) throws -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(byte: message.messageID.rawValue)

        switch message {
        case let .globalRequest(payload):
            writer.write(utf8: payload.requestName)
            writer.write(boolean: payload.wantReply)
            writer.write(rawBytes: payload.requestData)
        case let .requestSuccess(payload):
            writer.write(rawBytes: payload.responseData)
        case .requestFailure:
            break
        case let .channelOpen(payload):
            writer.write(utf8: payload.channelType)
            writer.write(uint32: payload.senderChannel)
            writer.write(uint32: payload.initialWindowSize)
            writer.write(uint32: payload.maximumPacketSize)
            writer.write(rawBytes: payload.channelTypeData)
        case let .channelOpenConfirmation(payload):
            writer.write(uint32: payload.recipientChannel)
            writer.write(uint32: payload.senderChannel)
            writer.write(uint32: payload.initialWindowSize)
            writer.write(uint32: payload.maximumPacketSize)
            writer.write(rawBytes: payload.channelTypeData)
        case let .channelOpenFailure(payload):
            writer.write(uint32: payload.recipientChannel)
            writer.write(uint32: payload.reasonCode.rawValue)
            writer.write(utf8: payload.description)
            writer.write(utf8: payload.languageTag)
        case let .channelWindowAdjust(payload):
            writer.write(uint32: payload.recipientChannel)
            writer.write(uint32: payload.bytesToAdd)
        case let .channelData(payload):
            writer.write(uint32: payload.recipientChannel)
            writer.write(string: payload.data)
        case let .channelExtendedData(payload):
            writer.write(uint32: payload.recipientChannel)
            writer.write(uint32: payload.dataTypeCode)
            writer.write(string: payload.data)
        case let .channelEOF(payload):
            writer.write(uint32: payload.recipientChannel)
        case let .channelClose(payload):
            writer.write(uint32: payload.recipientChannel)
        case let .channelRequest(payload):
            writer.write(uint32: payload.recipientChannel)
            writer.write(utf8: payload.requestType)
            writer.write(boolean: payload.wantReply)
            writer.write(rawBytes: payload.requestData)
        case let .channelSuccess(payload):
            writer.write(uint32: payload.recipientChannel)
        case let .channelFailure(payload):
            writer.write(uint32: payload.recipientChannel)
        }

        return writer.bytes
    }
}

struct SSHConnectionMessageParser: Sendable {
    func parse(_ bytes: [UInt8]) throws -> SSHConnectionMessage {
        var reader = SSHWireReader(bytes: bytes)
        let rawMessageType = try reader.readByte()

        guard let messageID = SSHConnectionMessageID(rawValue: rawMessageType) else {
            throw SSHWireError.unknownMessageType(rawMessageType)
        }

        let message: SSHConnectionMessage
        switch messageID {
        case .globalRequest:
            message = try .globalRequest(
                SSHGlobalRequestMessage(
                    requestName: reader.readUTF8String(),
                    wantReply: reader.readBoolean(),
                    requestData: reader.readRawBytes(count: reader.remainingByteCount)
                )
            )
        case .requestSuccess:
            message = try .requestSuccess(
                SSHGlobalRequestSuccessMessage(
                    responseData: reader.readRawBytes(count: reader.remainingByteCount)
                )
            )
        case .requestFailure:
            message = .requestFailure(SSHGlobalRequestFailureMessage())
        case .channelOpen:
            message = try .channelOpen(
                SSHChannelOpenMessage(
                    channelType: reader.readUTF8String(),
                    senderChannel: reader.readUInt32(),
                    initialWindowSize: reader.readUInt32(),
                    maximumPacketSize: reader.readUInt32(),
                    channelTypeData: reader.readRawBytes(count: reader.remainingByteCount)
                )
            )
        case .channelOpenConfirmation:
            message = try .channelOpenConfirmation(
                SSHChannelOpenConfirmationMessage(
                    recipientChannel: reader.readUInt32(),
                    senderChannel: reader.readUInt32(),
                    initialWindowSize: reader.readUInt32(),
                    maximumPacketSize: reader.readUInt32(),
                    channelTypeData: reader.readRawBytes(count: reader.remainingByteCount)
                )
            )
        case .channelOpenFailure:
            message = try .channelOpenFailure(
                SSHChannelOpenFailureMessage(
                    recipientChannel: reader.readUInt32(),
                    reasonCode: SSHChannelOpenFailureReasonCode(rawValue: reader.readUInt32()),
                    description: reader.readUTF8String(),
                    languageTag: reader.readUTF8String()
                )
            )
        case .channelWindowAdjust:
            message = try .channelWindowAdjust(
                SSHChannelWindowAdjustMessage(
                    recipientChannel: reader.readUInt32(),
                    bytesToAdd: reader.readUInt32()
                )
            )
        case .channelData:
            message = try .channelData(
                SSHChannelDataMessage(
                    recipientChannel: reader.readUInt32(),
                    data: reader.readString()
                )
            )
        case .channelExtendedData:
            message = try .channelExtendedData(
                SSHChannelExtendedDataMessage(
                    recipientChannel: reader.readUInt32(),
                    dataTypeCode: reader.readUInt32(),
                    data: reader.readString()
                )
            )
        case .channelEOF:
            message = try .channelEOF(
                SSHChannelEOFMessage(recipientChannel: reader.readUInt32())
            )
        case .channelClose:
            message = try .channelClose(
                SSHChannelCloseMessage(recipientChannel: reader.readUInt32())
            )
        case .channelRequest:
            message = try .channelRequest(
                SSHChannelRequestMessage(
                    recipientChannel: reader.readUInt32(),
                    requestType: reader.readUTF8String(),
                    wantReply: reader.readBoolean(),
                    requestData: reader.readRawBytes(count: reader.remainingByteCount)
                )
            )
        case .channelSuccess:
            message = try .channelSuccess(
                SSHChannelSuccessMessage(recipientChannel: reader.readUInt32())
            )
        case .channelFailure:
            message = try .channelFailure(
                SSHChannelFailureMessage(recipientChannel: reader.readUInt32())
            )
        }

        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }

        return message
    }
}

struct SSHSessionRequestCoder: Sendable {
    func makeEnvironmentRequest(
        recipientChannel: UInt32,
        environmentVariable: SSHSessionEnvironmentVariable,
        wantReply: Bool = true
    ) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(utf8: environmentVariable.name)
        writer.write(utf8: environmentVariable.value)

        return .channelRequest(
            SSHChannelRequestMessage(
                recipientChannel: recipientChannel,
                requestType: "env",
                wantReply: wantReply,
                requestData: writer.bytes
            )
        )
    }

    func parseEnvironmentRequest(
        from message: SSHChannelRequestMessage
    ) throws -> SSHSessionEnvironmentVariable {
        guard message.requestType == "env" else {
            throw SSHConnectionError.invalidChannelRequest(message.requestType)
        }

        var reader = SSHWireReader(bytes: message.requestData)
        let environmentVariable = try SSHSessionEnvironmentVariable(
            name: reader.readUTF8String(),
            value: reader.readUTF8String()
        )
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return environmentVariable
    }

    func makePseudoTerminalRequest(
        recipientChannel: UInt32,
        request: SSHPseudoTerminalRequest,
        wantReply: Bool = true
    ) throws -> SSHConnectionMessage {
        guard !request.encodedTerminalModes.isEmpty,
              request.encodedTerminalModes.last == 0 else {
            throw SSHConnectionError.invalidPseudoTerminalModes
        }

        var writer = SSHWireWriter()
        writer.write(utf8: request.terminalType)
        writer.write(uint32: request.characterWidth)
        writer.write(uint32: request.characterHeight)
        writer.write(uint32: request.pixelWidth)
        writer.write(uint32: request.pixelHeight)
        writer.write(string: request.encodedTerminalModes)

        return .channelRequest(
            SSHChannelRequestMessage(
                recipientChannel: recipientChannel,
                requestType: "pty-req",
                wantReply: wantReply,
                requestData: writer.bytes
            )
        )
    }

    func parsePseudoTerminalRequest(
        from message: SSHChannelRequestMessage
    ) throws -> SSHPseudoTerminalRequest {
        guard message.requestType == "pty-req" else {
            throw SSHConnectionError.invalidChannelRequest(message.requestType)
        }

        var reader = SSHWireReader(bytes: message.requestData)
        let request = try SSHPseudoTerminalRequest(
            terminalType: reader.readUTF8String(),
            characterWidth: reader.readUInt32(),
            characterHeight: reader.readUInt32(),
            pixelWidth: reader.readUInt32(),
            pixelHeight: reader.readUInt32(),
            encodedTerminalModes: reader.readString()
        )
        guard !request.encodedTerminalModes.isEmpty,
              request.encodedTerminalModes.last == 0 else {
            throw SSHConnectionError.invalidPseudoTerminalModes
        }
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return request
    }

    func makeShellRequest(
        recipientChannel: UInt32,
        wantReply: Bool = true
    ) -> SSHConnectionMessage {
        .channelRequest(
            SSHChannelRequestMessage(
                recipientChannel: recipientChannel,
                requestType: "shell",
                wantReply: wantReply,
                requestData: []
            )
        )
    }

    func parseShellRequest(from message: SSHChannelRequestMessage) throws {
        guard message.requestType == "shell" else {
            throw SSHConnectionError.invalidChannelRequest(message.requestType)
        }
        guard message.requestData.isEmpty else {
            throw SSHWireError.trailingMessageBytes(message.requestData.count)
        }
    }

    func makeSubsystemRequest(
        recipientChannel: UInt32,
        subsystem: String,
        wantReply: Bool = true
    ) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(utf8: subsystem)

        return .channelRequest(
            SSHChannelRequestMessage(
                recipientChannel: recipientChannel,
                requestType: "subsystem",
                wantReply: wantReply,
                requestData: writer.bytes
            )
        )
    }

    func parseSubsystemRequest(from message: SSHChannelRequestMessage) throws -> String {
        guard message.requestType == "subsystem" else {
            throw SSHConnectionError.invalidChannelRequest(message.requestType)
        }

        var reader = SSHWireReader(bytes: message.requestData)
        let subsystem = try reader.readUTF8String()
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return subsystem
    }

    func makeExecRequest(recipientChannel: UInt32, command: String, wantReply: Bool = true) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(utf8: command)

        return .channelRequest(
            SSHChannelRequestMessage(
                recipientChannel: recipientChannel,
                requestType: "exec",
                wantReply: wantReply,
                requestData: writer.bytes
            )
        )
    }

    func parseExecCommand(from message: SSHChannelRequestMessage) throws -> String {
        guard message.requestType == "exec" else {
            throw SSHConnectionError.invalidChannelRequest(message.requestType)
        }

        var reader = SSHWireReader(bytes: message.requestData)
        let command = try reader.readUTF8String()
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return command
    }

    func makeWindowChangeRequest(
        recipientChannel: UInt32,
        windowChange: SSHPseudoTerminalWindowChange
    ) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(uint32: windowChange.characterWidth)
        writer.write(uint32: windowChange.characterHeight)
        writer.write(uint32: windowChange.pixelWidth)
        writer.write(uint32: windowChange.pixelHeight)

        return .channelRequest(
            SSHChannelRequestMessage(
                recipientChannel: recipientChannel,
                requestType: "window-change",
                wantReply: false,
                requestData: writer.bytes
            )
        )
    }

    func parseWindowChangeRequest(
        from message: SSHChannelRequestMessage
    ) throws -> SSHPseudoTerminalWindowChange {
        guard message.requestType == "window-change" else {
            throw SSHConnectionError.invalidChannelRequest(message.requestType)
        }

        var reader = SSHWireReader(bytes: message.requestData)
        let windowChange = try SSHPseudoTerminalWindowChange(
            characterWidth: reader.readUInt32(),
            characterHeight: reader.readUInt32(),
            pixelWidth: reader.readUInt32(),
            pixelHeight: reader.readUInt32()
        )
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return windowChange
    }

    func makeSignalRequest(
        recipientChannel: UInt32,
        signal: SSHSessionSignal
    ) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(utf8: signal.rawValue)

        return .channelRequest(
            SSHChannelRequestMessage(
                recipientChannel: recipientChannel,
                requestType: "signal",
                wantReply: false,
                requestData: writer.bytes
            )
        )
    }

    func parseSignalRequest(
        from message: SSHChannelRequestMessage
    ) throws -> SSHSessionSignal {
        guard message.requestType == "signal" else {
            throw SSHConnectionError.invalidChannelRequest(message.requestType)
        }

        var reader = SSHWireReader(bytes: message.requestData)
        let signal = try SSHSessionSignal(rawValue: reader.readUTF8String())
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return signal
    }

    func makeExitStatusRequest(recipientChannel: UInt32, exitStatus: UInt32) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(uint32: exitStatus)

        return .channelRequest(
            SSHChannelRequestMessage(
                recipientChannel: recipientChannel,
                requestType: "exit-status",
                wantReply: false,
                requestData: writer.bytes
            )
        )
    }

    func parseExitStatus(from message: SSHChannelRequestMessage) throws -> UInt32 {
        guard message.requestType == "exit-status" else {
            throw SSHConnectionError.invalidChannelRequest(message.requestType)
        }

        var reader = SSHWireReader(bytes: message.requestData)
        let exitStatus = try reader.readUInt32()
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return exitStatus
    }

    func makeExitSignalRequest(
        recipientChannel: UInt32,
        exitSignal: SSHSessionExitSignal
    ) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(utf8: exitSignal.signal.rawValue)
        writer.write(boolean: exitSignal.didCoreDump)
        writer.write(utf8: exitSignal.errorMessage ?? "")
        writer.write(utf8: exitSignal.languageTag ?? "")

        return .channelRequest(
            SSHChannelRequestMessage(
                recipientChannel: recipientChannel,
                requestType: "exit-signal",
                wantReply: false,
                requestData: writer.bytes
            )
        )
    }

    func parseExitSignal(from message: SSHChannelRequestMessage) throws -> SSHSessionExitSignal {
        guard message.requestType == "exit-signal" else {
            throw SSHConnectionError.invalidChannelRequest(message.requestType)
        }

        var reader = SSHWireReader(bytes: message.requestData)
        let signal = try SSHSessionSignal(rawValue: reader.readUTF8String())
        let didCoreDump = try reader.readBoolean()
        let errorMessage = try reader.readUTF8String()
        let languageTag = try reader.readUTF8String()
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return SSHSessionExitSignal(
            signal: signal,
            didCoreDump: didCoreDump,
            errorMessage: errorMessage.isEmpty ? nil : errorMessage,
            languageTag: languageTag.isEmpty ? nil : languageTag
        )
    }
}

struct SSHTCPIPForwardingRequestCoder: Sendable {
    func makeForwardRequest(
        request: SSHTCPIPForwardingRequest,
        wantReply: Bool = true
    ) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(utf8: request.addressToBind)
        writer.write(uint32: UInt32(request.portToBind))

        return .globalRequest(
            SSHGlobalRequestMessage(
                requestName: "tcpip-forward",
                wantReply: wantReply,
                requestData: writer.bytes
            )
        )
    }

    func parseForwardRequest(
        from message: SSHGlobalRequestMessage
    ) throws -> SSHTCPIPForwardingRequest {
        guard message.requestName == "tcpip-forward" else {
            throw SSHConnectionError.invalidGlobalRequest(message.requestName)
        }

        var reader = SSHWireReader(bytes: message.requestData)
        let request = try SSHTCPIPForwardingRequest(
            addressToBind: reader.readUTF8String(),
            portToBind: Self.readTCPIPPort(from: &reader)
        )
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return request
    }

    func makeCancelForwardRequest(
        request: SSHTCPIPForwardingRequest,
        wantReply: Bool = true
    ) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(utf8: request.addressToBind)
        writer.write(uint32: UInt32(request.portToBind))

        return .globalRequest(
            SSHGlobalRequestMessage(
                requestName: "cancel-tcpip-forward",
                wantReply: wantReply,
                requestData: writer.bytes
            )
        )
    }

    func parseCancelForwardRequest(
        from message: SSHGlobalRequestMessage
    ) throws -> SSHTCPIPForwardingRequest {
        guard message.requestName == "cancel-tcpip-forward" else {
            throw SSHConnectionError.invalidGlobalRequest(message.requestName)
        }

        var reader = SSHWireReader(bytes: message.requestData)
        let request = try SSHTCPIPForwardingRequest(
            addressToBind: reader.readUTF8String(),
            portToBind: Self.readTCPIPPort(from: &reader)
        )
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return request
    }

    func makeStreamLocalForwardRequest(
        request: SSHStreamLocalForwardingRequest,
        wantReply: Bool = true
    ) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(utf8: request.socketPath)

        return .globalRequest(
            SSHGlobalRequestMessage(
                requestName: "streamlocal-forward@openssh.com",
                wantReply: wantReply,
                requestData: writer.bytes
            )
        )
    }

    func parseStreamLocalForwardRequest(
        from message: SSHGlobalRequestMessage
    ) throws -> SSHStreamLocalForwardingRequest {
        guard message.requestName == "streamlocal-forward@openssh.com" else {
            throw SSHConnectionError.invalidGlobalRequest(message.requestName)
        }

        var reader = SSHWireReader(bytes: message.requestData)
        let request = try SSHStreamLocalForwardingRequest(
            socketPath: reader.readUTF8String()
        )
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return request
    }

    func makeCancelStreamLocalForwardRequest(
        request: SSHStreamLocalForwardingRequest,
        wantReply: Bool = true
    ) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(utf8: request.socketPath)

        return .globalRequest(
            SSHGlobalRequestMessage(
                requestName: "cancel-streamlocal-forward@openssh.com",
                wantReply: wantReply,
                requestData: writer.bytes
            )
        )
    }

    func parseCancelStreamLocalForwardRequest(
        from message: SSHGlobalRequestMessage
    ) throws -> SSHStreamLocalForwardingRequest {
        guard message.requestName == "cancel-streamlocal-forward@openssh.com" else {
            throw SSHConnectionError.invalidGlobalRequest(message.requestName)
        }

        var reader = SSHWireReader(bytes: message.requestData)
        let request = try SSHStreamLocalForwardingRequest(
            socketPath: reader.readUTF8String()
        )
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return request
    }

    func parseForwardSuccessPort(
        from message: SSHGlobalRequestSuccessMessage
    ) throws -> UInt16? {
        guard !message.responseData.isEmpty else {
            return nil
        }

        var reader = SSHWireReader(bytes: message.responseData)
        let port = try Self.readTCPIPPort(from: &reader)
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return port
    }

    func validateEmptySuccessResponse(
        _ message: SSHGlobalRequestSuccessMessage,
        requestName: String
    ) throws {
        guard message.responseData.isEmpty else {
            throw SSHConnectionError.invalidGlobalRequestResponse(requestType: requestName)
        }
    }

    func makeDirectTCPIPChannelOpen(
        senderChannel: UInt32,
        initialWindowSize: UInt32,
        maximumPacketSize: UInt32,
        request: SSHDirectTCPIPChannelOpenRequest
    ) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(utf8: request.hostToConnect)
        writer.write(uint32: UInt32(request.portToConnect))
        writer.write(utf8: request.originatorAddress)
        writer.write(uint32: UInt32(request.originatorPort))

        return .channelOpen(
            SSHChannelOpenMessage(
                channelType: "direct-tcpip",
                senderChannel: senderChannel,
                initialWindowSize: initialWindowSize,
                maximumPacketSize: maximumPacketSize,
                channelTypeData: writer.bytes
            )
        )
    }

    func parseDirectTCPIPChannelOpen(
        from message: SSHChannelOpenMessage
    ) throws -> SSHDirectTCPIPChannelOpenRequest {
        guard message.channelType == "direct-tcpip" else {
            throw SSHConnectionError.invalidChannelOpen(message.channelType)
        }

        var reader = SSHWireReader(bytes: message.channelTypeData)
        let request = try SSHDirectTCPIPChannelOpenRequest(
            hostToConnect: reader.readUTF8String(),
            portToConnect: Self.readTCPIPPort(from: &reader),
            originatorAddress: reader.readUTF8String(),
            originatorPort: Self.readTCPIPPort(from: &reader)
        )
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return request
    }

    func makeDirectStreamLocalChannelOpen(
        senderChannel: UInt32,
        initialWindowSize: UInt32,
        maximumPacketSize: UInt32,
        request: SSHDirectStreamLocalChannelOpenRequest
    ) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(utf8: request.socketPath)
        writer.write(utf8: request.originatorAddress)
        writer.write(uint32: UInt32(request.originatorPort))

        return .channelOpen(
            SSHChannelOpenMessage(
                channelType: "direct-streamlocal@openssh.com",
                senderChannel: senderChannel,
                initialWindowSize: initialWindowSize,
                maximumPacketSize: maximumPacketSize,
                channelTypeData: writer.bytes
            )
        )
    }

    func parseDirectStreamLocalChannelOpen(
        from message: SSHChannelOpenMessage
    ) throws -> SSHDirectStreamLocalChannelOpenRequest {
        guard message.channelType == "direct-streamlocal@openssh.com" else {
            throw SSHConnectionError.invalidChannelOpen(message.channelType)
        }

        var reader = SSHWireReader(bytes: message.channelTypeData)
        let request = try SSHDirectStreamLocalChannelOpenRequest(
            socketPath: reader.readUTF8String(),
            originatorAddress: reader.readUTF8String(),
            originatorPort: Self.readTCPIPPort(from: &reader)
        )
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return request
    }

    func makeForwardedTCPIPChannelOpen(
        senderChannel: UInt32,
        initialWindowSize: UInt32,
        maximumPacketSize: UInt32,
        request: SSHForwardedTCPIPChannelOpenRequest
    ) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(utf8: request.listeningAddress)
        writer.write(uint32: UInt32(request.listeningPort))
        writer.write(utf8: request.originatorAddress)
        writer.write(uint32: UInt32(request.originatorPort))

        return .channelOpen(
            SSHChannelOpenMessage(
                channelType: "forwarded-tcpip",
                senderChannel: senderChannel,
                initialWindowSize: initialWindowSize,
                maximumPacketSize: maximumPacketSize,
                channelTypeData: writer.bytes
            )
        )
    }

    func parseForwardedTCPIPChannelOpen(
        from message: SSHChannelOpenMessage
    ) throws -> SSHForwardedTCPIPChannelOpenRequest {
        guard message.channelType == "forwarded-tcpip" else {
            throw SSHConnectionError.invalidChannelOpen(message.channelType)
        }

        var reader = SSHWireReader(bytes: message.channelTypeData)
        let request = try SSHForwardedTCPIPChannelOpenRequest(
            listeningAddress: reader.readUTF8String(),
            listeningPort: Self.readTCPIPPort(from: &reader),
            originatorAddress: reader.readUTF8String(),
            originatorPort: Self.readTCPIPPort(from: &reader)
        )
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return request
    }

    func makeForwardedStreamLocalChannelOpen(
        senderChannel: UInt32,
        initialWindowSize: UInt32,
        maximumPacketSize: UInt32,
        request: SSHForwardedStreamLocalChannelOpenRequest
    ) -> SSHConnectionMessage {
        var writer = SSHWireWriter()
        writer.write(utf8: request.socketPath)
        writer.write(utf8: "")

        return .channelOpen(
            SSHChannelOpenMessage(
                channelType: "forwarded-streamlocal@openssh.com",
                senderChannel: senderChannel,
                initialWindowSize: initialWindowSize,
                maximumPacketSize: maximumPacketSize,
                channelTypeData: writer.bytes
            )
        )
    }

    func parseForwardedStreamLocalChannelOpen(
        from message: SSHChannelOpenMessage
    ) throws -> SSHForwardedStreamLocalChannelOpenRequest {
        guard message.channelType == "forwarded-streamlocal@openssh.com" else {
            throw SSHConnectionError.invalidChannelOpen(message.channelType)
        }

        var reader = SSHWireReader(bytes: message.channelTypeData)
        let request = try SSHForwardedStreamLocalChannelOpenRequest(
            socketPath: reader.readUTF8String()
        )
        _ = try reader.readUTF8String()
        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }
        return request
    }

    private static func readTCPIPPort(from reader: inout SSHWireReader) throws -> UInt16 {
        let rawPort = try reader.readUInt32()
        guard let port = UInt16(exactly: rawPort) else {
            throw SSHConnectionError.invalidTCPIPPort(rawPort)
        }
        return port
    }
}
