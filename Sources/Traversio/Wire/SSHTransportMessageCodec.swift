// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

struct SSHTransportMessageSerializer: Sendable {
    func serialize(_ message: SSHTransportMessage) throws -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(byte: message.messageID.rawValue)

        switch message {
        case let .disconnect(payload):
            writer.write(uint32: payload.reasonCode.rawValue)
            writer.write(utf8: payload.description)
            writer.write(utf8: payload.languageTag)
        case let .ignore(payload):
            writer.write(string: payload.data)
        case let .unimplemented(payload):
            writer.write(uint32: payload.packetSequenceNumber)
        case let .debug(payload):
            writer.write(boolean: payload.alwaysDisplay)
            writer.write(utf8: payload.message)
            writer.write(utf8: payload.languageTag)
        case let .serviceRequest(payload):
            writer.write(utf8: payload.serviceName)
        case let .serviceAccept(payload):
            writer.write(utf8: payload.serviceName)
        case let .extensionInfo(payload):
            writer.write(uint32: UInt32(payload.entries.count))
            for entry in payload.entries {
                writer.write(utf8: entry.name)
                writer.write(string: entry.value)
            }
        case let .keyExchangeInit(payload):
            writer.write(rawBytes: payload.cookie)
            try writer.write(nameList: payload.keyExchangeAlgorithms)
            try writer.write(nameList: payload.serverHostKeyAlgorithms)
            try writer.write(nameList: payload.encryptionAlgorithmsClientToServer)
            try writer.write(nameList: payload.encryptionAlgorithmsServerToClient)
            try writer.write(nameList: payload.macAlgorithmsClientToServer)
            try writer.write(nameList: payload.macAlgorithmsServerToClient)
            try writer.write(nameList: payload.compressionAlgorithmsClientToServer)
            try writer.write(nameList: payload.compressionAlgorithmsServerToClient)
            try writer.write(nameList: payload.languagesClientToServer)
            try writer.write(nameList: payload.languagesServerToClient)
            writer.write(boolean: payload.firstKeyExchangePacketFollows)
            writer.write(uint32: payload.reserved)
        case .newKeys:
            break
        case let .keyExchangeECDHInit(payload):
            writer.write(string: payload.publicKey)
        case let .keyExchangeECDHReply(payload):
            writer.write(string: payload.hostKey)
            writer.write(string: payload.publicKey)
            writer.write(string: payload.signature)
        }

        return writer.bytes
    }
}

struct SSHTransportMessageParser: Sendable {
    func parse(_ bytes: [UInt8]) throws -> SSHTransportMessage {
        var reader = SSHWireReader(bytes: bytes)
        let rawMessageType = try reader.readByte()

        guard let messageID = SSHTransportMessageID(rawValue: rawMessageType) else {
            throw SSHWireError.unknownMessageType(rawMessageType)
        }

        let message: SSHTransportMessage
        switch messageID {
        case .disconnect:
            message = try .disconnect(
                SSHDisconnectMessage(
                    reasonCode: SSHDisconnectReasonCode(rawValue: reader.readUInt32()),
                    description: reader.readUTF8String(),
                    languageTag: reader.readUTF8String()
                )
            )
        case .ignore:
            message = try .ignore(
                SSHIgnoreMessage(data: reader.readString())
            )
        case .unimplemented:
            message = try .unimplemented(
                SSHUnimplementedMessage(packetSequenceNumber: reader.readUInt32())
            )
        case .debug:
            message = try .debug(
                SSHDebugMessage(
                    alwaysDisplay: reader.readBoolean(),
                    message: reader.readUTF8String(),
                    languageTag: reader.readUTF8String()
                )
            )
        case .serviceRequest:
            message = try .serviceRequest(
                SSHServiceRequestMessage(serviceName: reader.readUTF8String())
            )
        case .serviceAccept:
            message = try .serviceAccept(
                SSHServiceAcceptMessage(serviceName: reader.readUTF8String())
            )
        case .extensionInfo:
            let entryCount = try reader.readUInt32()
            var entries: [SSHExtensionInfoEntry] = []
            entries.reserveCapacity(Int(entryCount))
            for _ in 0..<entryCount {
                entries.append(
                    try SSHExtensionInfoEntry(
                        name: reader.readUTF8String(),
                        value: reader.readString()
                    )
                )
            }
            message = .extensionInfo(
                SSHExtensionInfoMessage(entries: entries)
            )
        case .keyExchangeInit:
            message = try .keyExchangeInit(
                SSHKeyExchangeInitMessage(
                    cookie: reader.readRawBytes(count: 16),
                    keyExchangeAlgorithms: reader.readNameList(),
                    serverHostKeyAlgorithms: reader.readNameList(),
                    encryptionAlgorithmsClientToServer: reader.readNameList(),
                    encryptionAlgorithmsServerToClient: reader.readNameList(),
                    macAlgorithmsClientToServer: reader.readNameList(),
                    macAlgorithmsServerToClient: reader.readNameList(),
                    compressionAlgorithmsClientToServer: reader.readNameList(),
                    compressionAlgorithmsServerToClient: reader.readNameList(),
                    languagesClientToServer: reader.readNameList(),
                    languagesServerToClient: reader.readNameList(),
                    firstKeyExchangePacketFollows: reader.readBoolean(),
                    reserved: reader.readUInt32()
                )
            )
        case .newKeys:
            message = .newKeys(SSHNewKeysMessage())
        case .keyExchangeECDHInit:
            message = try .keyExchangeECDHInit(
                SSHKeyExchangeECDHInitMessage(publicKey: reader.readString())
            )
        case .keyExchangeECDHReply:
            message = try .keyExchangeECDHReply(
                SSHKeyExchangeECDHReplyMessage(
                    hostKey: reader.readString(),
                    publicKey: reader.readString(),
                    signature: reader.readString()
                )
            )
        }

        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }

        return message
    }
}
