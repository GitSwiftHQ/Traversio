// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package struct SSHSFTPPacketSerializer: Sendable {
    static let defaultMaximumPacketLength: UInt32 = 256 * 1024

    let maximumPacketLength: UInt32

    init(maximumPacketLength: UInt32 = Self.defaultMaximumPacketLength) {
        self.maximumPacketLength = maximumPacketLength
    }

    func serialize(payload: [UInt8]) throws -> [UInt8] {
        let payloadLength = UInt32(payload.count)
        guard payloadLength > 0 else {
            throw SSHSFTPError.invalidPacketLength(payloadLength)
        }
        guard payloadLength <= self.maximumPacketLength else {
            throw SSHSFTPError.packetTooLarge(
                length: payloadLength,
                maximum: self.maximumPacketLength
            )
        }

        var writer = SSHWireWriter()
        writer.write(uint32: payloadLength)
        writer.write(rawBytes: payload)
        return writer.bytes
    }
}

package struct SSHSFTPPacketParser: Sendable {
    private(set) var bufferedBytes: [UInt8] = []
    let maximumPacketLength: UInt32

    init(maximumPacketLength: UInt32 = SSHSFTPPacketSerializer.defaultMaximumPacketLength) {
        self.maximumPacketLength = maximumPacketLength
    }

    mutating func append(bytes: [UInt8]) {
        self.bufferedBytes.append(contentsOf: bytes)
    }

    mutating func nextPayload() throws -> [UInt8]? {
        guard self.bufferedBytes.count >= 4 else {
            return nil
        }

        let packetLength = self.bufferedBytes.prefix(4).reduce(UInt32(0)) {
            ($0 << 8) | UInt32($1)
        }
        guard packetLength > 0 else {
            throw SSHSFTPError.invalidPacketLength(packetLength)
        }
        guard packetLength <= self.maximumPacketLength else {
            throw SSHSFTPError.packetTooLarge(
                length: packetLength,
                maximum: self.maximumPacketLength
            )
        }

        let totalPacketLength = 4 + Int(packetLength)
        guard self.bufferedBytes.count >= totalPacketLength else {
            return nil
        }

        let payload = Array(self.bufferedBytes[4..<totalPacketLength])
        self.bufferedBytes.removeFirst(totalPacketLength)
        return payload
    }
}

package struct SSHSFTPMessageSerializer: Sendable {
    func serialize(_ message: SSHSFTPMessage) -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(byte: message.messageID.rawValue)

        switch message {
        case let .initialize(payload):
            writer.write(uint32: payload.version)
        case let .openFile(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: payload.path)
            writer.write(uint32: payload.pflags.rawValue)
            self.writeAttributes(payload.attributes, to: &writer)
        case let .close(payload):
            writer.write(uint32: payload.requestID)
            writer.write(string: payload.handle.bytes)
        case let .version(payload):
            writer.write(uint32: payload.version)
            for extensionData in payload.extensions {
                writer.write(utf8: extensionData.name)
                writer.write(string: extensionData.data)
            }
        case let .readFile(payload):
            writer.write(uint32: payload.requestID)
            writer.write(string: payload.handle.bytes)
            writer.write(uint64: payload.offset)
            writer.write(uint32: payload.length)
        case let .writeFile(payload):
            writer.write(uint32: payload.requestID)
            writer.write(string: payload.handle.bytes)
            writer.write(uint64: payload.offset)
            writer.write(string: payload.data)
        case let .lstat(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: payload.path)
        case let .fstat(payload):
            writer.write(uint32: payload.requestID)
            writer.write(string: payload.handle.bytes)
        case let .setAttributes(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: payload.path)
            self.writeAttributes(payload.attributes, to: &writer)
        case let .fsetAttributes(payload):
            writer.write(uint32: payload.requestID)
            writer.write(string: payload.handle.bytes)
            self.writeAttributes(payload.attributes, to: &writer)
        case let .removeFile(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: payload.path)
        case let .makeDirectory(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: payload.path)
            self.writeAttributes(payload.attributes, to: &writer)
        case let .removeDirectory(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: payload.path)
        case let .openDirectory(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: payload.path)
        case let .readDirectory(payload):
            writer.write(uint32: payload.requestID)
            writer.write(string: payload.handle.bytes)
        case let .realPath(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: payload.path)
        case let .stat(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: payload.path)
        case let .rename(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: payload.oldPath)
            writer.write(utf8: payload.newPath)
        case let .posixRename(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: "posix-rename@openssh.com")
            writer.write(utf8: payload.oldPath)
            writer.write(utf8: payload.newPath)
        case let .statVFS(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: "statvfs@openssh.com")
            writer.write(utf8: payload.path)
        case let .fstatVFS(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: "fstatvfs@openssh.com")
            writer.write(string: payload.handle.bytes)
        case let .fsync(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: "fsync@openssh.com")
            writer.write(string: payload.handle.bytes)
        case let .readLink(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: payload.path)
        case let .symbolicLink(payload):
            writer.write(uint32: payload.requestID)
            writer.write(utf8: payload.targetPath)
            writer.write(utf8: payload.linkPath)
        case let .status(payload):
            writer.write(uint32: payload.requestID)
            writer.write(uint32: payload.statusCode.rawValue)
            if let errorMessage = payload.errorMessage {
                writer.write(utf8: errorMessage)
                writer.write(utf8: payload.languageTag ?? "")
            }
        case let .handle(payload):
            writer.write(uint32: payload.requestID)
            writer.write(string: payload.handle.bytes)
        case let .data(payload):
            writer.write(uint32: payload.requestID)
            writer.write(string: payload.data)
        case let .name(payload):
            writer.write(uint32: payload.requestID)
            writer.write(uint32: UInt32(payload.entries.count))
            for entry in payload.entries {
                writer.write(utf8: entry.filename)
                writer.write(utf8: entry.longName)
                self.writeAttributes(entry.attributes, to: &writer)
            }
        case let .attributes(payload):
            writer.write(uint32: payload.requestID)
            self.writeAttributes(payload.attributes, to: &writer)
        case let .extendedReply(payload):
            writer.write(uint32: payload.requestID)
            writer.write(rawBytes: payload.data)
        }

        return writer.bytes
    }

    private func writeAttributes(
        _ attributes: SSHSFTPFileAttributes,
        to writer: inout SSHWireWriter
    ) {
        writer.write(uint32: attributes.flags)
        if attributes.flags & SSHSFTPFileAttributes.sizeFlag != 0 {
            writer.write(uint64: attributes.size ?? 0)
        }
        if attributes.flags & SSHSFTPFileAttributes.userIDAndGroupIDFlag != 0 {
            writer.write(uint32: attributes.userID ?? 0)
            writer.write(uint32: attributes.groupID ?? 0)
        }
        if attributes.flags & SSHSFTPFileAttributes.permissionsFlag != 0 {
            writer.write(uint32: attributes.permissions ?? 0)
        }
        if attributes.flags & SSHSFTPFileAttributes.accessAndModificationTimeFlag != 0 {
            writer.write(uint32: attributes.accessTime ?? 0)
            writer.write(uint32: attributes.modificationTime ?? 0)
        }
        if attributes.flags & SSHSFTPFileAttributes.extendedFlag != 0 {
            writer.write(uint32: UInt32(attributes.extensions.count))
            for extensionData in attributes.extensions {
                writer.write(utf8: extensionData.name)
                writer.write(string: extensionData.data)
            }
        }
    }
}

package struct SSHSFTPMessageParser: Sendable {
    func parse(_ bytes: [UInt8]) throws -> SSHSFTPMessage {
        var reader = SSHWireReader(bytes: bytes)
        let rawMessageType = try reader.readByte()

        guard let messageID = SSHSFTPMessageID(rawValue: rawMessageType) else {
            throw SSHWireError.unknownMessageType(rawMessageType)
        }

        let message: SSHSFTPMessage
        switch messageID {
        case .initialize:
            message = try .initialize(
                SSHSFTPInitializeMessage(version: reader.readUInt32())
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .openFile:
            let requestID = try reader.readUInt32()
            let path = try reader.readUTF8String()
            let pflags = SSHSFTPOpenFileFlags(rawValue: try reader.readUInt32())
            let attributes = try self.readAttributes(from: &reader)
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
            message = .openFile(
                SSHSFTPOpenFileMessage(
                    requestID: requestID,
                    path: path,
                    pflags: pflags,
                    attributes: attributes
                )
            )
        case .close:
            message = try .close(
                SSHSFTPCloseMessage(
                    requestID: reader.readUInt32(),
                    handle: SSHSFTPHandle(bytes: reader.readString())
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .version:
            let version = try reader.readUInt32()
            var extensions: [SSHSFTPExtension] = []
            while !reader.isAtEnd {
                extensions.append(
                    try SSHSFTPExtension(
                        name: reader.readUTF8String(),
                        data: reader.readString()
                    )
                )
            }
            message = .version(
                SSHSFTPVersionMessage(
                    version: version,
                    extensions: extensions
                )
            )
        case .readFile:
            message = try .readFile(
                SSHSFTPReadFileMessage(
                    requestID: reader.readUInt32(),
                    handle: SSHSFTPHandle(bytes: reader.readString()),
                    offset: reader.readUInt64(),
                    length: reader.readUInt32()
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .writeFile:
            message = try .writeFile(
                SSHSFTPWriteFileMessage(
                    requestID: reader.readUInt32(),
                    handle: SSHSFTPHandle(bytes: reader.readString()),
                    offset: reader.readUInt64(),
                    data: reader.readString()
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .lstat:
            message = try .lstat(
                SSHSFTPLStatMessage(
                    requestID: reader.readUInt32(),
                    path: reader.readUTF8String()
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .fstat:
            message = try .fstat(
                SSHSFTPFStatMessage(
                    requestID: reader.readUInt32(),
                    handle: SSHSFTPHandle(bytes: reader.readString())
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .setstat:
            let requestID = try reader.readUInt32()
            let path = try reader.readUTF8String()
            let attributes = try self.readAttributes(from: &reader)
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
            message = .setAttributes(
                SSHSFTPSetAttributesMessage(
                    requestID: requestID,
                    path: path,
                    attributes: attributes
                )
            )
        case .fsetstat:
            let requestID = try reader.readUInt32()
            let handle = try SSHSFTPHandle(bytes: reader.readString())
            let attributes = try self.readAttributes(from: &reader)
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
            message = .fsetAttributes(
                SSHSFTPFSetAttributesMessage(
                    requestID: requestID,
                    handle: handle,
                    attributes: attributes
                )
            )
        case .removeFile:
            message = try .removeFile(
                SSHSFTPRemoveFileMessage(
                    requestID: reader.readUInt32(),
                    path: reader.readUTF8String()
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .makeDirectory:
            let requestID = try reader.readUInt32()
            let path = try reader.readUTF8String()
            let attributes = try self.readAttributes(from: &reader)
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
            message = .makeDirectory(
                SSHSFTPMakeDirectoryMessage(
                    requestID: requestID,
                    path: path,
                    attributes: attributes
                )
            )
        case .removeDirectory:
            message = try .removeDirectory(
                SSHSFTPRemoveDirectoryMessage(
                    requestID: reader.readUInt32(),
                    path: reader.readUTF8String()
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .openDirectory:
            message = try .openDirectory(
                SSHSFTPOpenDirectoryMessage(
                    requestID: reader.readUInt32(),
                    path: reader.readUTF8String()
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .readDirectory:
            message = try .readDirectory(
                SSHSFTPReadDirectoryMessage(
                    requestID: reader.readUInt32(),
                    handle: SSHSFTPHandle(bytes: reader.readString())
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .realPath:
            message = try .realPath(
                SSHSFTPRealPathMessage(
                    requestID: reader.readUInt32(),
                    path: reader.readUTF8String()
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .stat:
            message = try .stat(
                SSHSFTPStatMessage(
                    requestID: reader.readUInt32(),
                    path: reader.readUTF8String()
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .rename:
            message = try .rename(
                SSHSFTPRenameMessage(
                    requestID: reader.readUInt32(),
                    oldPath: reader.readUTF8String(),
                    newPath: reader.readUTF8String()
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .extended:
            let requestID = try reader.readUInt32()
            let requestType = try reader.readUTF8String()
            switch requestType {
            case "posix-rename@openssh.com":
                message = try .posixRename(
                    SSHSFTPPosixRenameMessage(
                        requestID: requestID,
                        oldPath: reader.readUTF8String(),
                        newPath: reader.readUTF8String()
                    )
                )
                guard reader.isAtEnd else {
                    throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
                }
            case "statvfs@openssh.com":
                message = try .statVFS(
                    SSHSFTPStatVFSMessage(
                        requestID: requestID,
                        path: reader.readUTF8String()
                    )
                )
                guard reader.isAtEnd else {
                    throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
                }
            case "fstatvfs@openssh.com":
                message = try .fstatVFS(
                    SSHSFTPFStatVFSMessage(
                        requestID: requestID,
                        handle: SSHSFTPHandle(bytes: reader.readString())
                    )
                )
                guard reader.isAtEnd else {
                    throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
                }
            case "fsync@openssh.com":
                message = try .fsync(
                    SSHSFTPFSyncMessage(
                        requestID: requestID,
                        handle: SSHSFTPHandle(bytes: reader.readString())
                    )
                )
                guard reader.isAtEnd else {
                    throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
                }
            default:
                throw SSHSFTPError.unsupportedExtendedRequest(requestType)
            }
        case .readLink:
            message = try .readLink(
                SSHSFTPReadLinkMessage(
                    requestID: reader.readUInt32(),
                    path: reader.readUTF8String()
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .symbolicLink:
            message = try .symbolicLink(
                SSHSFTPSymbolicLinkMessage(
                    requestID: reader.readUInt32(),
                    targetPath: reader.readUTF8String(),
                    linkPath: reader.readUTF8String()
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .status:
            let requestID = try reader.readUInt32()
            let statusCode = SSHSFTPStatusCode(rawValue: try reader.readUInt32())
            let errorMessage: String?
            let languageTag: String?
            if reader.isAtEnd {
                errorMessage = nil
                languageTag = nil
            } else {
                errorMessage = try reader.readUTF8String()
                languageTag = try reader.readUTF8String()
                guard reader.isAtEnd else {
                    throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
                }
            }
            message = .status(
                SSHSFTPStatusMessage(
                    requestID: requestID,
                    statusCode: statusCode,
                    errorMessage: errorMessage,
                    languageTag: languageTag
                )
            )
        case .handle:
            message = try .handle(
                SSHSFTPHandleMessage(
                    requestID: reader.readUInt32(),
                    handle: SSHSFTPHandle(bytes: reader.readString())
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .data:
            message = try .data(
                SSHSFTPDataMessage(
                    requestID: reader.readUInt32(),
                    data: reader.readString()
                )
            )
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
        case .name:
            let requestID = try reader.readUInt32()
            let entryCount = try reader.readUInt32()
            var entries: [SSHSFTPNameEntry] = []
            entries.reserveCapacity(Int(entryCount))
            for _ in 0..<entryCount {
                entries.append(
                    try SSHSFTPNameEntry(
                        filename: reader.readUTF8String(),
                        longName: reader.readUTF8String(),
                        attributes: self.readAttributes(from: &reader)
                    )
                )
            }
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
            message = .name(
                SSHSFTPNameMessage(
                    requestID: requestID,
                    entries: entries
                )
            )
        case .attributes:
            let requestID = try reader.readUInt32()
            let attributes = try self.readAttributes(from: &reader)
            guard reader.isAtEnd else {
                throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
            }
            message = .attributes(
                SSHSFTPAttributesMessage(
                    requestID: requestID,
                    attributes: attributes
                )
            )
        case .extendedReply:
            let requestID = try reader.readUInt32()
            let data = try reader.readRawBytes(count: reader.remainingByteCount)
            message = .extendedReply(
                SSHSFTPExtendedReplyMessage(
                    requestID: requestID,
                    data: data
                )
            )
        }

        return message
    }

    private func readAttributes(
        from reader: inout SSHWireReader
    ) throws -> SSHSFTPFileAttributes {
        let flags = try reader.readUInt32()

        let size: UInt64? = if flags & SSHSFTPFileAttributes.sizeFlag != 0 {
            try reader.readUInt64()
        } else {
            nil
        }
        let userID: UInt32?
        let groupID: UInt32?
        if flags & SSHSFTPFileAttributes.userIDAndGroupIDFlag != 0 {
            userID = try reader.readUInt32()
            groupID = try reader.readUInt32()
        } else {
            userID = nil
            groupID = nil
        }
        let permissions: UInt32? = if flags & SSHSFTPFileAttributes.permissionsFlag != 0 {
            try reader.readUInt32()
        } else {
            nil
        }
        let accessTime: UInt32?
        let modificationTime: UInt32?
        if flags & SSHSFTPFileAttributes.accessAndModificationTimeFlag != 0 {
            accessTime = try reader.readUInt32()
            modificationTime = try reader.readUInt32()
        } else {
            accessTime = nil
            modificationTime = nil
        }

        var extensions: [SSHSFTPExtension] = []
        if flags & SSHSFTPFileAttributes.extendedFlag != 0 {
            let extensionCount = try reader.readUInt32()
            extensions.reserveCapacity(Int(extensionCount))
            for _ in 0..<extensionCount {
                extensions.append(
                    try SSHSFTPExtension(
                        name: reader.readUTF8String(),
                        data: reader.readString()
                    )
                )
            }
        }

        return SSHSFTPFileAttributes(
            flags: flags,
            size: size,
            userID: userID,
            groupID: groupID,
            permissions: permissions,
            accessTime: accessTime,
            modificationTime: modificationTime,
            extensions: extensions
        )
    }
}
