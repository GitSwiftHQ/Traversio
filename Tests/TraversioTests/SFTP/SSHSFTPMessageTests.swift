// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func sftpMessageParserRoundTripsInitializeMessage() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.initialize(
        SSHSFTPInitializeMessage(version: 3)
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsCloseRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.close(
        SSHSFTPCloseMessage(
            requestID: 5,
            handle: SSHSFTPHandle(bytes: [0xde, 0xad, 0xbe, 0xef])
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsOpenFileRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.openFile(
        SSHSFTPOpenFileMessage(
            requestID: 4,
            path: "/tmp/example.txt",
            pflags: [.read],
            attributes: .empty
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsRealPathRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.realPath(
        SSHSFTPRealPathMessage(
            requestID: 7,
            path: "."
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsReadFileRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.readFile(
        SSHSFTPReadFileMessage(
            requestID: 13,
            handle: SSHSFTPHandle(bytes: [0x10, 0x20, 0x30]),
            offset: 4_096,
            length: 8_192
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsWriteFileRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.writeFile(
        SSHSFTPWriteFileMessage(
            requestID: 14,
            handle: SSHSFTPHandle(bytes: [0xaa, 0xbb, 0xcc]),
            offset: 8_192,
            data: Array("hello".utf8)
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsLStatRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.lstat(
        SSHSFTPLStatMessage(
            requestID: 15,
            path: "/tmp/link"
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsFStatRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.fstat(
        SSHSFTPFStatMessage(
            requestID: 16,
            handle: SSHSFTPHandle(bytes: [0xaa, 0xbb, 0xcc])
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsRemoveFileRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.removeFile(
        SSHSFTPRemoveFileMessage(
            requestID: 17,
            path: "/tmp/stale.txt"
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsMakeDirectoryRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.makeDirectory(
        SSHSFTPMakeDirectoryMessage(
            requestID: 18,
            path: "/tmp/output",
            attributes: SSHSFTPFileAttributes(
                flags: SSHSFTPFileAttributes.permissionsFlag,
                size: nil,
                userID: nil,
                groupID: nil,
                permissions: 0o755,
                accessTime: nil,
                modificationTime: nil,
                extensions: []
            )
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsRemoveDirectoryRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.removeDirectory(
        SSHSFTPRemoveDirectoryMessage(
            requestID: 20,
            path: "/tmp/obsolete"
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsOpenDirectoryRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.openDirectory(
        SSHSFTPOpenDirectoryMessage(
            requestID: 6,
            path: "/tmp"
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsReadDirectoryRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.readDirectory(
        SSHSFTPReadDirectoryMessage(
            requestID: 9,
            handle: SSHSFTPHandle(bytes: [0x01, 0x02, 0x03])
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsRenameRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.rename(
        SSHSFTPRenameMessage(
            requestID: 19,
            oldPath: "/tmp/from.txt",
            newPath: "/tmp/to.txt"
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsPosixRenameExtendedRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.posixRename(
        SSHSFTPPosixRenameMessage(
            requestID: 23,
            oldPath: "/tmp/from.txt",
            newPath: "/tmp/to.txt"
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRejectsUnsupportedExtendedRequest() throws {
    var writer = SSHWireWriter()
    writer.write(byte: SSHSFTPMessageID.extended.rawValue)
    writer.write(uint32: 24)
    writer.write(utf8: "example@vendor.invalid")
    writer.write(utf8: "payload")

    do {
        _ = try SSHSFTPMessageParser().parse(writer.bytes)
        Issue.record("Expected unsupported extended request error")
    } catch {
        #expect(
            error as? SSHSFTPError
                == .unsupportedExtendedRequest("example@vendor.invalid")
        )
    }
}

@Test
func sftpMessageParserRoundTripsReadLinkRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.readLink(
        SSHSFTPReadLinkMessage(
            requestID: 21,
            path: "/tmp/current"
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsSymbolicLinkRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.symbolicLink(
        SSHSFTPSymbolicLinkMessage(
            requestID: 22,
            targetPath: "/var/log/app.log",
            linkPath: "/tmp/app-log"
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsStatRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.stat(
        SSHSFTPStatMessage(
            requestID: 8,
            path: "/tmp"
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsSetAttributesRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let attributes = SSHSFTPFileAttributes(
        flags: SSHSFTPFileAttributes.permissionsFlag |
            SSHSFTPFileAttributes.accessAndModificationTimeFlag,
        size: nil,
        userID: nil,
        groupID: nil,
        permissions: 0o640,
        accessTime: 1_700_010_000,
        modificationTime: 1_700_010_120,
        extensions: []
    )
    let message = SSHSFTPMessage.setAttributes(
        SSHSFTPSetAttributesMessage(
            requestID: 25,
            path: "/tmp/example.txt",
            attributes: attributes
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsFSetAttributesRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let attributes = SSHSFTPFileAttributes(
        flags: SSHSFTPFileAttributes.sizeFlag,
        size: 512,
        userID: nil,
        groupID: nil,
        permissions: nil,
        accessTime: nil,
        modificationTime: nil,
        extensions: []
    )
    let message = SSHSFTPMessage.fsetAttributes(
        SSHSFTPFSetAttributesMessage(
            requestID: 26,
            handle: SSHSFTPHandle(bytes: [0x10, 0x20, 0x30, 0x40]),
            attributes: attributes
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsStatVFSRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.statVFS(
        SSHSFTPStatVFSMessage(
            requestID: 27,
            path: "/var"
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsFStatVFSRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.fstatVFS(
        SSHSFTPFStatVFSMessage(
            requestID: 28,
            handle: SSHSFTPHandle(bytes: [0xaa, 0xbb, 0xcc])
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsFSyncRequest() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.fsync(
        SSHSFTPFSyncMessage(
            requestID: 29,
            handle: SSHSFTPHandle(bytes: [0xde, 0xad, 0xbe, 0xef])
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsHandleResponse() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.handle(
        SSHSFTPHandleMessage(
            requestID: 10,
            handle: SSHSFTPHandle(bytes: [0xca, 0xfe, 0xba, 0xbe])
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsDataResponse() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.data(
        SSHSFTPDataMessage(
            requestID: 14,
            data: [0xde, 0xad, 0xbe, 0xef]
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsNameResponse() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.name(
        SSHSFTPNameMessage(
            requestID: 3,
            entries: [
                SSHSFTPNameEntry(
                    filename: "/tmp",
                    longName: "/tmp",
                    attributes: .empty
                )
            ]
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsAttributesResponse() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.attributes(
        SSHSFTPAttributesMessage(
            requestID: 12,
            attributes: SSHSFTPFileAttributes(
                flags: SSHSFTPFileAttributes.sizeFlag |
                    SSHSFTPFileAttributes.permissionsFlag |
                    SSHSFTPFileAttributes.accessAndModificationTimeFlag,
                size: 4_096,
                userID: nil,
                groupID: nil,
                permissions: 0o755,
                accessTime: 1_700_000_000,
                modificationTime: 1_700_000_100,
                extensions: []
            )
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsExtendedReplyResponse() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.extendedReply(
        SSHSFTPExtendedReplyMessage(
            requestID: 30,
            data: [0, 1, 2, 3, 4, 5]
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpMessageParserRoundTripsStatusResponse() throws {
    let serializer = SSHSFTPMessageSerializer()
    let parser = SSHSFTPMessageParser()
    let message = SSHSFTPMessage.status(
        SSHSFTPStatusMessage(
            requestID: 11,
            statusCode: .noSuchFile,
            errorMessage: "No such file",
            languageTag: ""
        )
    )

    let bytes = serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func sftpPacketParserRoundTripsChunkedVersionPacket() throws {
    let message = SSHSFTPMessage.version(
        SSHSFTPVersionMessage(
            version: 3,
            extensions: [
                SSHSFTPExtension(
                    name: "posix-rename@openssh.com",
                    data: Array("1".utf8)
                ),
                SSHSFTPExtension(
                    name: "copy-data",
                    data: Array("1".utf8)
                ),
            ]
        )
    )
    let packet = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(message)
    )
    var parser = SSHSFTPPacketParser()

    parser.append(bytes: Array(packet.prefix(6)))
    #expect(try parser.nextPayload() == nil)

    parser.append(bytes: Array(packet.dropFirst(6)))
    let payload = try #require(try parser.nextPayload())

    #expect(try SSHSFTPMessageParser().parse(payload) == message)
}

@Test
func sftpPacketSerializerRejectsPacketsAboveMaximumLength() throws {
    let payload = Array(repeating: UInt8(0x61), count: Int(SSHSFTPPacketSerializer.defaultMaximumPacketLength) + 1)

    do {
        _ = try SSHSFTPPacketSerializer().serialize(payload: payload)
        Issue.record("Expected packet-too-large error")
    } catch {
        #expect(
            error as? SSHSFTPError
                == .packetTooLarge(
                    length: UInt32(payload.count),
                    maximum: SSHSFTPPacketSerializer.defaultMaximumPacketLength
                )
        )
    }
}
