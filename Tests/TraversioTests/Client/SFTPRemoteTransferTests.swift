// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientCopiesRemoteFileBetweenDifferentSFTPSessions() async throws {
    let sourceHandle = SSHSFTPHandle(bytes: [0x10, 0x32, 0x54, 0x76])
    let destinationHandle = SSHSFTPHandle(bytes: [0x20, 0x42, 0x64, 0x86])
    let sourceFixture = try await makeConcurrentSFTPFixture(senderChannel: 107)
    let destinationFixture = try await makeConcurrentSFTPFixture(senderChannel: 207)
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await sourceFixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    _ = try await destinationFixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sourceSFTP = try await makePublicSFTPClient(from: sourceFixture.client)
    let destinationSFTP = try await makePublicSFTPClient(from: destinationFixture.client)

    let copyTask = Task {
        try await SFTPRemoteTransfer.copyFile(
            from: sourceSFTP,
            sourcePath: "/source/report.txt",
            to: destinationSFTP,
            destinationPath: "/destination/report.txt",
            chunkSize: 4,
            progress: { value in
                await progressRecorder.record(value)
            }
        )
    }
    defer { copyTask.cancel() }

    let sourceOpen = try await waitForOpenFile(from: sourceFixture, minimumCount: 1)
    #expect(sourceOpen.path == "/source/report.txt")
    #expect(sourceOpen.pflags == [.read])
    try await sourceFixture.server.appendSFTPMessages([
        .handle(.init(requestID: sourceOpen.requestID, handle: sourceHandle)),
    ])

    let destinationOpen = try await waitForOpenFile(from: destinationFixture, minimumCount: 1)
    #expect(destinationOpen.path == "/destination/report.txt")
    #expect(destinationOpen.pflags == [.write, .create, .truncate])
    try await destinationFixture.server.appendSFTPMessages([
        .handle(.init(requestID: destinationOpen.requestID, handle: destinationHandle)),
    ])

    let firstRead = try await waitForReadFile(from: sourceFixture, minimumCount: 2)
    #expect(firstRead.offset == 0)
    #expect(firstRead.length == 4)
    try await sourceFixture.server.appendSFTPMessages([
        .data(.init(requestID: firstRead.requestID, data: Array("abcd".utf8))),
    ])

    let firstWrite = try await waitForWriteFile(from: destinationFixture, minimumCount: 2)
    #expect(firstWrite.offset == 0)
    #expect(firstWrite.data == Array("abcd".utf8))
    try await destinationFixture.server.appendSFTPMessages([
        .status(makeSFTPStatusMessage(requestID: firstWrite.requestID, statusCode: .ok)),
    ])

    let secondRead = try await waitForReadFile(from: sourceFixture, minimumCount: 3)
    #expect(secondRead.offset == 4)
    #expect(secondRead.length == 4)
    try await sourceFixture.server.appendSFTPMessages([
        .data(.init(requestID: secondRead.requestID, data: Array("ef".utf8))),
    ])

    let secondWrite = try await waitForWriteFile(from: destinationFixture, minimumCount: 3)
    #expect(secondWrite.offset == 4)
    #expect(secondWrite.data == Array("ef".utf8))
    try await destinationFixture.server.appendSFTPMessages([
        .status(makeSFTPStatusMessage(requestID: secondWrite.requestID, statusCode: .ok)),
    ])

    let eofRead = try await waitForReadFile(from: sourceFixture, minimumCount: 4)
    #expect(eofRead.offset == 6)
    try await sourceFixture.server.appendSFTPMessages([
        .status(makeSFTPStatusMessage(requestID: eofRead.requestID, statusCode: .endOfFile)),
    ])

    let destinationClose = try await waitForClose(from: destinationFixture, minimumCount: 4)
    #expect(destinationClose.handle == destinationHandle)
    try await destinationFixture.server.appendSFTPMessages([
        .status(makeSFTPStatusMessage(requestID: destinationClose.requestID, statusCode: .ok)),
    ])

    let sourceClose = try await waitForClose(from: sourceFixture, minimumCount: 5)
    #expect(sourceClose.handle == sourceHandle)
    try await sourceFixture.server.appendSFTPMessages([
        .status(makeSFTPStatusMessage(requestID: sourceClose.requestID, statusCode: .ok)),
    ])

    let bytesCopied = try await copyTask.value
    #expect(bytesCopied == 6)
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .write, bytesTransferred: 4),
                .init(operation: .write, bytesTransferred: 6),
            ]
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientCopiesZeroByteRemoteFileOnOneSFTPSession() async throws {
    let sourceHandle = SSHSFTPHandle(bytes: [0xaa, 0xbb, 0xcc, 0xdd])
    let destinationHandle = SSHSFTPHandle(bytes: [0xde, 0xad, 0xbe, 0xef])
    let fixture = try await makeConcurrentSFTPFixture(
        senderChannel: 107,
        sftpMessagesAfterVersion: [
            .handle(.init(requestID: 0, handle: sourceHandle)),
            .handle(.init(requestID: 1, handle: destinationHandle)),
            .status(makeSFTPStatusMessage(requestID: 2, statusCode: .endOfFile)),
            .status(makeSFTPStatusMessage(requestID: 3, statusCode: .ok)),
            .status(makeSFTPStatusMessage(requestID: 4, statusCode: .ok)),
        ]
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let bytesCopied = try await SFTPRemoteTransfer.copyFile(
        from: sftp,
        sourcePath: "/source/empty.txt",
        to: sftp,
        destinationPath: "/destination/empty.txt",
        chunkSize: 4
    )

    #expect(bytesCopied == 0)
    let sentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
    #expect(
        sentMessages == [
            .openFile(
                .init(
                    requestID: 0,
                    path: "/source/empty.txt",
                    pflags: [.read],
                    attributes: .empty
                )
            ),
            .openFile(
                .init(
                    requestID: 1,
                    path: "/destination/empty.txt",
                    pflags: [.write, .create, .truncate],
                    attributes: .empty
                )
            ),
            .readFile(
                .init(
                    requestID: 2,
                    handle: sourceHandle,
                    offset: 0,
                    length: 4
                )
            ),
            .close(.init(requestID: 3, handle: destinationHandle)),
            .close(.init(requestID: 4, handle: sourceHandle)),
        ]
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientCopiesRemoteDirectoryAndSkipsLinks() async throws {
    let rootDirectoryHandle = SSHSFTPHandle(bytes: [0x10, 0x20, 0x30, 0x40])
    let nestedDirectoryHandle = SSHSFTPHandle(bytes: [0x11, 0x21, 0x31, 0x41])
    let alphaSourceHandle = SSHSFTPHandle(bytes: [0x12, 0x22, 0x32, 0x42])
    let alphaDestinationHandle = SSHSFTPHandle(bytes: [0x13, 0x23, 0x33, 0x43])
    let betaSourceHandle = SSHSFTPHandle(bytes: [0x14, 0x24, 0x34, 0x44])
    let betaDestinationHandle = SSHSFTPHandle(bytes: [0x15, 0x25, 0x35, 0x45])
    let fixture = try await makeConcurrentSFTPFixture(
        senderChannel: 107,
        sftpMessagesAfterVersion: [
            .attributes(.init(requestID: 0, attributes: makeSFTPAttributes(permissions: 0o040755))),
            .status(makeSFTPStatusMessage(requestID: 1, statusCode: .ok)),
            .handle(.init(requestID: 2, handle: rootDirectoryHandle)),
            .name(
                .init(
                    requestID: 3,
                    entries: [
                        makeSFTPNameEntry(filename: "alpha.txt", size: 5, permissions: 0o100644),
                        makeSFTPNameEntry(filename: "nested", permissions: 0o040755),
                        makeSFTPNameEntry(filename: "latest", permissions: 0o120777),
                    ]
                )
            ),
            .status(makeSFTPStatusMessage(requestID: 4, statusCode: .endOfFile)),
            .status(makeSFTPStatusMessage(requestID: 5, statusCode: .ok)),
            .handle(.init(requestID: 6, handle: alphaSourceHandle)),
            .handle(.init(requestID: 7, handle: alphaDestinationHandle)),
            .data(.init(requestID: 8, data: Array("alph".utf8))),
            .status(makeSFTPStatusMessage(requestID: 9, statusCode: .ok)),
            .data(.init(requestID: 10, data: Array("a".utf8))),
            .status(makeSFTPStatusMessage(requestID: 11, statusCode: .ok)),
            .status(makeSFTPStatusMessage(requestID: 12, statusCode: .endOfFile)),
            .status(makeSFTPStatusMessage(requestID: 13, statusCode: .ok)),
            .status(makeSFTPStatusMessage(requestID: 14, statusCode: .ok)),
            .status(makeSFTPStatusMessage(requestID: 15, statusCode: .ok)),
            .handle(.init(requestID: 16, handle: nestedDirectoryHandle)),
            .name(
                .init(
                    requestID: 17,
                    entries: [
                        makeSFTPNameEntry(filename: "beta.txt", size: 3, permissions: 0o100644),
                    ]
                )
            ),
            .status(makeSFTPStatusMessage(requestID: 18, statusCode: .endOfFile)),
            .status(makeSFTPStatusMessage(requestID: 19, statusCode: .ok)),
            .handle(.init(requestID: 20, handle: betaSourceHandle)),
            .handle(.init(requestID: 21, handle: betaDestinationHandle)),
            .data(.init(requestID: 22, data: Array("bet".utf8))),
            .status(makeSFTPStatusMessage(requestID: 23, statusCode: .ok)),
            .status(makeSFTPStatusMessage(requestID: 24, statusCode: .endOfFile)),
            .status(makeSFTPStatusMessage(requestID: 25, statusCode: .ok)),
            .status(makeSFTPStatusMessage(requestID: 26, statusCode: .ok)),
        ],
        initialWindowSize: 4_096
    )
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let summary = try await SFTPRemoteTransfer.copyDirectory(
        from: sftp,
        sourcePath: "/root/project",
        to: sftp,
        destinationPath: "/copy/project",
        chunkSize: 4,
        progress: { value in
            await progressRecorder.record(value)
        }
    )

    #expect(
        summary == SSHSFTPDirectoryTransferSummary(
            bytesTransferred: 8,
            filesTransferred: 2,
            directoriesTraversed: 2,
            skippedEntries: 1
        )
    )
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .write, bytesTransferred: 4, totalBytes: nil),
                .init(operation: .write, bytesTransferred: 5, totalBytes: nil),
                .init(operation: .write, bytesTransferred: 8, totalBytes: nil),
            ]
    )

    let sentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
    let openFilePaths = sentMessages.compactMap { message -> String? in
        if case let .openFile(openFile) = message {
            return openFile.path
        }
        return nil
    }
    #expect(
        openFilePaths == [
            "/root/project/alpha.txt",
            "/copy/project/alpha.txt",
            "/root/project/nested/beta.txt",
            "/copy/project/nested/beta.txt",
        ]
    )
    #expect(
        sentMessages.contains(
            .makeDirectory(.init(requestID: 1, path: "/copy/project", attributes: .empty))
        )
    )
    #expect(
        sentMessages.contains(
            .makeDirectory(.init(requestID: 15, path: "/copy/project/nested", attributes: .empty))
        )
    )
    #expect(openFilePaths.contains("/root/project/latest") == false)
    #expect(openFilePaths.contains("/copy/project/latest") == false)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func waitForOpenFile(
    from fixture: ConcurrentSFTPFixture,
    minimumCount: Int
) async throws -> SSHSFTPOpenFileMessage {
    let messages = try await waitForSentSFTPMessages(
        minimumCount: minimumCount,
        from: fixture
    )
    guard case let .openFile(message)? = messages.last else {
        throw TestFailure("Expected openFile, got \(String(describing: messages.last))")
    }
    return message
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func waitForReadFile(
    from fixture: ConcurrentSFTPFixture,
    minimumCount: Int
) async throws -> SSHSFTPReadFileMessage {
    let messages = try await waitForSentSFTPMessages(
        minimumCount: minimumCount,
        from: fixture
    )
    guard case let .readFile(message)? = messages.last else {
        throw TestFailure("Expected readFile, got \(String(describing: messages.last))")
    }
    return message
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func waitForWriteFile(
    from fixture: ConcurrentSFTPFixture,
    minimumCount: Int
) async throws -> SSHSFTPWriteFileMessage {
    let messages = try await waitForSentSFTPMessages(
        minimumCount: minimumCount,
        from: fixture
    )
    guard case let .writeFile(message)? = messages.last else {
        throw TestFailure("Expected writeFile, got \(String(describing: messages.last))")
    }
    return message
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func waitForClose(
    from fixture: ConcurrentSFTPFixture,
    minimumCount: Int
) async throws -> SSHSFTPCloseMessage {
    let messages = try await waitForSentSFTPMessages(
        minimumCount: minimumCount,
        from: fixture
    )
    guard case let .close(message)? = messages.last else {
        throw TestFailure("Expected close, got \(String(describing: messages.last))")
    }
    return message
}

private struct TestFailure: Error, CustomStringConvertible {
    let description: String

    init(_ description: String) {
        self.description = description
    }
}

private func makeSFTPNameEntry(
    filename: String,
    size: UInt64? = nil,
    permissions: UInt32? = nil
) -> SSHSFTPNameEntry {
    SSHSFTPNameEntry(
        filename: filename,
        longName: filename,
        attributes: makeSFTPAttributes(size: size, permissions: permissions)
    )
}

private func makeSFTPAttributes(
    size: UInt64? = nil,
    permissions: UInt32? = nil
) -> SSHSFTPFileAttributes {
    SSHSFTPFileAttributes(
        flags: SSHSFTPFileAttributes.flags(
            size: size,
            permissions: permissions
        ),
        size: size,
        userID: nil,
        groupID: nil,
        permissions: permissions,
        accessTime: nil,
        modificationTime: nil,
        extensions: []
    )
}

private func makeSFTPStatusMessage(
    requestID: UInt32,
    statusCode: SSHSFTPStatusCode
) -> SSHSFTPStatusMessage {
    SSHSFTPStatusMessage(
        requestID: requestID,
        statusCode: statusCode,
        errorMessage: "",
        languageTag: ""
    )
}

private extension SSHSFTPFileAttributes {
    static func flags(size: UInt64?, permissions: UInt32?) -> UInt32 {
        var flags: UInt32 = 0
        if size != nil {
            flags |= Self.sizeFlag
        }
        if permissions != nil {
            flags |= Self.permissionsFlag
        }
        return flags
    }
}
