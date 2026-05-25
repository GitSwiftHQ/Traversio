// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRoutesConcurrentSFTPRepliesByRequestID() async throws {
    let expectedAttributes = SSHSFTPFileAttributes(
        flags: SSHSFTPFileAttributes.sizeFlag | SSHSFTPFileAttributes.permissionsFlag,
        size: 512,
        userID: nil,
        groupID: nil,
        permissions: 0o644,
        accessTime: nil,
        modificationTime: nil,
        extensions: []
    )
    let expectedLinkEntry = SSHSFTPNameEntry(
        filename: "/root/releases/current",
        longName: "/root/releases/current",
        attributes: .empty
    )
    let fixture = try await makeConcurrentSFTPFixture(
        senderChannel: 104
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    let statTask = Task {
        try await sftpClient.stat("/root/example.txt")
    }

    let firstSentMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    #expect(firstSentMessages.count == 1)
    let statRequestID = try #require(firstStatRequestID(in: firstSentMessages))

    let readLinkTask = Task {
        try await sftpClient.readLink("/root/current")
    }

    let sentSFTPMessages = try await waitForSentSFTPMessages(
        minimumCount: 2,
        from: fixture
    )
    #expect(sentSFTPMessages.count == 2)
    let readLinkRequestID = try #require(firstReadLinkRequestID(in: sentSFTPMessages))

    try await fixture.server.appendSFTPMessages(
        [
            .name(
                SSHSFTPNameMessage(
                    requestID: readLinkRequestID,
                    entries: [expectedLinkEntry]
                )
            ),
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: statRequestID,
                    attributes: expectedAttributes
                )
            ),
        ]
    )

    let receivedAttributes = try await statTask.value
    let receivedLinkEntry = try await readLinkTask.value

    #expect(receivedAttributes == expectedAttributes)
    #expect(receivedLinkEntry == expectedLinkEntry)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientIgnoresCancelledSFTPReplyWithoutBreakingConcurrentWaiters() async throws {
    let survivingEntry = SSHSFTPNameEntry(
        filename: "/root/releases/live",
        longName: "/root/releases/live",
        attributes: .empty
    )
    let fixture = try await makeConcurrentSFTPFixture(
        senderChannel: 105
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    let cancelledTask = Task {
        try await sftpClient.stat("/root/cancelled.txt")
    }

    let firstSentMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    #expect(firstSentMessages.count == 1)
    let cancelledRequestID = try #require(firstStatRequestID(in: firstSentMessages))

    let survivingTask = Task {
        try await sftpClient.readLink("/root/current")
    }

    let sentSFTPMessages = try await waitForSentSFTPMessages(
        minimumCount: 2,
        from: fixture
    )
    #expect(sentSFTPMessages.count == 2)
    let survivingRequestID = try #require(firstReadLinkRequestID(in: sentSFTPMessages))

    cancelledTask.cancel()

    do {
        _ = try await cancelledTask.value
        Issue.record("Expected cancelled SFTP request to throw CancellationError")
    } catch is CancellationError {
    } catch {
        Issue.record("Expected CancellationError, got \(String(reflecting: error))")
    }

    try await fixture.server.appendSFTPMessages(
        [
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: cancelledRequestID,
                    attributes: SSHSFTPFileAttributes(
                        flags: SSHSFTPFileAttributes.sizeFlag,
                        size: 1_024,
                        userID: nil,
                        groupID: nil,
                        permissions: nil,
                        accessTime: nil,
                        modificationTime: nil,
                        extensions: []
                    )
                )
            ),
            .name(
                SSHSFTPNameMessage(
                    requestID: survivingRequestID,
                    entries: [survivingEntry]
                )
            ),
        ]
    )

    let receivedEntry = try await survivingTask.value
    #expect(receivedEntry == survivingEntry)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientDoesNotStartSFTPReceiveLoopWhenRequestSendFails() async throws {
    let fixture = try await makeConcurrentSFTPFixture(
        senderChannel: 115
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()
    #expect(await fixture.transport.activeReceiveCountObserved() == 0)

    await fixture.transport.enqueueSendFailure(.ECONNRESET)

    do {
        _ = try await sftpClient.stat("/root/example.txt")
        Issue.record("Expected SFTP stat send failure")
    } catch let error as POSIXError {
        #expect(error.code == .ECONNRESET)
    } catch {
        Issue.record("Expected POSIX ECONNRESET, got \(String(reflecting: error))")
    }

    for _ in 0..<20 {
        await Task.yield()
    }
    #expect(await fixture.transport.activeReceiveCountObserved() == 0)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReadsWholeFileWithBoundedConcurrentSFTPRequests() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0xde, 0xad, 0xbe, 0xef])
    let fixture = try await makeConcurrentSFTPFixture(
        senderChannel: 106
    )
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    let readTask = Task {
        try await sftpClient.readFile(
            "/root/example.txt",
            chunkSize: 4,
            maxConcurrentReads: 3,
            progress: { value in
                await progressRecorder.record(value)
            }
        )
    }
    defer { readTask.cancel() }

    let openFileMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    let openFileMessage = try #require(openFileMessages.first)
    let openFileRequest: SSHSFTPOpenFileMessage
    switch openFileMessage {
    case let .openFile(message):
        openFileRequest = message
    default:
        Issue.record("Expected first SFTP message to be openFile, got \(openFileMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openFileRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let sentMessages = try await waitForSentSFTPMessages(
        minimumCount: 4,
        from: fixture
    )
    #expect(sentMessages.count == 4)

    let readRequests = sentMessages.compactMap { message -> SSHSFTPReadFileMessage? in
        guard case let .readFile(readMessage) = message else {
            return nil
        }
        return readMessage
    }
    #expect(readRequests.count == 3)
    #expect(readRequests.map(\.handle).allSatisfy { $0 == fileHandle })
    #expect(readRequests.map(\.offset) == [0, 4, 8])
    #expect(readRequests.map(\.length) == [4, 4, 4])

    let firstReadRequest = try #require(readRequests.first(where: { $0.offset == 0 }))
    let secondReadRequest = try #require(readRequests.first(where: { $0.offset == 4 }))
    let terminalReadRequest = try #require(readRequests.first(where: { $0.offset == 8 }))

    try await fixture.server.appendSFTPMessages(
        [
            .data(
                SSHSFTPDataMessage(
                    requestID: terminalReadRequest.requestID,
                    data: Array("ij".utf8)
                )
            ),
            .data(
                SSHSFTPDataMessage(
                    requestID: secondReadRequest.requestID,
                    data: Array("efgh".utf8)
                )
            ),
            .data(
                SSHSFTPDataMessage(
                    requestID: firstReadRequest.requestID,
                    data: Array("abcd".utf8)
                )
            ),
        ]
    )

    let sentMessagesAfterEOFRead = try await waitForSentSFTPMessages(
        minimumCount: 7,
        from: fixture
    )
    #expect(sentMessagesAfterEOFRead.count == 7)
    let eofReadMessage = try #require(sentMessagesAfterEOFRead.last)

    guard case let .readFile(eofReadRequest) = eofReadMessage else {
        Issue.record("Expected trailing SFTP message to be readFile, got \(eofReadMessage)")
        return
    }

    #expect(eofReadRequest.handle == fileHandle)
    #expect(eofReadRequest.offset == 10)
    #expect(eofReadRequest.length == 4)

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: eofReadRequest.requestID,
                    statusCode: .endOfFile,
                    errorMessage: "",
                    languageTag: ""
                )
            ),
        ]
    )

    let sentMessagesAfterClose = try await waitForSentSFTPMessages(
        minimumCount: 8,
        from: fixture
    )
    #expect(sentMessagesAfterClose.count == 8)
    let closeMessage = try #require(sentMessagesAfterClose.last)

    guard case let .close(closeRequest) = closeMessage else {
        Issue.record("Expected trailing SFTP message to be close, got \(closeMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: closeRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    let fileData = try await readTask.value
    #expect(fileData == Array("abcdefghij".utf8))
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .read, bytesTransferred: 4),
                .init(operation: .read, bytesTransferred: 8),
                .init(operation: .read, bytesTransferred: 10),
            ]
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientClampsOversizedConcurrentSFTPReadRequestsToSafeDataLengths() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0xaa, 0xbb, 0xcc, 0xdd])
    let fixture = try await makeConcurrentSFTPFixture(
        senderChannel: 108
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    let readTask = Task {
        try await sftpClient.readFile(
            "/root/example.txt",
            chunkSize: SSHSFTPPacketSerializer.defaultMaximumPacketLength,
            maxConcurrentReads: 2
        )
    }
    defer { readTask.cancel() }

    let openFileMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    let openFileMessage = try #require(openFileMessages.first)
    let openFileRequest: SSHSFTPOpenFileMessage
    switch openFileMessage {
    case let .openFile(message):
        openFileRequest = message
    default:
        Issue.record("Expected first SFTP message to be openFile, got \(openFileMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openFileRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let sentMessages = try await waitForSentSFTPMessages(
        minimumCount: 3,
        from: fixture
    )
    let readRequests = sentMessages.compactMap { message -> SSHSFTPReadFileMessage? in
        guard case let .readFile(readMessage) = message else {
            return nil
        }
        return readMessage
    }

    #expect(readRequests.count == 2)

    let safeReadLength = UInt32(
        Int(SSHSFTPPacketSerializer.defaultMaximumPacketLength) - (1 + 4 + 4)
    )
    #expect(readRequests.map(\.handle).allSatisfy { $0 == fileHandle })
    #expect(readRequests.map(\.offset) == [0, UInt64(safeReadLength)])
    #expect(readRequests.map(\.length) == [safeReadLength, safeReadLength])

    let firstReadRequest = try #require(readRequests.first(where: { $0.offset == 0 }))

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: firstReadRequest.requestID,
                    statusCode: .endOfFile,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    let sentMessagesAfterClose = try await waitForSentSFTPMessages(
        minimumCount: 4,
        from: fixture
    )
    let closeMessage = try #require(sentMessagesAfterClose.last)

    guard case let .close(closeRequest) = closeMessage else {
        Issue.record("Expected trailing SFTP message to be close, got \(closeMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: closeRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    let fileData = try await readTask.value
    #expect(fileData.isEmpty)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientWritesWholeFileWithBoundedConcurrentSFTPRequests() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0xfa, 0xce, 0xb0, 0x0c])
    let fixture = try await makeConcurrentSFTPFixture(
        senderChannel: 107
    )
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftpClient = try await fixture.client.openSFTPClient()

    let writeTask = Task {
        try await sftpClient.writeFile(
            "/root/output.txt",
            data: Array("abcdefghij".utf8),
            chunkSize: 4,
            maxConcurrentWrites: 2,
            progress: { value in
                await progressRecorder.record(value)
            }
        )
    }
    defer { writeTask.cancel() }

    let openFileMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    let openFileMessage = try #require(openFileMessages.first)
    let openFileRequest: SSHSFTPOpenFileMessage
    switch openFileMessage {
    case let .openFile(message):
        openFileRequest = message
    default:
        Issue.record("Expected first SFTP message to be openFile, got \(openFileMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openFileRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let sentMessages = try await waitForSentSFTPMessages(
        minimumCount: 3,
        from: fixture
    )
    #expect(sentMessages.count == 3)

    let writeRequests = sentMessages.compactMap { message -> SSHSFTPWriteFileMessage? in
        guard case let .writeFile(writeMessage) = message else {
            return nil
        }
        return writeMessage
    }
    #expect(writeRequests.count == 2)
    #expect(writeRequests.map(\.handle).allSatisfy { $0 == fileHandle })
    #expect(writeRequests.map(\.offset) == [0, 4])
    #expect(writeRequests.map(\.data) == [Array("abcd".utf8), Array("efgh".utf8)])

    let firstWriteRequest = try #require(writeRequests.first(where: { $0.offset == 0 }))
    let secondWriteRequest = try #require(writeRequests.first(where: { $0.offset == 4 }))

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: secondWriteRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            ),
            .status(
                SSHSFTPStatusMessage(
                    requestID: firstWriteRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            ),
        ]
    )

    let sentMessagesAfterThirdWrite = try await waitForSentSFTPMessages(
        minimumCount: 4,
        from: fixture
    )
    #expect(sentMessagesAfterThirdWrite.count == 4)
    let thirdWriteMessage = try #require(sentMessagesAfterThirdWrite.last)

    guard case let .writeFile(thirdWriteRequest) = thirdWriteMessage else {
        Issue.record("Expected trailing SFTP message to be writeFile, got \(thirdWriteMessage)")
        return
    }

    #expect(thirdWriteRequest.handle == fileHandle)
    #expect(thirdWriteRequest.offset == 8)
    #expect(thirdWriteRequest.data == Array("ij".utf8))

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: thirdWriteRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            ),
        ]
    )

    let sentMessagesAfterClose = try await waitForSentSFTPMessages(
        minimumCount: 5,
        from: fixture
    )
    #expect(sentMessagesAfterClose.count == 5)
    let closeMessage = try #require(sentMessagesAfterClose.last)

    #expect(
        closeMessage
            == .close(
                SSHSFTPCloseMessage(
                    requestID: thirdWriteRequest.requestID + 1,
                    handle: fileHandle
                )
            )
    )

    guard case let .close(closeRequest) = closeMessage else {
        Issue.record("Expected trailing SFTP message to be close, got \(closeMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: closeRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    try await writeTask.value
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .write, bytesTransferred: 4, totalBytes: 10),
                .init(operation: .write, bytesTransferred: 8, totalBytes: 10),
                .init(operation: .write, bytesTransferred: 10, totalBytes: 10),
            ]
    )
}
