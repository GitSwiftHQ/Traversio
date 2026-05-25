// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientDownloadsRemoteFileToLocalURL() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x10, 0x32, 0x54, 0x76])
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }
    let localURL = temporaryDirectory
        .appendingPathComponent("nested", isDirectory: true)
        .appendingPathComponent("output.txt")

    let downloadTask = Task {
        try await sftp.downloadFile(
            "/root/output.txt",
            to: localURL,
            expectedSize: 7,
            chunkSize: 4,
            maxConcurrentReads: 1
        ) { value in
            await progressRecorder.record(value)
        }
    }
    defer { downloadTask.cancel() }

    let openMessages = try await waitForSentSFTPMessages(minimumCount: 1, from: fixture)
    let openMessage = try #require(openMessages.last)
    let openRequest: SSHSFTPOpenFileMessage
    switch openMessage {
    case let .openFile(message):
        openRequest = message
    default:
        Issue.record("Expected first SFTP message to be openFile, got \(openMessage)")
        return
    }
    #expect(openRequest.path == "/root/output.txt")
    #expect(openRequest.pflags == [.read])

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let firstReadMessages = try await waitForSentSFTPMessages(minimumCount: 2, from: fixture)
    let firstReadMessage = try #require(firstReadMessages.last)
    let firstReadRequest: SSHSFTPReadFileMessage
    switch firstReadMessage {
    case let .readFile(message):
        firstReadRequest = message
    default:
        Issue.record("Expected second SFTP message to be readFile, got \(firstReadMessage)")
        return
    }
    #expect(firstReadRequest.offset == 0)
    #expect(firstReadRequest.length == 4)

    try await fixture.server.appendSFTPMessages(
        [
            .data(
                SSHSFTPDataMessage(
                    requestID: firstReadRequest.requestID,
                    data: Array("abcd".utf8)
                )
            )
        ]
    )

    let secondReadMessages = try await waitForSentSFTPMessages(minimumCount: 3, from: fixture)
    let secondReadMessage = try #require(secondReadMessages.last)
    let secondReadRequest: SSHSFTPReadFileMessage
    switch secondReadMessage {
    case let .readFile(message):
        secondReadRequest = message
    default:
        Issue.record("Expected third SFTP message to be readFile, got \(secondReadMessage)")
        return
    }
    #expect(secondReadRequest.offset == 4)
    #expect(secondReadRequest.length == 4)

    try await fixture.server.appendSFTPMessages(
        [
            .data(
                SSHSFTPDataMessage(
                    requestID: secondReadRequest.requestID,
                    data: Array("efg".utf8)
                )
            )
        ]
    )

    let eofReadMessages = try await waitForSentSFTPMessages(minimumCount: 4, from: fixture)
    let eofReadMessage = try #require(eofReadMessages.last)
    let eofReadRequest: SSHSFTPReadFileMessage
    switch eofReadMessage {
    case let .readFile(message):
        eofReadRequest = message
    default:
        Issue.record("Expected fourth SFTP message to be readFile, got \(eofReadMessage)")
        return
    }
    #expect(eofReadRequest.offset == 7)
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
            )
        ]
    )

    let closeMessages = try await waitForSentSFTPMessages(minimumCount: 5, from: fixture)
    let closeMessage = try #require(closeMessages.last)
    let closeRequest: SSHSFTPCloseMessage
    switch closeMessage {
    case let .close(message):
        closeRequest = message
    default:
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

    let bytesDownloaded = try await downloadTask.value
    #expect(bytesDownloaded == 7)
    #expect(String(decoding: try Data(contentsOf: localURL), as: UTF8.self) == "abcdefg")
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .read, bytesTransferred: 4, totalBytes: 7),
                .init(operation: .read, bytesTransferred: 7, totalBytes: 7),
            ]
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientDownloadsRemoteFileToLocalURLWithConcurrentReads() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x21, 0x43, 0x65, 0x87])
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }
    let localURL = temporaryDirectory.appendingPathComponent("windowed.txt")

    let downloadTask = Task {
        try await sftp.downloadFile(
            "/root/windowed.txt",
            to: localURL,
            expectedSize: 12,
            chunkSize: 4,
            maxConcurrentReads: 3
        ) { value in
            await progressRecorder.record(value)
        }
    }
    defer { downloadTask.cancel() }

    let openMessages = try await waitForSentSFTPMessages(minimumCount: 1, from: fixture)
    let openMessage = try #require(openMessages.last)
    let openRequest: SSHSFTPOpenFileMessage
    switch openMessage {
    case let .openFile(message):
        openRequest = message
    default:
        Issue.record("Expected first SFTP message to be openFile, got \(openMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let readMessages = try await waitForSentSFTPMessages(minimumCount: 4, from: fixture)
    let readRequests = readMessages.compactMap { message -> SSHSFTPReadFileMessage? in
        if case let .readFile(readRequest) = message {
            return readRequest
        }
        return nil
    }
    #expect(readRequests.map(\.offset) == [0, 4, 8])
    #expect(readRequests.map(\.length) == [4, 4, 4])

    let firstReadRequest = try #require(readRequests.first { $0.offset == 0 })
    let secondReadRequest = try #require(readRequests.first { $0.offset == 4 })
    let thirdReadRequest = try #require(readRequests.first { $0.offset == 8 })

    try await fixture.server.appendSFTPMessages(
        [
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
            .data(
                SSHSFTPDataMessage(
                    requestID: thirdReadRequest.requestID,
                    data: Array("ijkl".utf8)
                )
            ),
        ]
    )

    let closeMessages = try await waitForSentSFTPMessages(minimumCount: 5, from: fixture)
    let closeMessage = try #require(closeMessages.last)
    let closeRequest: SSHSFTPCloseMessage
    switch closeMessage {
    case let .close(message):
        closeRequest = message
    default:
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

    let bytesDownloaded = try await downloadTask.value
    #expect(bytesDownloaded == 12)
    #expect(String(decoding: try Data(contentsOf: localURL), as: UTF8.self) == "abcdefghijkl")
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .read, bytesTransferred: 4, totalBytes: 12),
                .init(operation: .read, bytesTransferred: 8, totalBytes: 12),
                .init(operation: .read, bytesTransferred: 12, totalBytes: 12),
            ]
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientDownloadLocalFileURLDefaultsToOpenSSHStyleReadWindow() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x62, 0x75, 0x6c, 0x6b])
    let fixture = try await makeConcurrentSFTPFixture(
        senderChannel: 107,
        initialWindowSize: 1_000_000
    )
    let defaultChunkSize = UInt64(32 * 1_024)
    let expectedSize = defaultChunkSize * 65

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }
    let localURL = temporaryDirectory.appendingPathComponent("default-window.bin")

    let downloadTask = Task {
        try await sftp.downloadFile(
            "/root/default-window.bin",
            to: localURL,
            expectedSize: expectedSize
        )
    }
    defer { downloadTask.cancel() }

    let openMessages = try await waitForSentSFTPMessages(minimumCount: 1, from: fixture)
    let openMessage = try #require(openMessages.last)
    let openRequest: SSHSFTPOpenFileMessage
    switch openMessage {
    case let .openFile(message):
        openRequest = message
    default:
        Issue.record("Expected first SFTP message to be openFile, got \(openMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let initialMessages = try await waitForSentSFTPMessages(minimumCount: 65, from: fixture)
    let initialReadRequests = initialMessages.compactMap { message -> SSHSFTPReadFileMessage? in
        if case let .readFile(readRequest) = message {
            return readRequest
        }
        return nil
    }
    let defaultChunkLength = UInt32(32 * 1_024)
    #expect(initialReadRequests.count == 64)
    #expect(initialReadRequests.map(\.offset) == (0..<64).map { UInt64($0) * defaultChunkSize })
    #expect(initialReadRequests.map(\.length) == Array(repeating: defaultChunkLength, count: 64))

    let firstReadRequest = try #require(initialReadRequests.first)
    try await fixture.server.appendSFTPMessages(
        [
            .data(
                SSHSFTPDataMessage(
                    requestID: firstReadRequest.requestID,
                    data: Array(repeating: 0x01, count: Int(firstReadRequest.length))
                )
            )
        ]
    )

    let windowRefillMessages = try await waitForSentSFTPMessages(minimumCount: 66, from: fixture)
    let allReadRequests = windowRefillMessages.compactMap { message -> SSHSFTPReadFileMessage? in
        if case let .readFile(readRequest) = message {
            return readRequest
        }
        return nil
    }
    #expect(allReadRequests.count == 65)
    #expect(allReadRequests.last?.offset == defaultChunkSize * 64)
    #expect(allReadRequests.last?.length == defaultChunkLength)

    try await fixture.server.appendSFTPMessages(
        allReadRequests.dropFirst().map { request in
            .data(
                SSHSFTPDataMessage(
                    requestID: request.requestID,
                    data: Array(repeating: 0x02, count: Int(request.length))
                )
            )
        }
    )

    let closeMessages = try await waitForSentSFTPMessages(minimumCount: 67, from: fixture)
    let closeMessage = try #require(closeMessages.last)
    let closeRequest: SSHSFTPCloseMessage
    switch closeMessage {
    case let .close(message):
        closeRequest = message
    default:
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

    let bytesDownloaded = try await downloadTask.value
    let fileSize = try FileManager.default.attributesOfItem(atPath: localURL.path)[.size] as? NSNumber
    #expect(bytesDownloaded == expectedSize)
    #expect(fileSize?.uint64Value == expectedSize)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientDownloadLocalFileURLContinuesAfterShortConcurrentRead() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x21, 0x43, 0x65, 0x87])
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }
    let localURL = temporaryDirectory.appendingPathComponent("short-read.txt")

    let downloadTask = Task {
        try await sftp.downloadFile(
            "/root/short-read.txt",
            to: localURL,
            expectedSize: 12,
            chunkSize: 4,
            maxConcurrentReads: 3
        )
    }
    defer { downloadTask.cancel() }

    let openMessages = try await waitForSentSFTPMessages(minimumCount: 1, from: fixture)
    let openMessage = try #require(openMessages.last)
    let openRequest: SSHSFTPOpenFileMessage
    switch openMessage {
    case let .openFile(message):
        openRequest = message
    default:
        Issue.record("Expected first SFTP message to be openFile, got \(openMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let initialReadMessages = try await waitForSentSFTPMessages(minimumCount: 4, from: fixture)
    let initialReadRequests = initialReadMessages.compactMap { message -> SSHSFTPReadFileMessage? in
        if case let .readFile(readRequest) = message {
            return readRequest
        }
        return nil
    }
    #expect(initialReadRequests.map(\.offset) == [0, 4, 8])
    #expect(initialReadRequests.map(\.length) == [4, 4, 4])

    let firstReadRequest = try #require(initialReadRequests.first { $0.offset == 0 })
    try await fixture.server.appendSFTPMessages(
        [
            .data(
                SSHSFTPDataMessage(
                    requestID: firstReadRequest.requestID,
                    data: Array("abc".utf8)
                )
            )
        ]
    )

    let retryReadRequest = try await waitForSentSFTPReadRequest(offset: 3, from: fixture)
    #expect(retryReadRequest.length == 4)
    try await fixture.server.appendSFTPMessages(
        [
            .data(
                SSHSFTPDataMessage(
                    requestID: retryReadRequest.requestID,
                    data: Array("defg".utf8)
                )
            )
        ]
    )

    let secondRetryRequest = try await waitForSentSFTPReadRequest(offset: 7, from: fixture)
    #expect(secondRetryRequest.length == 4)
    try await fixture.server.appendSFTPMessages(
        [
            .data(
                SSHSFTPDataMessage(
                    requestID: secondRetryRequest.requestID,
                    data: Array("hijk".utf8)
                )
            )
        ]
    )

    let finalReadRequest = try await waitForSentSFTPReadRequest(offset: 11, from: fixture)
    #expect(finalReadRequest.length == 1)
    try await fixture.server.appendSFTPMessages(
        [
            .data(
                SSHSFTPDataMessage(
                    requestID: finalReadRequest.requestID,
                    data: Array("l".utf8)
                )
            )
        ]
    )

    let closeMessages = try await waitForSentSFTPMessages(minimumCount: 8, from: fixture)
    let closeMessage = try #require(closeMessages.last)
    let closeRequest: SSHSFTPCloseMessage
    switch closeMessage {
    case let .close(message):
        closeRequest = message
    default:
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

    let bytesDownloaded = try await downloadTask.value
    #expect(bytesDownloaded == 12)
    #expect(String(decoding: try Data(contentsOf: localURL), as: UTF8.self) == "abcdefghijkl")
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientDownloadLocalFileURLStopsBeforeNextReadWhenContinuationStops() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x20, 0x42, 0x64, 0x86])
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)
    let progressRecorder = SFTPTransferProgressRecorder()
    let continuation = SFTPTransferContinuationRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }
    let localURL = temporaryDirectory.appendingPathComponent("partial.txt")

    let downloadTask = Task {
        try await sftp.downloadFile(
            "/root/partial.txt",
            to: localURL,
            chunkSize: 4,
            maxConcurrentReads: 1,
            progress: { value in
                await progressRecorder.record(value)
                await continuation.stop()
            },
            shouldContinue: {
                await continuation.shouldContinue()
            }
        )
    }
    defer { downloadTask.cancel() }

    let openMessages = try await waitForSentSFTPMessages(minimumCount: 1, from: fixture)
    let openMessage = try #require(openMessages.last)
    let openRequest: SSHSFTPOpenFileMessage
    switch openMessage {
    case let .openFile(message):
        openRequest = message
    default:
        Issue.record("Expected first SFTP message to be openFile, got \(openMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let firstReadMessages = try await waitForSentSFTPMessages(minimumCount: 2, from: fixture)
    let firstReadMessage = try #require(firstReadMessages.last)
    let firstReadRequest: SSHSFTPReadFileMessage
    switch firstReadMessage {
    case let .readFile(message):
        firstReadRequest = message
    default:
        Issue.record("Expected second SFTP message to be readFile, got \(firstReadMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .data(
                SSHSFTPDataMessage(
                    requestID: firstReadRequest.requestID,
                    data: Array("abcd".utf8)
                )
            )
        ]
    )

    let closeMessages = try await waitForSentSFTPMessages(minimumCount: 3, from: fixture)
    let closeMessage = try #require(closeMessages.last)
    let closeRequest: SSHSFTPCloseMessage
    switch closeMessage {
    case let .close(message):
        closeRequest = message
    default:
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

    do {
        _ = try await downloadTask.value
        Issue.record("Expected transfer continuation stop to cancel the download")
    } catch is CancellationError {
    } catch {
        Issue.record("Expected CancellationError, got \(String(reflecting: error))")
    }

    #expect(String(decoding: try Data(contentsOf: localURL), as: UTF8.self) == "abcd")
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .read, bytesTransferred: 4, totalBytes: nil),
            ]
    )

    let sentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
    #expect(
        sentMessages
            == [
                .openFile(
                    .init(
                        requestID: 0,
                        path: "/root/partial.txt",
                        pflags: [.read],
                        attributes: .empty
                    )
                ),
                .readFile(
                    .init(
                        requestID: 1,
                        handle: fileHandle,
                        offset: 0,
                        length: 4
                    )
                ),
                .close(
                    .init(
                        requestID: 2,
                        handle: fileHandle
                    )
                ),
            ]
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientUploadsLocalFileURLToRemotePath() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0xaa, 0xbb, 0xcc, 0xdd])
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: temporaryDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }
    let localURL = temporaryDirectory.appendingPathComponent("upload.txt")
    try Data("abcdefg".utf8).write(to: localURL)

    let uploadTask = Task {
        try await sftp.uploadFile(
            from: localURL,
            to: "/root/upload.txt",
            chunkSize: 4,
            maxConcurrentWrites: 1,
            progress: { value in
                await progressRecorder.record(value)
            }
        )
    }
    defer { uploadTask.cancel() }

    let openMessages = try await waitForSentSFTPMessages(minimumCount: 1, from: fixture)
    let openMessage = try #require(openMessages.last)
    let openRequest: SSHSFTPOpenFileMessage
    switch openMessage {
    case let .openFile(message):
        openRequest = message
    default:
        Issue.record("Expected first SFTP message to be openFile, got \(openMessage)")
        return
    }
    #expect(openRequest.path == "/root/upload.txt")
    #expect(openRequest.pflags == [.write, .create, .truncate])

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let firstWriteMessages = try await waitForSentSFTPMessages(minimumCount: 2, from: fixture)
    let firstWriteMessage = try #require(firstWriteMessages.last)
    let firstWriteRequest: SSHSFTPWriteFileMessage
    switch firstWriteMessage {
    case let .writeFile(message):
        firstWriteRequest = message
    default:
        Issue.record("Expected second SFTP message to be writeFile, got \(firstWriteMessage)")
        return
    }
    #expect(firstWriteRequest.offset == 0)
    #expect(firstWriteRequest.data == Array("abcd".utf8))

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: firstWriteRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    let secondWriteMessages = try await waitForSentSFTPMessages(minimumCount: 3, from: fixture)
    let secondWriteMessage = try #require(secondWriteMessages.last)
    let secondWriteRequest: SSHSFTPWriteFileMessage
    switch secondWriteMessage {
    case let .writeFile(message):
        secondWriteRequest = message
    default:
        Issue.record("Expected third SFTP message to be writeFile, got \(secondWriteMessage)")
        return
    }
    #expect(secondWriteRequest.offset == 4)
    #expect(secondWriteRequest.data == Array("efg".utf8))

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: secondWriteRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    let closeMessages = try await waitForSentSFTPMessages(minimumCount: 4, from: fixture)
    let closeMessage = try #require(closeMessages.last)
    let closeRequest: SSHSFTPCloseMessage
    switch closeMessage {
    case let .close(message):
        closeRequest = message
    default:
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

    let bytesUploaded = try await uploadTask.value
    #expect(bytesUploaded == 7)
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .write, bytesTransferred: 4, totalBytes: 7),
                .init(operation: .write, bytesTransferred: 7, totalBytes: 7),
            ]
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientUploadsLocalFileURLToRemotePathWithConcurrentWrites() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x41, 0x52, 0x63, 0x74])
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: temporaryDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }
    let localURL = temporaryDirectory.appendingPathComponent("upload-windowed.txt")
    try Data("abcdefghijkl".utf8).write(to: localURL)

    let uploadTask = Task {
        try await sftp.uploadFile(
            from: localURL,
            to: "/root/upload-windowed.txt",
            chunkSize: 4,
            maxConcurrentWrites: 3,
            progress: { value in
                await progressRecorder.record(value)
            }
        )
    }
    defer { uploadTask.cancel() }

    let openMessages = try await waitForSentSFTPMessages(minimumCount: 1, from: fixture)
    let openMessage = try #require(openMessages.last)
    let openRequest: SSHSFTPOpenFileMessage
    switch openMessage {
    case let .openFile(message):
        openRequest = message
    default:
        Issue.record("Expected first SFTP message to be openFile, got \(openMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let writeMessages = try await waitForSentSFTPMessages(minimumCount: 4, from: fixture)
    let writeRequests = writeMessages.compactMap { message -> SSHSFTPWriteFileMessage? in
        if case let .writeFile(writeRequest) = message {
            return writeRequest
        }
        return nil
    }
    #expect(writeRequests.map(\.offset) == [0, 4, 8])
    #expect(writeRequests.map(\.data) == [
        Array("abcd".utf8),
        Array("efgh".utf8),
        Array("ijkl".utf8),
    ])

    let firstWriteRequest = try #require(writeRequests.first { $0.offset == 0 })
    let secondWriteRequest = try #require(writeRequests.first { $0.offset == 4 })
    let thirdWriteRequest = try #require(writeRequests.first { $0.offset == 8 })

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

    let closeMessages = try await waitForSentSFTPMessages(minimumCount: 5, from: fixture)
    let closeMessage = try #require(closeMessages.last)
    let closeRequest: SSHSFTPCloseMessage
    switch closeMessage {
    case let .close(message):
        closeRequest = message
    default:
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

    let bytesUploaded = try await uploadTask.value
    #expect(bytesUploaded == 12)
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .write, bytesTransferred: 4, totalBytes: 12),
                .init(operation: .write, bytesTransferred: 8, totalBytes: 12),
                .init(operation: .write, bytesTransferred: 12, totalBytes: 12),
            ]
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sftpFileHandleReportsPacketSafeTransferLengths() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x31, 0x42, 0x53, 0x64])
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let openTask = Task {
        try await sftp.openFile("/root/packet-safe.bin", flags: [.read])
    }
    defer { openTask.cancel() }

    let openMessages = try await waitForSentSFTPMessages(minimumCount: 1, from: fixture)
    let openMessage = try #require(openMessages.last)
    let openRequest: SSHSFTPOpenFileMessage
    switch openMessage {
    case let .openFile(message):
        openRequest = message
    default:
        Issue.record("Expected first SFTP message to be openFile, got \(openMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let handle = try await openTask.value
    #expect(
        await handle.effectiveReadLength(SSHSFTPPacketSerializer.defaultMaximumPacketLength)
            == UInt32(maximumSFTPReadDataLength())
    )
    #expect(await handle.maximumWriteDataLength() == maximumSFTPWriteDataLength(for: fileHandle))

    let closeTask = Task {
        try await handle.close()
    }

    let closeMessages = try await waitForSentSFTPMessages(minimumCount: 3, from: fixture)
    let closeMessage = try #require(closeMessages.last)
    let closeRequest: SSHSFTPCloseMessage
    switch closeMessage {
    case let .close(message):
        closeRequest = message
    default:
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
    try await closeTask.value
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientUploadLocalFileURLRejectsDirectoryPath() async throws {
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: temporaryDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    do {
        _ = try await sftp.uploadFile(
            from: temporaryDirectory,
            to: "/root/upload.txt"
        )
        Issue.record("Expected directory upload to fail")
    } catch let error as SSHSFTPLocalFileTransferError {
        #expect(error == .localURLReferencesDirectory(temporaryDirectory))
    } catch {
        Issue.record("Expected SSHSFTPLocalFileTransferError, got \(String(reflecting: error))")
    }

    let sentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
    #expect(sentMessages.isEmpty)
}

private func maximumSFTPReadDataLength() -> Int {
    Int(SSHSFTPPacketSerializer.defaultMaximumPacketLength) - 9
}

private func maximumSFTPWriteDataLength(for handle: SSHSFTPHandle) -> Int {
    Int(SSHSFTPPacketSerializer.defaultMaximumPacketLength) - 21 - handle.bytes.count
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func waitForSentSFTPReadRequest(
    offset: UInt64,
    from fixture: ConcurrentSFTPFixture
) async throws -> SSHSFTPReadFileMessage {
    for _ in 0..<500 {
        let readRequests = try await sentSFTPReadRequests(from: fixture)
        if let request = readRequests.first(where: { $0.offset == offset }) {
            return request
        }
        try? await Task.sleep(nanoseconds: 1_000_000)
    }

    let readRequests = try await sentSFTPReadRequests(from: fixture)
    return try #require(readRequests.first { $0.offset == offset })
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func sentSFTPReadRequests(
    from fixture: ConcurrentSFTPFixture
) async throws -> [SSHSFTPReadFileMessage] {
    try await extractConcurrentSentSFTPMessages(from: fixture).compactMap { message in
        if case let .readFile(readRequest) = message {
            return readRequest
        }
        return nil
    }
}

private actor SFTPTransferContinuationRecorder {
    private var value = true

    func shouldContinue() -> Bool {
        self.value
    }

    func stop() {
        self.value = false
    }
}
