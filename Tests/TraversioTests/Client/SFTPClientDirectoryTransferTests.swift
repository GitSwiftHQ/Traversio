// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientDownloadsRemoteDirectoryToLocalURL() async throws {
    let rootDirectoryHandle = SSHSFTPHandle(bytes: [0x10, 0x20, 0x30, 0x40])
    let nestedDirectoryHandle = SSHSFTPHandle(bytes: [0x11, 0x21, 0x31, 0x41])
    let alphaHandle = SSHSFTPHandle(bytes: [0x12, 0x22, 0x32, 0x42])
    let betaHandle = SSHSFTPHandle(bytes: [0x13, 0x23, 0x33, 0x43])
    let fixture = try await makeConcurrentSFTPFixture(
        senderChannel: 107,
        sftpMessagesAfterVersion: [
            .handle(.init(requestID: 0, handle: rootDirectoryHandle)),
            .name(
                .init(
                    requestID: 1,
                    entries: [
                        makeNameEntry(
                            filename: "alpha.txt",
                            size: 5,
                            permissions: 0o100644
                        ),
                        makeNameEntry(
                            filename: "nested",
                            permissions: 0o040755
                        ),
                        makeNameEntry(
                            filename: "latest",
                            permissions: 0o120777
                        ),
                    ]
                )
            ),
            .status(makeStatusMessage(requestID: 2, statusCode: .endOfFile)),
            .status(makeStatusMessage(requestID: 3, statusCode: .ok)),
            .handle(.init(requestID: 4, handle: alphaHandle)),
            .data(.init(requestID: 5, data: Array("alpha".utf8))),
            .status(makeStatusMessage(requestID: 6, statusCode: .endOfFile)),
            .status(makeStatusMessage(requestID: 7, statusCode: .ok)),
            .handle(.init(requestID: 8, handle: nestedDirectoryHandle)),
            .name(
                .init(
                    requestID: 9,
                    entries: [
                        makeNameEntry(
                            filename: "beta.txt",
                            size: 3,
                            permissions: 0o100644
                        )
                    ]
                )
            ),
            .status(makeStatusMessage(requestID: 10, statusCode: .endOfFile)),
            .status(makeStatusMessage(requestID: 11, statusCode: .ok)),
            .handle(.init(requestID: 12, handle: betaHandle)),
            .data(.init(requestID: 13, data: Array("bet".utf8))),
            .status(makeStatusMessage(requestID: 14, statusCode: .endOfFile)),
            .status(makeStatusMessage(requestID: 15, statusCode: .ok)),
        ],
        initialWindowSize: 4_096
    )
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let localDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer {
        try? FileManager.default.removeItem(at: localDirectory)
    }

    let summary = try await sftp.downloadDirectory(
        "/root/project",
        to: localDirectory,
        chunkSize: 32,
        maxConcurrentReads: 1,
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
        String(
            decoding: try Data(contentsOf: localDirectory.appendingPathComponent("alpha.txt")),
            as: UTF8.self
        ) == "alpha"
    )
    #expect(
        String(
            decoding: try Data(contentsOf: localDirectory.appendingPathComponent("nested").appendingPathComponent("beta.txt")),
            as: UTF8.self
        ) == "bet"
    )
    #expect(
        FileManager.default.fileExists(
            atPath: localDirectory.appendingPathComponent("latest").path
        ) == false
    )
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .read, bytesTransferred: 5, totalBytes: nil),
                .init(operation: .read, bytesTransferred: 8, totalBytes: nil),
            ]
    )

    let sentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
    let expectedSentMessages: [SSHSFTPMessage] = [
        .openDirectory(
            .init(
                requestID: 0,
                path: "/root/project"
            )
        ),
        .readDirectory(
            .init(
                requestID: 1,
                handle: rootDirectoryHandle
            )
        ),
        .readDirectory(
            .init(
                requestID: 2,
                handle: rootDirectoryHandle
            )
        ),
        .close(
            .init(
                requestID: 3,
                handle: rootDirectoryHandle
            )
        ),
        .openFile(
            .init(
                requestID: 4,
                path: "/root/project/alpha.txt",
                pflags: [.read],
                attributes: .empty
            )
        ),
        .readFile(
            .init(
                requestID: 5,
                handle: alphaHandle,
                offset: 0,
                length: 32
            )
        ),
        .readFile(
            .init(
                requestID: 6,
                handle: alphaHandle,
                offset: 5,
                length: 32
            )
        ),
        .close(
            .init(
                requestID: 7,
                handle: alphaHandle
            )
        ),
        .openDirectory(
            .init(
                requestID: 8,
                path: "/root/project/nested"
            )
        ),
        .readDirectory(
            .init(
                requestID: 9,
                handle: nestedDirectoryHandle
            )
        ),
        .readDirectory(
            .init(
                requestID: 10,
                handle: nestedDirectoryHandle
            )
        ),
        .close(
            .init(
                requestID: 11,
                handle: nestedDirectoryHandle
            )
        ),
        .openFile(
            .init(
                requestID: 12,
                path: "/root/project/nested/beta.txt",
                pflags: [.read],
                attributes: .empty
            )
        ),
        .readFile(
            .init(
                requestID: 13,
                handle: betaHandle,
                offset: 0,
                length: 32
            )
        ),
        .readFile(
            .init(
                requestID: 14,
                handle: betaHandle,
                offset: 3,
                length: 32
            )
        ),
        .close(
            .init(
                requestID: 15,
                handle: betaHandle
            )
        ),
    ]
    #expect(sentMessages == expectedSentMessages)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientUploadsLocalDirectoryToRemotePath() async throws {
    let alphaHandle = SSHSFTPHandle(bytes: [0x30, 0x40, 0x50, 0x60])
    let betaHandle = SSHSFTPHandle(bytes: [0x31, 0x41, 0x51, 0x61])
    let fixture = try await makeConcurrentSFTPFixture(
        senderChannel: 107,
        sftpMessagesAfterVersion: [
            .status(makeStatusMessage(requestID: 0, statusCode: .ok)),
            .handle(.init(requestID: 1, handle: alphaHandle)),
            .status(makeStatusMessage(requestID: 2, statusCode: .ok)),
            .status(makeStatusMessage(requestID: 3, statusCode: .ok)),
            .status(makeStatusMessage(requestID: 4, statusCode: .ok)),
            .handle(.init(requestID: 5, handle: betaHandle)),
            .status(makeStatusMessage(requestID: 6, statusCode: .ok)),
            .status(makeStatusMessage(requestID: 7, statusCode: .ok)),
        ],
        initialWindowSize: 4_096
    )
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let localDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let nestedDirectory = localDirectory.appendingPathComponent("nested", isDirectory: true)
    try FileManager.default.createDirectory(
        at: nestedDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: localDirectory)
    }
    try Data("alpha".utf8).write(to: localDirectory.appendingPathComponent("alpha.txt"))
    try Data("bet".utf8).write(to: nestedDirectory.appendingPathComponent("beta.txt"))

    let summary = try await sftp.uploadDirectory(
        from: localDirectory,
        to: "/root/uploaded",
        chunkSize: 32,
        progress: { value in
            await progressRecorder.record(value)
        }
    )

    #expect(
        summary == SSHSFTPDirectoryTransferSummary(
            bytesTransferred: 8,
            filesTransferred: 2,
            directoriesTraversed: 2,
            skippedEntries: 0
        )
    )
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .write, bytesTransferred: 5, totalBytes: nil),
                .init(operation: .write, bytesTransferred: 8, totalBytes: nil),
            ]
    )

    let sentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
    let expectedSentMessages: [SSHSFTPMessage] = [
        .makeDirectory(
            .init(
                requestID: 0,
                path: "/root/uploaded",
                attributes: .empty
            )
        ),
        .openFile(
            .init(
                requestID: 1,
                path: "/root/uploaded/alpha.txt",
                pflags: [.write, .create, .truncate],
                attributes: .empty
            )
        ),
        .writeFile(
            .init(
                requestID: 2,
                handle: alphaHandle,
                offset: 0,
                data: Array("alpha".utf8)
            )
        ),
        .close(
            .init(
                requestID: 3,
                handle: alphaHandle
            )
        ),
        .makeDirectory(
            .init(
                requestID: 4,
                path: "/root/uploaded/nested",
                attributes: .empty
            )
        ),
        .openFile(
            .init(
                requestID: 5,
                path: "/root/uploaded/nested/beta.txt",
                pflags: [.write, .create, .truncate],
                attributes: .empty
            )
        ),
        .writeFile(
            .init(
                requestID: 6,
                handle: betaHandle,
                offset: 0,
                data: Array("bet".utf8)
            )
        ),
        .close(
            .init(
                requestID: 7,
                handle: betaHandle
            )
        ),
    ]
    #expect(sentMessages == expectedSentMessages)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientUploadDirectoryUsesStatWhenRemoteDirectoryAlreadyExists() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x51, 0x61, 0x71, 0x81])
    let fixture = try await makeConcurrentSFTPFixture(
        senderChannel: 107,
        sftpMessagesAfterVersion: [
            .status(
                .init(
                    requestID: 0,
                    statusCode: .failure,
                    errorMessage: "already exists",
                    languageTag: ""
                )
            ),
            .attributes(
                .init(
                    requestID: 1,
                    attributes: makeAttributes(permissions: 0o040755)
                )
            ),
            .handle(.init(requestID: 2, handle: fileHandle)),
            .status(makeStatusMessage(requestID: 3, statusCode: .ok)),
            .status(makeStatusMessage(requestID: 4, statusCode: .ok)),
        ],
        initialWindowSize: 4_096
    )

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let localDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: localDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: localDirectory)
    }
    try Data("x".utf8).write(to: localDirectory.appendingPathComponent("note.txt"))

    let summary = try await sftp.uploadDirectory(
        from: localDirectory,
        to: "/root/existing"
    )

    #expect(
        summary == SSHSFTPDirectoryTransferSummary(
            bytesTransferred: 1,
            filesTransferred: 1,
            directoriesTraversed: 1,
            skippedEntries: 0
        )
    )

    let sentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
    let expectedSentMessages: [SSHSFTPMessage] = [
        .makeDirectory(
            .init(
                requestID: 0,
                path: "/root/existing",
                attributes: .empty
            )
        ),
        .stat(
            .init(
                requestID: 1,
                path: "/root/existing"
            )
        ),
        .openFile(
            .init(
                requestID: 2,
                path: "/root/existing/note.txt",
                pflags: [.write, .create, .truncate],
                attributes: .empty
            )
        ),
        .writeFile(
            .init(
                requestID: 3,
                handle: fileHandle,
                offset: 0,
                data: Array("x".utf8)
            )
        ),
        .close(
            .init(
                requestID: 4,
                handle: fileHandle
            )
        ),
    ]
    #expect(sentMessages == expectedSentMessages)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientUploadDirectoryStopsBeforeRemoteMutationWhenContinuationStops() async throws {
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let sftp = try await makePublicSFTPClient(from: fixture.client)

    let localDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: localDirectory,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: localDirectory)
    }
    try Data("alpha".utf8).write(to: localDirectory.appendingPathComponent("alpha.txt"))

    do {
        _ = try await sftp.uploadDirectory(
            from: localDirectory,
            to: "/root/uploaded",
            shouldContinue: { false }
        )
        Issue.record("Expected transfer continuation stop to cancel the upload")
    } catch is CancellationError {
    } catch {
        Issue.record("Expected CancellationError, got \(String(reflecting: error))")
    }

    let sentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
    #expect(sentMessages.isEmpty)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func sshClientDownloadDirectoryRejectsExistingLocalFileTarget() async throws {
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
    let localFile = temporaryDirectory.appendingPathComponent("target.txt")
    try Data("occupied".utf8).write(to: localFile)

    do {
        _ = try await sftp.downloadDirectory(
            "/root/project",
            to: localFile
        )
        Issue.record("Expected local file target to be rejected")
    } catch let error as SSHSFTPDirectoryTransferError {
        #expect(error == .localURLReferencesFile(localFile))
    } catch {
        Issue.record("Expected SSHSFTPDirectoryTransferError, got \(String(reflecting: error))")
    }

    let sentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
    #expect(sentMessages.isEmpty)
}

private func makeAttributes(
    size: UInt64? = nil,
    permissions: UInt32? = nil
) -> SSHSFTPFileAttributes {
    var flags: UInt32 = 0
    if size != nil {
        flags |= SSHSFTPFileAttributes.sizeFlag
    }
    if permissions != nil {
        flags |= SSHSFTPFileAttributes.permissionsFlag
    }

    return SSHSFTPFileAttributes(
        flags: flags,
        size: size,
        userID: nil,
        groupID: nil,
        permissions: permissions,
        accessTime: nil,
        modificationTime: nil,
        extensions: []
    )
}

private func makeNameEntry(
    filename: String,
    size: UInt64? = nil,
    permissions: UInt32? = nil
) -> SSHSFTPNameEntry {
    SSHSFTPNameEntry(
        filename: filename,
        longName: filename,
        attributes: makeAttributes(
            size: size,
            permissions: permissions
        )
    )
}

private func makeStatusMessage(
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
