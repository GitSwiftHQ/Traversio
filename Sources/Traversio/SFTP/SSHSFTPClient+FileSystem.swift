// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

extension SSHSFTPClient {
    package func realPath(_ path: String) async throws -> SSHSFTPNameEntry {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .realPath(
                SSHSFTPRealPathMessage(
                    requestID: requestID,
                    path: path
                )
            ),
            requestID: requestID
        )

        return try self.receiveSingleNameEntryResponse(response, for: requestID)
    }

    package func openFile(
        _ path: String,
        flags: SSHSFTPOpenFileFlags = [.read],
        attributes: SSHSFTPFileAttributes = .empty
    ) async throws -> SSHSFTPHandle {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .openFile(
                SSHSFTPOpenFileMessage(
                    requestID: requestID,
                    path: path,
                    pflags: flags,
                    attributes: attributes
                )
            ),
            requestID: requestID
        )

        switch response {
        case let .handle(handleMessage):
            try self.requireRequestID(
                expected: requestID,
                received: handleMessage.requestID
            )
            return handleMessage.handle
        case let .status(statusMessage):
            try self.requireRequestID(
                expected: requestID,
                received: statusMessage.requestID
            )
            throw SSHSFTPError.status(statusMessage)
        default:
            throw SSHSFTPError.unexpectedMessage(
                expected: .handle,
                received: response.messageID
            )
        }
    }

    package func lstat(_ path: String) async throws -> SSHSFTPFileAttributes {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .lstat(
                SSHSFTPLStatMessage(
                    requestID: requestID,
                    path: path
                )
            ),
            requestID: requestID
        )

        return try self.receiveAttributesResponse(response, for: requestID)
    }

    package func fstat(handle: SSHSFTPHandle) async throws -> SSHSFTPFileAttributes {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .fstat(
                SSHSFTPFStatMessage(
                    requestID: requestID,
                    handle: handle
                )
            ),
            requestID: requestID
        )

        return try self.receiveAttributesResponse(response, for: requestID)
    }

    package func setAttributes(
        _ path: String,
        attributes: SSHSFTPFileAttributes
    ) async throws {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .setAttributes(
                SSHSFTPSetAttributesMessage(
                    requestID: requestID,
                    path: path,
                    attributes: attributes
                )
            ),
            requestID: requestID
        )

        try self.requireSuccessfulStatusResponse(response, for: requestID)
    }

    package func setAttributes(
        handle: SSHSFTPHandle,
        attributes: SSHSFTPFileAttributes
    ) async throws {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .fsetAttributes(
                SSHSFTPFSetAttributesMessage(
                    requestID: requestID,
                    handle: handle,
                    attributes: attributes
                )
            ),
            requestID: requestID
        )

        try self.requireSuccessfulStatusResponse(response, for: requestID)
    }

    package func removeFile(_ path: String) async throws {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .removeFile(
                SSHSFTPRemoveFileMessage(
                    requestID: requestID,
                    path: path
                )
            ),
            requestID: requestID
        )

        try self.requireSuccessfulStatusResponse(response, for: requestID)
    }

    package func makeDirectory(
        _ path: String,
        attributes: SSHSFTPFileAttributes = .empty
    ) async throws {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .makeDirectory(
                SSHSFTPMakeDirectoryMessage(
                    requestID: requestID,
                    path: path,
                    attributes: attributes
                )
            ),
            requestID: requestID
        )

        try self.requireSuccessfulStatusResponse(response, for: requestID)
    }

    package func removeDirectory(_ path: String) async throws {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .removeDirectory(
                SSHSFTPRemoveDirectoryMessage(
                    requestID: requestID,
                    path: path
                )
            ),
            requestID: requestID
        )

        try self.requireSuccessfulStatusResponse(response, for: requestID)
    }

    func openDirectory(_ path: String) async throws -> SSHSFTPHandle {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .openDirectory(
                SSHSFTPOpenDirectoryMessage(
                    requestID: requestID,
                    path: path
                )
            ),
            requestID: requestID
        )

        switch response {
        case let .handle(handleMessage):
            try self.requireRequestID(
                expected: requestID,
                received: handleMessage.requestID
            )
            return handleMessage.handle
        case let .status(statusMessage):
            try self.requireRequestID(
                expected: requestID,
                received: statusMessage.requestID
            )
            throw SSHSFTPError.status(statusMessage)
        default:
            throw SSHSFTPError.unexpectedMessage(
                expected: .handle,
                received: response.messageID
            )
        }
    }

    func readDirectory(handle: SSHSFTPHandle) async throws -> [SSHSFTPNameEntry]? {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .readDirectory(
                SSHSFTPReadDirectoryMessage(
                    requestID: requestID,
                    handle: handle
                )
            ),
            requestID: requestID
        )

        switch response {
        case let .name(nameMessage):
            try self.requireRequestID(
                expected: requestID,
                received: nameMessage.requestID
            )
            return nameMessage.entries
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
                expected: .name,
                received: response.messageID
            )
        }
    }

    package func stat(_ path: String) async throws -> SSHSFTPFileAttributes {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .stat(
                SSHSFTPStatMessage(
                    requestID: requestID,
                    path: path
                )
            ),
            requestID: requestID
        )

        return try self.receiveAttributesResponse(response, for: requestID)
    }

    package func fileSystemAttributes(_ path: String) async throws -> SSHSFTPFileSystemAttributes {
        try self.requireSupportedExtension(
            named: Self.statVFSExtensionName,
            minimumVersion: 2
        )

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .statVFS(
                SSHSFTPStatVFSMessage(
                    requestID: requestID,
                    path: path
                )
            ),
            requestID: requestID
        )

        let data = try self.receiveExtendedReplyData(response, for: requestID)
        return try self.parseFileSystemAttributes(from: data)
    }

    package func fileSystemAttributes(
        handle: SSHSFTPHandle
    ) async throws -> SSHSFTPFileSystemAttributes {
        try self.requireSupportedExtension(
            named: Self.fstatVFSExtensionName,
            minimumVersion: 2
        )

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .fstatVFS(
                SSHSFTPFStatVFSMessage(
                    requestID: requestID,
                    handle: handle
                )
            ),
            requestID: requestID
        )

        let data = try self.receiveExtendedReplyData(response, for: requestID)
        return try self.parseFileSystemAttributes(from: data)
    }

    package func rename(_ oldPath: String, to newPath: String) async throws {
        let versionExchange = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let message: SSHSFTPMessage
        if versionExchange.supportsExtension(
            named: Self.posixRenameExtensionName,
            minimumVersion: 1
        ) {
            message = .posixRename(
                SSHSFTPPosixRenameMessage(
                    requestID: requestID,
                    oldPath: oldPath,
                    newPath: newPath
                )
            )
        } else {
            message = .rename(
                SSHSFTPRenameMessage(
                    requestID: requestID,
                    oldPath: oldPath,
                    newPath: newPath
                )
            )
        }
        let response = try await self.sendRequest(message, requestID: requestID)

        try self.requireSuccessfulStatusResponse(response, for: requestID)
    }

    package func readLink(_ path: String) async throws -> SSHSFTPNameEntry {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .readLink(
                SSHSFTPReadLinkMessage(
                    requestID: requestID,
                    path: path
                )
            ),
            requestID: requestID
        )

        return try self.receiveSingleNameEntryResponse(response, for: requestID)
    }

    package func createSymbolicLink(
        targetPath: String,
        linkPath: String
    ) async throws {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendSerializedRequest(
            self.serializeSymbolicLinkRequest(
                requestID: requestID,
                targetPath: targetPath,
                linkPath: linkPath,
                wireFormat: await self.currentSymbolicLinkWireFormat()
            ),
            requestID: requestID
        )

        try self.requireSuccessfulStatusResponse(response, for: requestID)
    }

    package func synchronize(handle: SSHSFTPHandle) async throws {
        try self.requireSupportedExtension(
            named: Self.fsyncExtensionName,
            minimumVersion: 1
        )

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .fsync(
                SSHSFTPFSyncMessage(
                    requestID: requestID,
                    handle: handle
                )
            ),
            requestID: requestID
        )

        try self.requireSuccessfulStatusResponse(response, for: requestID)
    }

    package func close(handle: SSHSFTPHandle) async throws {
        _ = try self.currentVersionExchange()

        let requestID = self.allocateRequestID()
        let response = try await self.sendRequest(
            .close(
                SSHSFTPCloseMessage(
                    requestID: requestID,
                    handle: handle
                )
            ),
            requestID: requestID
        )

        try self.requireSuccessfulStatusResponse(response, for: requestID)
    }

    package func listDirectory(_ path: String) async throws -> [SSHSFTPNameEntry] {
        _ = try self.currentVersionExchange()

        let handle = try await self.openDirectory(path)
        var entries: [SSHSFTPNameEntry] = []

        do {
            while let batch = try await self.readDirectory(handle: handle) {
                try self.checkCancellation()
                if batch.isEmpty {
                    break
                }
                entries.append(contentsOf: batch)
            }
        } catch {
            try? await self.close(handle: handle)
            throw error
        }

        try await self.close(handle: handle)
        return entries
    }

    private func receiveAttributesResponse(
        _ response: SSHSFTPMessage,
        for requestID: UInt32
    ) throws -> SSHSFTPFileAttributes {
        switch response {
        case let .attributes(attributesMessage):
            try self.requireRequestID(
                expected: requestID,
                received: attributesMessage.requestID
            )
            return attributesMessage.attributes
        case let .status(statusMessage):
            try self.requireRequestID(
                expected: requestID,
                received: statusMessage.requestID
            )
            throw SSHSFTPError.status(statusMessage)
        default:
            throw SSHSFTPError.unexpectedMessage(
                expected: .attributes,
                received: response.messageID
            )
        }
    }

    private func receiveExtendedReplyData(
        _ response: SSHSFTPMessage,
        for requestID: UInt32
    ) throws -> [UInt8] {
        switch response {
        case let .extendedReply(replyMessage):
            try self.requireRequestID(
                expected: requestID,
                received: replyMessage.requestID
            )
            return replyMessage.data
        case let .status(statusMessage):
            try self.requireRequestID(
                expected: requestID,
                received: statusMessage.requestID
            )
            throw SSHSFTPError.status(statusMessage)
        default:
            throw SSHSFTPError.unexpectedMessage(
                expected: .extendedReply,
                received: response.messageID
            )
        }
    }

    private func receiveSingleNameEntryResponse(
        _ response: SSHSFTPMessage,
        for requestID: UInt32
    ) throws -> SSHSFTPNameEntry {
        switch response {
        case let .name(nameMessage):
            try self.requireRequestID(
                expected: requestID,
                received: nameMessage.requestID
            )
            guard nameMessage.entries.count == 1 else {
                throw SSHSFTPError.unexpectedNameCount(
                    expected: 1,
                    received: UInt32(nameMessage.entries.count)
                )
            }
            return nameMessage.entries[0]
        case let .status(statusMessage):
            try self.requireRequestID(
                expected: requestID,
                received: statusMessage.requestID
            )
            throw SSHSFTPError.status(statusMessage)
        default:
            throw SSHSFTPError.unexpectedMessage(
                expected: .name,
                received: response.messageID
            )
        }
    }
}
