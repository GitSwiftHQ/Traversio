// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

/// A typed SFTP v3 client opened from an authenticated SSH connection.
///
/// Open one with `SSHConnection.openSFTP()`. The client owns one SSH subsystem
/// channel and should be closed when the SFTP work is done.
///
/// Example:
///
/// ```swift
/// let sftp = try await connection.openSFTP()
/// defer {
///     Task { try? await sftp.close() }
/// }
///
/// let bytes = try await sftp.readFile("/var/log/app.log")
/// ```
public struct SFTPClient: Sendable {
    private let client: SSHSFTPClient
    private let lifetime: SSHConnectionLifetime
    private let metadata: SSHConnectionMetadata
    private let localChannelID: UInt32
    private let remoteChannelID: UInt32
    private let logHandler: SSHClientLogHandler

    init(
        client: SSHSFTPClient,
        lifetime: SSHConnectionLifetime,
        metadata: SSHConnectionMetadata,
        localChannelID: UInt32,
        remoteChannelID: UInt32,
        logHandler: SSHClientLogHandler
    ) {
        self.client = client
        self.lifetime = lifetime
        self.metadata = metadata
        self.localChannelID = localChannelID
        self.remoteChannelID = remoteChannelID
        self.logHandler = logHandler
    }

    /// Returns the negotiated SFTP version and server extension list.
    public func currentVersionExchange() async throws -> SSHSFTPVersionExchange {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.currentVersionExchange()
        }
    }

    /// Closes the SFTP subsystem channel.
    public func close() async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.close()
        }
    }

    /// Resolves a server path using SFTP `REALPATH`.
    public func realPath(_ path: String) async throws -> SSHSFTPNameEntry {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.realPath(path)
        }
    }

    /// Reads attributes for a path without following a final symbolic link.
    public func lstat(_ path: String) async throws -> SSHSFTPFileAttributes {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.lstat(path)
        }
    }

    /// Reads attributes for a path, following a final symbolic link when the
    /// server does so for SFTP `STAT`.
    public func stat(_ path: String) async throws -> SSHSFTPFileAttributes {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.stat(path)
        }
    }

    /// Updates file attributes using SFTP `SETSTAT`.
    public func setAttributes(
        _ path: String,
        attributes: SSHSFTPFileAttributes
    ) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.setAttributes(path, attributes: attributes)
        }
    }

    /// Reads filesystem capacity and capability information using the
    /// OpenSSH `statvfs@openssh.com` extension.
    public func fileSystemAttributes(
        _ path: String
    ) async throws -> SSHSFTPFileSystemAttributes {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.fileSystemAttributes(path)
        }
    }

    /// Opens a remote file and returns a handle for offset-based reads, writes,
    /// metadata, sync, and close.
    ///
    /// Example:
    ///
    /// ```swift
    /// let handle = try await sftp.openFile("/tmp/report.txt", flags: [.write, .create, .truncate])
    /// try await handle.write(Array("hello\n".utf8))
    /// try await handle.close()
    /// ```
    public func openFile(
        _ path: String,
        flags: SSHSFTPOpenFileFlags = [.read],
        attributes: SSHSFTPFileAttributes = .empty
    ) async throws -> SFTPFileHandle {
        try await self.lifetime.requireActive()
        let handle = try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.openFile(
                path,
                flags: flags,
                attributes: attributes
            )
        }
        return SFTPFileHandle(
            handle: handle,
            client: self.client,
            lifetime: self.lifetime,
            metadata: self.metadata,
            localChannelID: self.localChannelID,
            remoteChannelID: self.remoteChannelID,
            logHandler: self.logHandler,
            cursor: SFTPFileHandleCursor()
        )
    }

    /// Lists a remote directory, excluding no entries added by Traversio.
    ///
    /// Servers commonly include `"."` and `".."`; callers that render user
    /// file lists should filter those names if they are not wanted.
    public func listDirectory(_ path: String) async throws -> [SSHSFTPNameEntry] {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.listDirectory(path)
        }
    }

    /// Reads a complete remote file into memory.
    ///
    /// Use `openFile(_:)` and `SFTPFileHandle.readChunks(startingAt:chunkSize:)`
    /// for large files or streaming UIs.
    public func readFile(
        _ path: String,
        chunkSize: UInt32 = 32 * 1_024,
        maxConcurrentReads: Int = 1,
        progress: SSHSFTPTransferProgressHandler? = nil
    ) async throws -> [UInt8] {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.readFile(
                path,
                chunkSize: chunkSize,
                maxConcurrentReads: maxConcurrentReads,
                progress: progress
            )
        }
    }

    /// Writes a complete remote file from memory.
    ///
    /// By default the file is created or truncated by the underlying SFTP open
    /// flags used by the internal writer.
    public func writeFile(
        _ path: String,
        data: [UInt8],
        chunkSize: UInt32 = 32 * 1_024,
        maxConcurrentWrites: Int = 1,
        syncAfterWrite: Bool = false,
        progress: SSHSFTPTransferProgressHandler? = nil
    ) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.writeFile(
                path,
                data: data,
                chunkSize: chunkSize,
                maxConcurrentWrites: maxConcurrentWrites,
                syncAfterWrite: syncAfterWrite,
                progress: progress
            )
        }
    }

    /// Resumes an upload by appending the missing suffix after the current
    /// remote file size.
    ///
    /// Throws `SSHSFTPResumeError.remoteFileIsLargerThanLocalData` if the
    /// remote file is already larger than `data`.
    public func resumeUploadFile(
        _ path: String,
        data: [UInt8],
        chunkSize: UInt32 = 32 * 1_024,
        maxConcurrentWrites: Int = 1,
        syncAfterWrite: Bool = false,
        progress: SSHSFTPTransferProgressHandler? = nil
    ) async throws -> SSHSFTPResumeUploadResult {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            let totalBytes = UInt64(data.count)
            let startingOffset = try await self.resumeUploadStartOffset(for: path)

            guard startingOffset <= totalBytes else {
                throw SSHSFTPResumeError.remoteFileIsLargerThanLocalData(
                    path: path,
                    remoteSize: startingOffset,
                    localSize: totalBytes
                )
            }

            if let progress, (startingOffset > 0 || totalBytes == 0) {
                await progress(
                    SSHSFTPTransferProgress(
                        operation: .write,
                        bytesTransferred: startingOffset,
                        totalBytes: totalBytes
                    )
                )
            }

            if startingOffset < totalBytes {
                let remainingData = Array(data[Int(startingOffset)...])
                let handle = try await self.client.openFile(
                    path,
                    flags: [.write, .create]
                )
                do {
                    try await self.client.writeFile(
                        handle: handle,
                        data: remainingData,
                        startingAt: startingOffset,
                        chunkSize: chunkSize,
                        maxConcurrentWrites: maxConcurrentWrites,
                        progress: self.resumeTransferProgressHandler(
                            operation: .write,
                            startingOffset: startingOffset,
                            totalBytes: totalBytes,
                            progress: progress
                        )
                    )
                    if syncAfterWrite {
                        try await self.client.synchronize(handle: handle)
                    }
                } catch {
                    try? await self.client.close(handle: handle)
                    throw error
                }
                try await self.client.close(handle: handle)
            } else if totalBytes == 0 {
                try await self.client.writeFile(
                    path,
                    data: [],
                    chunkSize: chunkSize,
                    maxConcurrentWrites: maxConcurrentWrites,
                    syncAfterWrite: syncAfterWrite,
                    progress: nil,
                    flags: [.write, .create]
                )
            }

            return SSHSFTPResumeUploadResult(
                path: path,
                startingOffset: startingOffset,
                bytesUploaded: totalBytes - startingOffset,
                totalBytes: totalBytes
            )
        }
    }

    /// Resumes a download by reading the remaining bytes after `existingData`.
    ///
    /// The returned result contains `existingData` plus the newly downloaded
    /// bytes.
    public func resumeDownloadFile(
        _ path: String,
        existingData: [UInt8],
        chunkSize: UInt32 = 32 * 1_024,
        maxConcurrentReads: Int = 1,
        progress: SSHSFTPTransferProgressHandler? = nil
    ) async throws -> SSHSFTPResumeDownloadResult {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            let totalBytes = try await self.remoteFileSize(for: path)
            let startingOffset = UInt64(existingData.count)

            guard startingOffset <= totalBytes else {
                throw SSHSFTPResumeError.remoteFileIsSmallerThanLocalData(
                    path: path,
                    remoteSize: totalBytes,
                    localSize: startingOffset
                )
            }

            if let progress, (startingOffset > 0 || totalBytes == 0) {
                await progress(
                    SSHSFTPTransferProgress(
                        operation: .read,
                        bytesTransferred: startingOffset,
                        totalBytes: totalBytes
                    )
                )
            }

            if startingOffset == totalBytes {
                return SSHSFTPResumeDownloadResult(
                    path: path,
                    startingOffset: startingOffset,
                    bytesDownloaded: 0,
                    totalBytes: totalBytes,
                    data: existingData
                )
            }

            let handle = try await self.client.openFile(path)
            let remainingData: [UInt8]
            do {
                remainingData = try await self.client.readFile(
                    handle: handle,
                    startingAt: startingOffset,
                    chunkSize: chunkSize,
                    maxConcurrentReads: maxConcurrentReads,
                    progress: self.resumeTransferProgressHandler(
                        operation: .read,
                        startingOffset: startingOffset,
                        totalBytes: totalBytes,
                        progress: progress
                    )
                )
            } catch {
                try? await self.client.close(handle: handle)
                throw error
            }
            try await self.client.close(handle: handle)

            return SSHSFTPResumeDownloadResult(
                path: path,
                startingOffset: startingOffset,
                bytesDownloaded: UInt64(remainingData.count),
                totalBytes: totalBytes,
                data: existingData + remainingData
            )
        }
    }

    /// Creates a remote directory.
    public func makeDirectory(
        _ path: String,
        attributes: SSHSFTPFileAttributes = .empty
    ) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.makeDirectory(path, attributes: attributes)
        }
    }

    /// Removes a remote file.
    public func removeFile(_ path: String) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.removeFile(path)
        }
    }

    /// Removes an empty remote directory.
    public func removeDirectory(_ path: String) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.removeDirectory(path)
        }
    }

    /// Renames or moves a remote path using SFTP `RENAME`.
    public func rename(_ oldPath: String, to newPath: String) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.rename(oldPath, to: newPath)
        }
    }

    /// Reads the target of a remote symbolic link.
    public func readLink(_ path: String) async throws -> SSHSFTPNameEntry {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.readLink(path)
        }
    }

    /// Creates a remote symbolic link.
    ///
    /// `targetPath` is the link target and `linkPath` is the new symlink path,
    /// matching common Swift naming rather than the raw SFTP packet field order.
    public func createSymbolicLink(
        targetPath: String,
        linkPath: String
    ) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.createSymbolicLink(
                targetPath: targetPath,
                linkPath: linkPath
            )
        }
    }

    private func resumeUploadStartOffset(
        for path: String
    ) async throws -> UInt64 {
        do {
            return try await self.remoteFileSize(for: path)
        } catch let SSHSFTPError.status(status)
            where status.statusCode == .noSuchFile {
            return 0
        }
    }

    private func remoteFileSize(for path: String) async throws -> UInt64 {
        let attributes = try await self.client.stat(path)
        guard let size = attributes.size else {
            throw SSHSFTPResumeError.remoteFileSizeUnavailable(path: path)
        }
        return size
    }

    private func resumeTransferProgressHandler(
        operation: SSHSFTPTransferProgress.Operation,
        startingOffset: UInt64,
        totalBytes: UInt64,
        progress: SSHSFTPTransferProgressHandler?
    ) -> SSHSFTPTransferProgressHandler? {
        guard let progress else {
            return nil
        }

        return { value in
            await progress(
                SSHSFTPTransferProgress(
                    operation: operation,
                    bytesTransferred: startingOffset + value.bytesTransferred,
                    totalBytes: totalBytes
                )
            )
        }
    }
}

/// Errors raised by stateful `SFTPFileHandle` cursor operations.
public enum SSHSFTPFileHandleError: Error, Equatable, Sendable {
    /// Cursor Offset Overflow.
    case cursorOffsetOverflow(current: UInt64, byteCount: UInt64)
}

private enum SFTPFileHandleCursorAcquireResult {
    case acquired
    case cancelled
}

private actor SFTPFileHandleCursor {
    private struct Waiter {
        let id: UInt64
        let continuation: CheckedContinuation<SFTPFileHandleCursorAcquireResult, Never>
    }

    private var offset: UInt64 = 0
    private var isAcquired = false
    private var nextWaiterID: UInt64 = 0
    private var waiters: [Waiter] = []

    func tell() async throws -> UInt64 {
        _ = try await self.acquireOffset()
        defer { self.releaseAcquiredOffset() }
        return self.offset
    }

    func seek(to offset: UInt64) async throws {
        _ = try await self.acquireOffset()
        defer { self.releaseAcquiredOffset() }
        self.offset = offset
    }

    func acquireOffset() async throws -> UInt64 {
        try Task.checkCancellation()

        if !self.isAcquired {
            self.isAcquired = true
            return self.offset
        }

        let waiterID = self.nextWaiterID
        self.nextWaiterID &+= 1
        let cursor = self
        let result = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                self.waiters.append(
                    Waiter(
                        id: waiterID,
                        continuation: continuation
                    )
                )
            }
        } onCancel: {
            Task {
                await cursor.cancelWaiter(id: waiterID)
            }
        }

        switch result {
        case .acquired:
            return self.offset
        case .cancelled:
            throw CancellationError()
        }
    }

    func release() {
        self.releaseAcquiredOffset()
    }

    func advanceAndRelease(by byteCount: Int) throws {
        defer { self.releaseAcquiredOffset() }

        let increment = UInt64(byteCount)
        let (nextOffset, overflow) = self.offset.addingReportingOverflow(increment)
        guard !overflow else {
            throw SSHSFTPFileHandleError.cursorOffsetOverflow(
                current: self.offset,
                byteCount: increment
            )
        }

        self.offset = nextOffset
    }

    private func cancelWaiter(id: UInt64) {
        guard let index = self.waiters.firstIndex(where: { $0.id == id }) else {
            return
        }

        let waiter = self.waiters.remove(at: index)
        waiter.continuation.resume(returning: .cancelled)
    }

    private func releaseAcquiredOffset() {
        guard !self.waiters.isEmpty else {
            self.isAcquired = false
            return
        }

        let waiter = self.waiters.removeFirst()
        waiter.continuation.resume(returning: .acquired)
    }
}

/// A remote SFTP file handle.
///
/// Handles support both explicit offset operations and cursor-style operations
/// such as `read(length:)` and `write(_:)`. Cursor operations are serialized so
/// concurrent calls do not corrupt the in-memory cursor.
public struct SFTPFileHandle: Sendable {
    private let handle: SSHSFTPHandle
    private let client: SSHSFTPClient
    private let lifetime: SSHConnectionLifetime
    private let metadata: SSHConnectionMetadata
    private let localChannelID: UInt32
    private let remoteChannelID: UInt32
    private let logHandler: SSHClientLogHandler
    private let cursor: SFTPFileHandleCursor

    fileprivate init(
        handle: SSHSFTPHandle,
        client: SSHSFTPClient,
        lifetime: SSHConnectionLifetime,
        metadata: SSHConnectionMetadata,
        localChannelID: UInt32,
        remoteChannelID: UInt32,
        logHandler: SSHClientLogHandler,
        cursor: SFTPFileHandleCursor
    ) {
        self.handle = handle
        self.client = client
        self.lifetime = lifetime
        self.metadata = metadata
        self.localChannelID = localChannelID
        self.remoteChannelID = remoteChannelID
        self.logHandler = logHandler
        self.cursor = cursor
    }

    /// Returns the current cursor offset used by cursor-style reads and writes.
    public func tell() async throws -> UInt64 {
        try await self.lifetime.requireActive()
        return try await self.cursor.tell()
    }

    /// Moves the cursor used by cursor-style reads and writes.
    public func seek(to offset: UInt64) async throws {
        try await self.lifetime.requireActive()
        try await self.cursor.seek(to: offset)
    }

    /// Moves the cursor back to offset zero.
    public func rewind() async throws {
        try await self.seek(to: 0)
    }

    /// Reads from the current cursor offset and advances the cursor by the
    /// number of bytes received.
    ///
    /// Returns `nil` on EOF.
    public func read(
        length: UInt32
    ) async throws -> [UInt8]? {
        let offset = try await self.cursor.acquireOffset()
        var cursorAcquired = true
        do {
            try Task.checkCancellation()
            let data = try await self.read(
                at: offset,
                length: length
            )
            if let data {
                do {
                    try await self.cursor.advanceAndRelease(by: data.count)
                    cursorAcquired = false
                } catch {
                    cursorAcquired = false
                    throw error
                }
            } else {
                await self.cursor.release()
                cursorAcquired = false
            }
            return data
        } catch {
            if cursorAcquired {
                await self.cursor.release()
            }
            throw error
        }
    }

    /// Reads up to `length` bytes from an explicit remote file offset.
    ///
    /// Returns `nil` on EOF.
    public func read(
        at offset: UInt64,
        length: UInt32
    ) async throws -> [UInt8]? {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.readFile(
                handle: self.handle,
                offset: offset,
                length: length
            )
        }
    }

    /// Reads the whole file represented by this handle into memory.
    public func readAll(
        chunkSize: UInt32 = 32 * 1_024,
        maxConcurrentReads: Int = 1,
        progress: SSHSFTPTransferProgressHandler? = nil
    ) async throws -> [UInt8] {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.readFile(
                handle: self.handle,
                chunkSize: chunkSize,
                maxConcurrentReads: maxConcurrentReads,
                progress: progress
            )
        }
    }

    /// Returns an async sequence of offset-tagged chunks for streaming reads.
    ///
    /// Example:
    ///
    /// ```swift
    /// for try await chunk in handle.readChunks(chunkSize: 64 * 1024) {
    ///     process(chunk.bytes)
    /// }
    /// ```
    public func readChunks(
        startingAt offset: UInt64 = 0,
        chunkSize: UInt32 = 32 * 1_024
    ) -> SSHSFTPFileChunkSequence {
        SSHSFTPFileChunkSequence(
            startingAt: offset,
            chunkSize: chunkSize
        ) { chunkOffset, chunkLength in
            try await self.read(at: chunkOffset, length: chunkLength)
        }
    }

    /// Writes bytes at the current cursor offset and advances the cursor.
    public func write(
        _ data: [UInt8]
    ) async throws {
        let offset = try await self.cursor.acquireOffset()
        var cursorAcquired = true
        do {
            try Task.checkCancellation()
            try await self.write(
                data,
                at: offset
            )
            do {
                try await self.cursor.advanceAndRelease(by: data.count)
                cursorAcquired = false
            } catch {
                cursorAcquired = false
                throw error
            }
        } catch {
            if cursorAcquired {
                await self.cursor.release()
            }
            throw error
        }
    }

    /// Writes bytes at an explicit remote file offset.
    public func write(
        _ data: [UInt8],
        at offset: UInt64
    ) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.writeFile(
                handle: self.handle,
                offset: offset,
                data: data
            )
        }
    }

    package func sendReadRequest(
        at offset: UInt64,
        length: UInt32
    ) async throws -> UInt32 {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.sendReadRequest(
                handle: self.handle,
                offset: offset,
                length: length
            )
        }
    }

    package func effectiveReadLength(_ requestedLength: UInt32) async -> UInt32 {
        await self.client.effectiveReadLength(requestedLength)
    }

    package func maximumWriteDataLength() async -> Int {
        await self.client.maximumWriteDataLength(for: self.handle)
    }

    package func receiveReadResponse(
        for requestID: UInt32,
        length: UInt32
    ) async throws -> [UInt8]? {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.receiveReadResponse(
                for: requestID,
                length: length
            )
        }
    }

    package func sendWriteRequest(
        _ data: [UInt8],
        at offset: UInt64
    ) async throws -> UInt32 {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.sendWriteRequest(
                handle: self.handle,
                offset: offset,
                data: data
            )
        }
    }

    package func receiveWriteResponse(for requestID: UInt32) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.receiveWriteResponse(for: requestID)
        }
    }

    package func cancelPendingResponse(for requestID: UInt32) async {
        await self.client.cancelPendingResponse(for: requestID)
    }

    /// Writes an async sequence of byte chunks starting at `offset`.
    public func write<Chunks: AsyncSequence>(
        contentsOf chunks: Chunks,
        startingAt offset: UInt64 = 0,
        progress: SSHSFTPTransferProgressHandler? = nil
    ) async throws where Chunks.Element == [UInt8] {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            var nextOffset = offset
            var bytesTransferred: UInt64 = 0

            for try await chunk in chunks {
                if chunk.isEmpty {
                    continue
                }

                try await self.client.writeFile(
                    handle: self.handle,
                    offset: nextOffset,
                    data: chunk
                )
                nextOffset += UInt64(chunk.count)
                bytesTransferred += UInt64(chunk.count)

                if let progress {
                    await progress(
                        SSHSFTPTransferProgress(
                            operation: .write,
                            bytesTransferred: bytesTransferred
                        )
                    )
                }
            }
        }
    }

    /// Reads attributes for this open handle using SFTP `FSTAT`.
    public func stat() async throws -> SSHSFTPFileAttributes {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.fstat(handle: self.handle)
        }
    }

    /// Updates attributes for this open handle using SFTP `FSETSTAT`.
    public func setAttributes(
        _ attributes: SSHSFTPFileAttributes
    ) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.setAttributes(
                handle: self.handle,
                attributes: attributes
            )
        }
    }

    /// Reads filesystem attributes for this handle using OpenSSH `fstatvfs`.
    public func fileSystemAttributes() async throws -> SSHSFTPFileSystemAttributes {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.fileSystemAttributes(handle: self.handle)
        }
    }

    /// Flushes remote file data using the OpenSSH `fsync@openssh.com`
    /// extension.
    public func synchronize() async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.synchronize(handle: self.handle)
        }
    }

    /// Closes this remote file handle.
    public func close() async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.close(handle: self.handle)
        }
    }
}

extension SFTPClient: SSHOperationFailureMappingContext {
    var operationFailureMetadata: SSHConnectionMetadata { self.metadata }
    var operationFailureLogHandler: SSHClientLogHandler { self.logHandler }
    var operationFailureLocalChannelID: UInt32? { self.localChannelID }
    var operationFailureRemoteChannelID: UInt32? { self.remoteChannelID }

    func operationFailureSnapshot() async -> SSHTransportProtocolDiagnosticsSnapshot {
        await self.client.diagnosticsSnapshot()
    }
}

extension SFTPFileHandle: SSHOperationFailureMappingContext {
    var operationFailureMetadata: SSHConnectionMetadata { self.metadata }
    var operationFailureLogHandler: SSHClientLogHandler { self.logHandler }
    var operationFailureLocalChannelID: UInt32? { self.localChannelID }
    var operationFailureRemoteChannelID: UInt32? { self.remoteChannelID }

    func operationFailureSnapshot() async -> SSHTransportProtocolDiagnosticsSnapshot {
        await self.client.diagnosticsSnapshot()
    }
}
