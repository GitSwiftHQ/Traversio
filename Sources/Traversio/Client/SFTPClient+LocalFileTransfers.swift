// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Errors raised before a local filesystem transfer starts.
public enum SSHSFTPLocalFileTransferError: Error, Equatable, Sendable {
    /// local URL Must Reference File.
    case localURLMustReferenceFile(URL)
    /// local URL References Directory.
    case localURLReferencesDirectory(URL)
}

extension SFTPClient {
    /// Downloads a remote file directly to a local file URL.
    ///
    /// `progress` is called after bytes are written locally. `shouldContinue`
    /// lets callers cancel long transfers without cancelling the whole task.
    ///
    /// Example:
    ///
    /// ```swift
    /// let bytes = try await sftp.downloadFile(
    ///     "/var/log/app.log",
    ///     to: URL(filePath: "/tmp/app.log")
    /// )
    /// ```
    public func downloadFile(
        _ remotePath: String,
        to localURL: URL,
        expectedSize: UInt64? = nil,
        chunkSize: UInt32 = 32 * 1_024,
        maxConcurrentReads: Int = 64,
        progress: SSHSFTPTransferProgressHandler? = nil,
        shouldContinue: SSHSFTPTransferContinuationHandler? = nil
    ) async throws -> UInt64 {
        try self.validateLocalFileURL(localURL)
        try await self.checkTransferContinuation(shouldContinue)
        let remoteHandle = try await self.openFile(remotePath, flags: [.read])

        do {
            let localHandle = try self.prepareWritableLocalFile(at: localURL)
            defer {
                self.closeLocalHandle(localHandle)
            }

            if let progress, expectedSize == 0 {
                await progress(
                    SSHSFTPTransferProgress(
                        operation: .read,
                        bytesTransferred: 0,
                        totalBytes: 0
                    )
                )
            }
            try await self.checkTransferContinuation(shouldContinue)

            let bytesTransferred: UInt64
            if max(maxConcurrentReads, 1) == 1 || expectedSize == nil {
                bytesTransferred = try await self.downloadFileSequentially(
                    from: remoteHandle,
                    to: localHandle,
                    expectedSize: expectedSize,
                    chunkSize: max(chunkSize, 1),
                    progress: progress,
                    shouldContinue: shouldContinue
                )
            } else {
                bytesTransferred = try await self.downloadFileWithConcurrentReads(
                    from: remoteHandle,
                    to: localHandle,
                    expectedSize: expectedSize ?? 0,
                    chunkSize: max(chunkSize, 1),
                    maxConcurrentReads: max(maxConcurrentReads, 1),
                    progress: progress,
                    shouldContinue: shouldContinue
                )
            }

            try await remoteHandle.close()
            return bytesTransferred
        } catch {
            try? await remoteHandle.close()
            throw error
        }
    }

    /// Uploads a local file URL to a remote path.
    ///
    /// When `syncAfterWrite` is true, Traversio asks the server to flush the
    /// handle before closing it. Servers that do not support the OpenSSH fsync
    /// extension may reject that request.
    public func uploadFile(
        from localURL: URL,
        to remotePath: String,
        attributes: SSHSFTPFileAttributes = .empty,
        chunkSize: UInt32 = 32 * 1_024,
        maxConcurrentWrites: Int = 16,
        syncAfterWrite: Bool = false,
        progress: SSHSFTPTransferProgressHandler? = nil,
        shouldContinue: SSHSFTPTransferContinuationHandler? = nil
    ) async throws -> UInt64 {
        let localHandle = try self.openReadableLocalFile(at: localURL)
        defer {
            self.closeLocalHandle(localHandle)
        }

        let totalBytes = try self.localFileSizeIfAvailable(at: localURL)
        try await self.checkTransferContinuation(shouldContinue)
        let remoteHandle = try await self.openFile(
            remotePath,
            flags: [.write, .create, .truncate],
            attributes: attributes
        )

        do {
            if let progress, totalBytes == 0 {
                await progress(
                    SSHSFTPTransferProgress(
                        operation: .write,
                        bytesTransferred: 0,
                        totalBytes: 0
                    )
                )
            }
            try await self.checkTransferContinuation(shouldContinue)

            let bytesTransferred: UInt64
            if max(maxConcurrentWrites, 1) == 1 {
                bytesTransferred = try await self.uploadFileSequentially(
                    from: localHandle,
                    to: remoteHandle,
                    totalBytes: totalBytes,
                    chunkSize: max(chunkSize, 1),
                    progress: progress,
                    shouldContinue: shouldContinue
                )
            } else {
                bytesTransferred = try await self.uploadFileWithConcurrentWrites(
                    from: localHandle,
                    to: remoteHandle,
                    totalBytes: totalBytes,
                    chunkSize: max(chunkSize, 1),
                    maxConcurrentWrites: max(maxConcurrentWrites, 1),
                    progress: progress,
                    shouldContinue: shouldContinue
                )
            }

            if syncAfterWrite {
                try await remoteHandle.synchronize()
            }

            try await remoteHandle.close()
            return bytesTransferred
        } catch {
            try? await remoteHandle.close()
            throw error
        }
    }

    private func downloadFileSequentially(
        from remoteHandle: SFTPFileHandle,
        to localHandle: FileHandle,
        expectedSize: UInt64?,
        chunkSize: UInt32,
        progress: SSHSFTPTransferProgressHandler?,
        shouldContinue: SSHSFTPTransferContinuationHandler?
    ) async throws -> UInt64 {
        var bytesTransferred: UInt64 = 0
        var chunkIterator = remoteHandle.readChunks(
            chunkSize: max(chunkSize, 1)
        ).makeAsyncIterator()

        while true {
            try await self.checkTransferContinuation(shouldContinue)
            guard let chunk = try await chunkIterator.next() else {
                break
            }

            if !chunk.bytes.isEmpty {
                try self.writeLocalData(Data(chunk.bytes), to: localHandle)
                bytesTransferred += UInt64(chunk.bytes.count)
            }

            if let progress {
                await progress(
                    SSHSFTPTransferProgress(
                        operation: .read,
                        bytesTransferred: bytesTransferred,
                        totalBytes: expectedSize
                    )
                )
            }
        }

        return bytesTransferred
    }

    private func downloadFileWithConcurrentReads(
        from remoteHandle: SFTPFileHandle,
        to localHandle: FileHandle,
        expectedSize: UInt64,
        chunkSize: UInt32,
        maxConcurrentReads: Int,
        progress: SSHSFTPTransferProgressHandler?,
        shouldContinue: SSHSFTPTransferContinuationHandler?
    ) async throws -> UInt64 {
        guard expectedSize > 0 else {
            return 0
        }

        let readLength = await remoteHandle.effectiveReadLength(chunkSize)
        var pendingReads: [(requestID: UInt32, offset: UInt64, length: UInt32)] = []
        var nextPendingIndex = 0
        var nextOffsetToSchedule: UInt64 = 0
        var bytesTransferred: UInt64 = 0
        var concurrentReadLimit = maxConcurrentReads

        do {
            func scheduleAvailableReads() async throws {
                while pendingReads.count - nextPendingIndex < concurrentReadLimit,
                      nextOffsetToSchedule < expectedSize {
                    try await self.checkTransferContinuation(shouldContinue)
                    let remaining = expectedSize - nextOffsetToSchedule
                    let length = UInt32(min(UInt64(readLength), remaining))
                    let offset = nextOffsetToSchedule
                    let requestID = try await remoteHandle.sendReadRequest(
                        at: offset,
                        length: length
                    )
                    pendingReads.append((requestID: requestID, offset: offset, length: length))
                    nextOffsetToSchedule += UInt64(length)
                }
            }

            try await scheduleAvailableReads()

            while true {
                if nextPendingIndex >= pendingReads.count {
                    guard nextOffsetToSchedule < expectedSize else {
                        return bytesTransferred
                    }
                    pendingReads.removeAll()
                    nextPendingIndex = 0
                    try await scheduleAvailableReads()
                    if pendingReads.isEmpty {
                        return bytesTransferred
                    }
                }

                try await self.checkTransferContinuation(shouldContinue)
                let pendingRead = pendingReads[nextPendingIndex]
                nextPendingIndex += 1
                guard let bytes = try await remoteHandle.receiveReadResponse(
                    for: pendingRead.requestID,
                    length: pendingRead.length
                ), !bytes.isEmpty else {
                    for pendingRead in pendingReads[nextPendingIndex...] {
                        await remoteHandle.cancelPendingResponse(for: pendingRead.requestID)
                    }
                    return bytesTransferred
                }

                try await self.checkTransferContinuation(shouldContinue)
                try self.writeLocalData(Data(bytes), to: localHandle)
                bytesTransferred += UInt64(bytes.count)

                if let progress {
                    await progress(
                        SSHSFTPTransferProgress(
                            operation: .read,
                            bytesTransferred: bytesTransferred,
                            totalBytes: expectedSize
                        )
                    )
                }

                try await self.checkTransferContinuation(shouldContinue)

                guard bytes.count == Int(pendingRead.length) else {
                    for pendingRead in pendingReads[nextPendingIndex...] {
                        await remoteHandle.cancelPendingResponse(for: pendingRead.requestID)
                    }
                    pendingReads.removeAll()
                    nextPendingIndex = 0
                    nextOffsetToSchedule = pendingRead.offset + UInt64(bytes.count)
                    concurrentReadLimit = 1
                    try await scheduleAvailableReads()
                    continue
                }

                try await scheduleAvailableReads()
            }
        } catch {
            for pendingRead in pendingReads[nextPendingIndex...] {
                await remoteHandle.cancelPendingResponse(for: pendingRead.requestID)
            }
            throw error
        }
    }

    private func uploadFileSequentially(
        from localHandle: FileHandle,
        to remoteHandle: SFTPFileHandle,
        totalBytes: UInt64?,
        chunkSize: UInt32,
        progress: SSHSFTPTransferProgressHandler?,
        shouldContinue: SSHSFTPTransferContinuationHandler?
    ) async throws -> UInt64 {
        var bytesTransferred: UInt64 = 0
        var offset: UInt64 = 0
        let maximumWriteDataLength = await remoteHandle.maximumWriteDataLength()
        let readLength = min(
            Int(max(chunkSize, 1)),
            maximumWriteDataLength
        )

        while true {
            try await self.checkTransferContinuation(shouldContinue)
            let data = try self.readLocalData(from: localHandle, upToCount: readLength)
            if data.isEmpty {
                break
            }
            try await self.checkTransferContinuation(shouldContinue)

            let bytes = Array(data)
            try await remoteHandle.write(bytes, at: offset)
            offset += UInt64(bytes.count)
            bytesTransferred += UInt64(bytes.count)

            if let progress {
                await progress(
                    SSHSFTPTransferProgress(
                        operation: .write,
                        bytesTransferred: bytesTransferred,
                        totalBytes: totalBytes
                    )
                )
            }
        }

        return bytesTransferred
    }

    private func uploadFileWithConcurrentWrites(
        from localHandle: FileHandle,
        to remoteHandle: SFTPFileHandle,
        totalBytes: UInt64?,
        chunkSize: UInt32,
        maxConcurrentWrites: Int,
        progress: SSHSFTPTransferProgressHandler?,
        shouldContinue: SSHSFTPTransferContinuationHandler?
    ) async throws -> UInt64 {
        var pendingWrites: [(requestID: UInt32, byteCount: Int)] = []
        var nextPendingIndex = 0
        var nextOffset: UInt64 = 0
        var bytesTransferred: UInt64 = 0
        let maximumWriteDataLength = await remoteHandle.maximumWriteDataLength()
        let readLength = min(
            Int(max(chunkSize, 1)),
            maximumWriteDataLength
        )

        do {
            func scheduleAvailableWrites() async throws {
                while pendingWrites.count - nextPendingIndex < maxConcurrentWrites {
                    try await self.checkTransferContinuation(shouldContinue)
                    let data = try self.readLocalData(
                        from: localHandle,
                        upToCount: readLength
                    )
                    if data.isEmpty {
                        return
                    }
                    try await self.checkTransferContinuation(shouldContinue)
                    let bytes = Array(data)
                    let requestID = try await remoteHandle.sendWriteRequest(
                        bytes,
                        at: nextOffset
                    )
                    pendingWrites.append((requestID: requestID, byteCount: bytes.count))
                    nextOffset += UInt64(bytes.count)
                }
            }

            try await scheduleAvailableWrites()

            while nextPendingIndex < pendingWrites.count {
                try await self.checkTransferContinuation(shouldContinue)
                let pendingWrite = pendingWrites[nextPendingIndex]
                nextPendingIndex += 1
                try await remoteHandle.receiveWriteResponse(for: pendingWrite.requestID)
                bytesTransferred += UInt64(pendingWrite.byteCount)

                if let progress {
                    await progress(
                        SSHSFTPTransferProgress(
                            operation: .write,
                            bytesTransferred: bytesTransferred,
                            totalBytes: totalBytes
                        )
                    )
                }

                try await scheduleAvailableWrites()
            }

            return bytesTransferred
        } catch {
            for pendingWrite in pendingWrites[nextPendingIndex...] {
                await remoteHandle.cancelPendingResponse(for: pendingWrite.requestID)
            }
            throw error
        }
    }

    private func prepareWritableLocalFile(at localURL: URL) throws -> FileHandle {
        try self.validateLocalFileURL(localURL)
        try FileManager.default.createDirectory(
            at: localURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        if FileManager.default.fileExists(atPath: localURL.path) {
            try FileManager.default.removeItem(at: localURL)
        }

        _ = FileManager.default.createFile(atPath: localURL.path, contents: nil)
        return try FileHandle(forWritingTo: localURL)
    }

    private func openReadableLocalFile(at localURL: URL) throws -> FileHandle {
        try self.validateLocalFileURL(localURL)
        return try FileHandle(forReadingFrom: localURL)
    }

    private func readLocalData(
        from handle: FileHandle,
        upToCount count: Int
    ) throws -> Data {
        if #available(macOS 10.15.4, iOS 13.4, tvOS 13.4, watchOS 6.2, visionOS 1.0, *) {
            return try handle.read(upToCount: count) ?? Data()
        }

        return handle.readData(ofLength: count)
    }

    private func writeLocalData(
        _ data: Data,
        to handle: FileHandle
    ) throws {
        if #available(macOS 10.15.4, iOS 13.4, tvOS 13.4, watchOS 6.2, visionOS 1.0, *) {
            try handle.write(contentsOf: data)
            return
        }

        handle.write(data)
    }

    private func closeLocalHandle(_ handle: FileHandle) {
        if #available(macOS 10.15.4, iOS 13.4, tvOS 13.4, watchOS 6.2, visionOS 1.0, *) {
            try? handle.close()
            return
        }

        handle.closeFile()
    }

    private func localFileSizeIfAvailable(at localURL: URL) throws -> UInt64? {
        let values = try localURL.resourceValues(forKeys: [.isDirectoryKey, .fileSizeKey])
        if values.isDirectory == true {
            throw SSHSFTPLocalFileTransferError.localURLReferencesDirectory(localURL)
        }

        guard let fileSize = values.fileSize else {
            return nil
        }
        return UInt64(fileSize)
    }

    private func validateLocalFileURL(_ localURL: URL) throws {
        guard localURL.isFileURL else {
            throw SSHSFTPLocalFileTransferError.localURLMustReferenceFile(localURL)
        }

        let values = try? localURL.resourceValues(forKeys: [.isDirectoryKey])
        if values?.isDirectory == true {
            throw SSHSFTPLocalFileTransferError.localURLReferencesDirectory(localURL)
        }
    }
}
