// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

extension SSHSFTPClient {
    package func readFile(
        handle: SSHSFTPHandle,
        offset: UInt64,
        length: UInt32
    ) async throws -> [UInt8]? {
        _ = try self.currentVersionExchange()

        let effectiveLength = self.effectiveReadLength(length)
        let requestID = try await self.sendReadRequest(
            handle: handle,
            offset: offset,
            length: effectiveLength
        )
        return try await self.receiveReadResponse(
            for: requestID,
            length: effectiveLength
        )
    }

    package func writeFile(
        handle: SSHSFTPHandle,
        offset: UInt64,
        data: [UInt8]
    ) async throws {
        _ = try self.currentVersionExchange()
        let maximumWriteDataLength = self.maximumWriteDataLength(for: handle)
        if data.count > maximumWriteDataLength {
            try await self.writeFileSequentially(
                handle: handle,
                data: data,
                startingAt: offset,
                chunkSize: maximumWriteDataLength,
                progress: nil
            )
            return
        }

        let requestID = try await self.sendWriteRequest(
            handle: handle,
            offset: offset,
            data: data
        )
        try await self.receiveWriteResponse(for: requestID)
    }

    package func readFile(
        _ path: String,
        chunkSize: UInt32 = 32 * 1024,
        maxConcurrentReads: Int = 1,
        progress: SSHSFTPTransferProgressHandler? = nil
    ) async throws -> [UInt8] {
        _ = try self.currentVersionExchange()

        let handle = try await self.openFile(path)

        do {
            let data = try await self.readFile(
                handle: handle,
                startingAt: 0,
                chunkSize: chunkSize,
                maxConcurrentReads: maxConcurrentReads,
                progress: progress
            )
            try await self.close(handle: handle)
            return data
        } catch {
            try? await self.close(handle: handle)
            throw error
        }
    }

    package func writeFile(
        _ path: String,
        data: [UInt8],
        chunkSize: UInt32 = 32 * 1024,
        maxConcurrentWrites: Int = 1,
        syncAfterWrite: Bool = false,
        progress: SSHSFTPTransferProgressHandler? = nil,
        flags: SSHSFTPOpenFileFlags = [.write, .create, .truncate],
        attributes: SSHSFTPFileAttributes = .empty
    ) async throws {
        _ = try self.currentVersionExchange()

        if syncAfterWrite {
            try self.requireSupportedExtension(
                named: Self.fsyncExtensionName,
                minimumVersion: 1
            )
        }

        let handle = try await self.openFile(
            path,
            flags: flags,
            attributes: attributes
        )

        do {
            try await self.writeFile(
                handle: handle,
                data: data,
                startingAt: 0,
                chunkSize: chunkSize,
                maxConcurrentWrites: maxConcurrentWrites,
                progress: progress
            )

            if syncAfterWrite {
                try await self.synchronize(handle: handle)
            }
        } catch {
            try? await self.close(handle: handle)
            throw error
        }

        try await self.close(handle: handle)
    }

    package func writeFile(
        handle: SSHSFTPHandle,
        data: [UInt8],
        startingAt offset: UInt64 = 0,
        chunkSize: UInt32 = 32 * 1024,
        maxConcurrentWrites: Int = 1,
        progress: SSHSFTPTransferProgressHandler? = nil
    ) async throws {
        _ = try self.currentVersionExchange()

        let effectiveChunkSize = min(
            max(Int(chunkSize), 1),
            self.maximumWriteDataLength(for: handle)
        )
        let effectiveMaxConcurrentWrites = max(maxConcurrentWrites, 1)

        if effectiveMaxConcurrentWrites == 1 {
            try await self.writeFileSequentially(
                handle: handle,
                data: data,
                startingAt: offset,
                chunkSize: effectiveChunkSize,
                progress: progress
            )
            return
        }

        try await self.writeFileWithConcurrentRequests(
            handle: handle,
            data: data,
            startingAt: offset,
            chunkSize: effectiveChunkSize,
            maxConcurrentWrites: effectiveMaxConcurrentWrites,
            progress: progress
        )
    }

    package func readFile(
        handle: SSHSFTPHandle,
        startingAt offset: UInt64 = 0,
        chunkSize: UInt32 = 32 * 1024,
        maxConcurrentReads: Int = 1,
        progress: SSHSFTPTransferProgressHandler? = nil
    ) async throws -> [UInt8] {
        _ = try self.currentVersionExchange()

        let effectiveChunkSize = Int(self.effectiveReadLength(chunkSize))
        let effectiveMaxConcurrentReads = max(maxConcurrentReads, 1)
        if effectiveMaxConcurrentReads == 1 {
            return try await self.readFileSequentially(
                handle: handle,
                startingAt: offset,
                chunkSize: UInt32(effectiveChunkSize),
                progress: progress
            )
        }

        return try await self.readFileWithConcurrentRequests(
            handle: handle,
            startingAt: offset,
            chunkSize: effectiveChunkSize,
            maxConcurrentReads: effectiveMaxConcurrentReads,
            progress: progress
        )
    }

    private func readFileSequentially(
        handle: SSHSFTPHandle,
        startingAt offset: UInt64,
        chunkSize: UInt32,
        progress: SSHSFTPTransferProgressHandler?
    ) async throws -> [UInt8] {
        var data: [UInt8] = []
        var nextOffset = offset
        var bytesTransferred: UInt64 = 0

        while let chunk = try await self.readFile(
            handle: handle,
            offset: nextOffset,
            length: chunkSize
        ) {
            try self.checkCancellation()
            if chunk.isEmpty {
                break
            }
            data.append(contentsOf: chunk)
            bytesTransferred += UInt64(chunk.count)
            await self.reportTransferProgress(
                .init(
                    operation: .read,
                    bytesTransferred: bytesTransferred
                ),
                using: progress
            )
            nextOffset += UInt64(chunk.count)
        }

        return data
    }

    private func writeFileSequentially(
        handle: SSHSFTPHandle,
        data: [UInt8],
        startingAt offset: UInt64,
        chunkSize: Int,
        progress: SSHSFTPTransferProgressHandler?
    ) async throws {
        var nextOffset = offset
        var chunkStart = 0
        var bytesTransferred: UInt64 = 0
        let totalBytes = UInt64(data.count)

        while chunkStart < data.count {
            try self.checkCancellation()
            let chunkEnd = min(chunkStart + chunkSize, data.count)
            let chunk = Array(data[chunkStart..<chunkEnd])
            try await self.writeFile(
                handle: handle,
                offset: nextOffset,
                data: chunk
            )
            bytesTransferred += UInt64(chunk.count)
            await self.reportTransferProgress(
                .init(
                    operation: .write,
                    bytesTransferred: bytesTransferred,
                    totalBytes: totalBytes
                ),
                using: progress
            )
            nextOffset += UInt64(chunk.count)
            chunkStart = chunkEnd
        }
    }

    private func readFileWithConcurrentRequests(
        handle: SSHSFTPHandle,
        startingAt offset: UInt64,
        chunkSize: Int,
        maxConcurrentReads: Int,
        progress: SSHSFTPTransferProgressHandler?
    ) async throws -> [UInt8] {
        let readLength = UInt32(chunkSize)
        var data: [UInt8] = []
        var pendingRequests: [UInt64: UInt32] = [:]
        var nextOffsetToSchedule = offset
        var nextOffsetToAppend = offset
        var bytesTransferred: UInt64 = 0
        var concurrentReadLimit = maxConcurrentReads

        while pendingRequests.count < concurrentReadLimit {
            let offset = nextOffsetToSchedule
            nextOffsetToSchedule += UInt64(chunkSize)
            pendingRequests[offset] = try await self.sendReadRequest(
                handle: handle,
                offset: offset,
                length: readLength
            )
        }

        while let requestID = pendingRequests.removeValue(forKey: nextOffsetToAppend) {
            try self.checkCancellation()
            let chunk = try await self.receiveReadResponse(
                for: requestID,
                length: readLength
            )

            switch chunk {
            case let .some(bytes):
                guard !bytes.isEmpty else {
                    let laterRequestIDs = pendingRequests
                        .filter { $0.key > nextOffsetToAppend }
                        .map(\.value)
                    for requestID in laterRequestIDs {
                        self.cancelPendingResponse(for: requestID)
                    }
                    return data
                }

                data.append(contentsOf: bytes)
                bytesTransferred += UInt64(bytes.count)
                await self.reportTransferProgress(
                    .init(
                        operation: .read,
                        bytesTransferred: bytesTransferred
                    ),
                    using: progress
                )
                nextOffsetToAppend += UInt64(bytes.count)

                if bytes.count < chunkSize {
                    for requestID in pendingRequests.values {
                        self.cancelPendingResponse(for: requestID)
                    }
                    pendingRequests.removeAll()
                    nextOffsetToSchedule = nextOffsetToAppend
                    concurrentReadLimit = 1
                }
            case .none:
                let laterRequestIDs = pendingRequests
                    .filter { $0.key > nextOffsetToAppend }
                    .map(\.value)
                for requestID in laterRequestIDs {
                    self.cancelPendingResponse(for: requestID)
                }
                return data
            }

            while pendingRequests.count < concurrentReadLimit {
                let offset = nextOffsetToSchedule
                nextOffsetToSchedule += UInt64(chunkSize)
                pendingRequests[offset] = try await self.sendReadRequest(
                    handle: handle,
                    offset: offset,
                    length: readLength
                )
            }
        }

        return data
    }

    private func writeFileWithConcurrentRequests(
        handle: SSHSFTPHandle,
        data: [UInt8],
        startingAt offset: UInt64,
        chunkSize: Int,
        maxConcurrentWrites: Int,
        progress: SSHSFTPTransferProgressHandler?
    ) async throws {
        var pendingWrites: [(requestID: UInt32, count: Int)] = []
        var nextPendingIndex = 0
        var nextChunkStart = 0
        var nextOffset = offset
        var bytesTransferred: UInt64 = 0
        let totalBytes = UInt64(data.count)

        do {
            while pendingWrites.count - nextPendingIndex < maxConcurrentWrites,
                  nextChunkStart < data.count {
                let chunkEnd = min(nextChunkStart + chunkSize, data.count)
                let chunk = Array(data[nextChunkStart..<chunkEnd])
                let requestID = try await self.sendWriteRequest(
                    handle: handle,
                    offset: nextOffset,
                    data: chunk
                )
                pendingWrites.append((requestID: requestID, count: chunk.count))
                nextOffset += UInt64(chunk.count)
                nextChunkStart = chunkEnd
            }

            while nextPendingIndex < pendingWrites.count {
                try self.checkCancellation()
                let pendingWrite = pendingWrites[nextPendingIndex]
                nextPendingIndex += 1
                try await self.receiveWriteResponse(for: pendingWrite.requestID)
                bytesTransferred += UInt64(pendingWrite.count)
                await self.reportTransferProgress(
                    .init(
                        operation: .write,
                        bytesTransferred: bytesTransferred,
                        totalBytes: totalBytes
                    ),
                    using: progress
                )

                while pendingWrites.count - nextPendingIndex < maxConcurrentWrites,
                      nextChunkStart < data.count {
                    let chunkEnd = min(nextChunkStart + chunkSize, data.count)
                    let chunk = Array(data[nextChunkStart..<chunkEnd])
                    let scheduledRequestID = try await self.sendWriteRequest(
                        handle: handle,
                        offset: nextOffset,
                        data: chunk
                    )
                    pendingWrites.append((requestID: scheduledRequestID, count: chunk.count))
                    nextOffset += UInt64(chunk.count)
                    nextChunkStart = chunkEnd
                }
            }
        } catch {
            for pendingWrite in pendingWrites[nextPendingIndex...] {
                self.cancelPendingResponse(for: pendingWrite.requestID)
            }
            throw error
        }
    }

    private func reportTransferProgress(
        _ progressValue: SSHSFTPTransferProgress,
        using progress: SSHSFTPTransferProgressHandler?
    ) async {
        guard let progress else {
            return
        }

        await progress(progressValue)
    }
}
