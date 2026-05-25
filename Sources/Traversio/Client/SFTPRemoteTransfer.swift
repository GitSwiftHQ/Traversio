// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

/// Errors raised by client-mediated remote-to-remote SFTP copies.
public enum SSHSFTPRemoteTransferError: Error, Equatable, Sendable {
    /// Source Path Is Not Directory.
    case sourcePathIsNotDirectory(String)
}

/// Helpers for copying data between two SFTP clients through the local process.
///
/// The source and destination clients may point at the same SSH server or at
/// different servers. Data is read from the source SFTP channel and written to
/// the destination SFTP channel by the caller's process; this is not a
/// server-side copy extension.
///
/// Example:
///
/// ```swift
/// let copied = try await SFTPRemoteTransfer.copyFile(
///     from: sourceSFTP,
///     sourcePath: "/srv/app.tar.gz",
///     to: destinationSFTP,
///     destinationPath: "/tmp/app.tar.gz"
/// )
/// ```
public struct SFTPRemoteTransfer: Sendable {
    /// Copies one regular file from a source SFTP client to a destination SFTP
    /// client.
    ///
    /// The destination file is created or truncated.
    public static func copyFile(
        from sourceClient: SFTPClient,
        sourcePath: String,
        to destinationClient: SFTPClient,
        destinationPath: String,
        attributes: SSHSFTPFileAttributes = .empty,
        chunkSize: UInt32 = 64 * 1024,
        progress: SSHSFTPTransferProgressHandler? = nil,
        shouldContinue: SSHSFTPTransferContinuationHandler? = nil
    ) async throws -> UInt64 {
        try await sourceClient.checkTransferContinuation(shouldContinue)
        let sourceHandle = try await sourceClient.openFile(sourcePath, flags: [.read])

        do {
            try await destinationClient.checkTransferContinuation(shouldContinue)
            let destinationHandle = try await destinationClient.openFile(
                destinationPath,
                flags: [.write, .create, .truncate],
                attributes: attributes
            )

            do {
                var bytesTransferred: UInt64 = 0
                var chunks = sourceHandle.readChunks(
                    chunkSize: max(chunkSize, 1)
                ).makeAsyncIterator()

                while true {
                    try await sourceClient.checkTransferContinuation(shouldContinue)
                    guard let chunk = try await chunks.next() else {
                        break
                    }

                    guard !chunk.bytes.isEmpty else {
                        continue
                    }

                    try await destinationClient.checkTransferContinuation(shouldContinue)
                    try await destinationHandle.write(chunk.bytes)
                    bytesTransferred += UInt64(chunk.bytes.count)

                    if let progress {
                        await progress(
                            SSHSFTPTransferProgress(
                                operation: .write,
                                bytesTransferred: bytesTransferred
                            )
                        )
                    }
                }

                try await destinationHandle.close()
                try await sourceHandle.close()
                return bytesTransferred
            } catch {
                try? await destinationHandle.close()
                throw error
            }
        } catch {
            try? await sourceHandle.close()
            throw error
        }
    }

    /// Recursively copies a source directory to a destination directory.
    ///
    /// Regular files and directories are copied. Symbolic links and other entry
    /// kinds are counted as skipped in the returned summary.
    public static func copyDirectory(
        from sourceClient: SFTPClient,
        sourcePath: String,
        to destinationClient: SFTPClient,
        destinationPath: String,
        fileAttributes: SSHSFTPFileAttributes = .empty,
        directoryAttributes: SSHSFTPFileAttributes = .empty,
        chunkSize: UInt32 = 64 * 1024,
        progress: SSHSFTPTransferProgressHandler? = nil,
        shouldContinue: SSHSFTPTransferContinuationHandler? = nil
    ) async throws -> SSHSFTPDirectoryTransferSummary {
        try await sourceClient.checkTransferContinuation(shouldContinue)
        let sourceAttributes = try await sourceClient.stat(sourcePath)
        guard remoteEntryKind(for: sourceAttributes, longName: nil) == .directory else {
            throw SSHSFTPRemoteTransferError.sourcePathIsNotDirectory(sourcePath)
        }

        return try await copyDirectoryContents(
            from: sourceClient,
            sourcePath: sourcePath,
            to: destinationClient,
            destinationPath: destinationPath,
            startingBytes: 0,
            fileAttributes: fileAttributes,
            directoryAttributes: directoryAttributes,
            chunkSize: chunkSize,
            progress: progress,
            shouldContinue: shouldContinue
        )
    }

    private static func copyDirectoryContents(
        from sourceClient: SFTPClient,
        sourcePath: String,
        to destinationClient: SFTPClient,
        destinationPath: String,
        startingBytes: UInt64,
        fileAttributes: SSHSFTPFileAttributes,
        directoryAttributes: SSHSFTPFileAttributes,
        chunkSize: UInt32,
        progress: SSHSFTPTransferProgressHandler?,
        shouldContinue: SSHSFTPTransferContinuationHandler?
    ) async throws -> SSHSFTPDirectoryTransferSummary {
        try await sourceClient.checkTransferContinuation(shouldContinue)
        try await ensureRemoteDirectoryExists(
            destinationPath,
            on: destinationClient,
            attributes: directoryAttributes
        )

        let entries = try await sourceClient.listDirectory(sourcePath)
        var summary = SSHSFTPDirectoryTransferSummary(
            bytesTransferred: 0,
            filesTransferred: 0,
            directoriesTraversed: 1,
            skippedEntries: 0
        )

        for entry in entries {
            try await sourceClient.checkTransferContinuation(shouldContinue)

            if entry.filename == "." || entry.filename == ".." {
                continue
            }

            let sourceChildPath = appendingRemotePathComponent(
                entry.filename,
                to: sourcePath
            )
            let destinationChildPath = appendingRemotePathComponent(
                entry.filename,
                to: destinationPath
            )

            switch remoteEntryKind(for: entry) {
            case .directory:
                let childSummary = try await copyDirectoryContents(
                    from: sourceClient,
                    sourcePath: sourceChildPath,
                    to: destinationClient,
                    destinationPath: destinationChildPath,
                    startingBytes: startingBytes + summary.bytesTransferred,
                    fileAttributes: fileAttributes,
                    directoryAttributes: directoryAttributes,
                    chunkSize: chunkSize,
                    progress: progress,
                    shouldContinue: shouldContinue
                )
                summary = summary.merging(childSummary)
            case .regularFile:
                let bytesCopied = try await copyFile(
                    from: sourceClient,
                    sourcePath: sourceChildPath,
                    to: destinationClient,
                    destinationPath: destinationChildPath,
                    attributes: fileAttributes,
                    chunkSize: chunkSize,
                    progress: cumulativeDirectoryProgressHandler(
                        startingBytes: startingBytes + summary.bytesTransferred,
                        progress: progress
                    ),
                    shouldContinue: shouldContinue
                )
                summary = summary.merging(
                    SSHSFTPDirectoryTransferSummary(
                        bytesTransferred: bytesCopied,
                        filesTransferred: 1,
                        directoriesTraversed: 0,
                        skippedEntries: 0
                    )
                )
            case .symbolicLink, .other:
                summary = summary.merging(
                    SSHSFTPDirectoryTransferSummary(
                        bytesTransferred: 0,
                        filesTransferred: 0,
                        directoriesTraversed: 0,
                        skippedEntries: 1
                    )
                )
            }
        }

        return summary
    }

    private static func ensureRemoteDirectoryExists(
        _ path: String,
        on client: SFTPClient,
        attributes: SSHSFTPFileAttributes
    ) async throws {
        do {
            try await client.makeDirectory(path, attributes: attributes)
        } catch {
            let existingAttributes = try await client.stat(path)
            guard remoteEntryKind(for: existingAttributes, longName: nil) == .directory else {
                throw error
            }
        }
    }

    private static func cumulativeDirectoryProgressHandler(
        startingBytes: UInt64,
        progress: SSHSFTPTransferProgressHandler?
    ) -> SSHSFTPTransferProgressHandler? {
        guard let progress else { return nil }

        return { value in
            await progress(
                SSHSFTPTransferProgress(
                    operation: value.operation,
                    bytesTransferred: startingBytes + value.bytesTransferred,
                    totalBytes: nil
                )
            )
        }
    }

    private static func appendingRemotePathComponent(
        _ component: String,
        to parentPath: String
    ) -> String {
        if parentPath == "/" {
            return "/" + component
        }

        if parentPath.hasSuffix("/") {
            return parentPath + component
        }

        return parentPath + "/" + component
    }

    private static func remoteEntryKind(
        for entry: SSHSFTPNameEntry
    ) -> SSHSFTPRemoteTransferEntryKind {
        remoteEntryKind(
            for: entry.attributes,
            longName: entry.longName
        )
    }

    private static func remoteEntryKind(
        for attributes: SSHSFTPFileAttributes,
        longName: String?
    ) -> SSHSFTPRemoteTransferEntryKind {
        if let permissions = attributes.permissions {
            switch permissions & SSHSFTPRemoteTransferEntryKind.typeMask {
            case SSHSFTPRemoteTransferEntryKind.regularFileBits:
                return .regularFile
            case SSHSFTPRemoteTransferEntryKind.directoryBits:
                return .directory
            case SSHSFTPRemoteTransferEntryKind.symbolicLinkBits:
                return .symbolicLink
            default:
                break
            }
        }

        switch longName?.first {
        case "-":
            return .regularFile
        case "d":
            return .directory
        case "l":
            return .symbolicLink
        default:
            return .other
        }
    }
}

private enum SSHSFTPRemoteTransferEntryKind: Sendable {
    static let typeMask: UInt32 = 0o170000
    static let regularFileBits: UInt32 = 0o100000
    static let directoryBits: UInt32 = 0o040000
    static let symbolicLinkBits: UInt32 = 0o120000

    case regularFile
    case directory
    case symbolicLink
    case other
}
