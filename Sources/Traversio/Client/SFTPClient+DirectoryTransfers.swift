// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Summary returned by recursive SFTP directory transfers.
public struct SSHSFTPDirectoryTransferSummary: Equatable, Sendable {
    /// Bytes Transferred.
    public let bytesTransferred: UInt64
    /// Files Transferred.
    public let filesTransferred: Int
    /// Directories Traversed.
    public let directoriesTraversed: Int
    /// Skipped Entries.
    public let skippedEntries: Int
    /// Creates an SSHSFTPDirectoryTransferSummary.

    public init(
        bytesTransferred: UInt64,
        filesTransferred: Int,
        directoriesTraversed: Int,
        skippedEntries: Int
    ) {
        self.bytesTransferred = bytesTransferred
        self.filesTransferred = filesTransferred
        self.directoriesTraversed = directoriesTraversed
        self.skippedEntries = skippedEntries
    }

    static let empty = Self(
        bytesTransferred: 0,
        filesTransferred: 0,
        directoriesTraversed: 0,
        skippedEntries: 0
    )

    func merging(_ other: Self) -> Self {
        Self(
            bytesTransferred: self.bytesTransferred + other.bytesTransferred,
            filesTransferred: self.filesTransferred + other.filesTransferred,
            directoriesTraversed: self.directoriesTraversed + other.directoriesTraversed,
            skippedEntries: self.skippedEntries + other.skippedEntries
        )
    }
}

/// Errors raised by recursive directory transfers before or during traversal.
public enum SSHSFTPDirectoryTransferError: Error, Equatable, Sendable {
    /// local URL Must Reference Directory.
    case localURLMustReferenceDirectory(URL)
    /// local URL References File.
    case localURLReferencesFile(URL)
    /// remote path Is Not Directory.
    case remotePathIsNotDirectory(String)
}

extension SFTPClient {
    /// Recursively downloads a remote directory into a local directory URL.
    ///
    /// Regular files are copied. Directory entries that are not regular files
    /// or directories are counted as skipped.
    ///
    /// Example:
    ///
    /// ```swift
    /// let summary = try await sftp.downloadDirectory(
    ///     "/srv/releases/current",
    ///     to: URL(filePath: "/tmp/current")
    /// )
    /// ```
    public func downloadDirectory(
        _ remotePath: String,
        to localURL: URL,
        chunkSize: UInt32 = 32 * 1_024,
        maxConcurrentReads: Int = 64,
        progress: SSHSFTPTransferProgressHandler? = nil,
        shouldContinue: SSHSFTPTransferContinuationHandler? = nil
    ) async throws -> SSHSFTPDirectoryTransferSummary {
        try self.validateLocalDirectoryURL(localURL)
        try await self.checkTransferContinuation(shouldContinue)
        return try await self.downloadDirectoryContents(
            remotePath: remotePath,
            localURL: localURL,
            startingBytes: 0,
            chunkSize: chunkSize,
            maxConcurrentReads: maxConcurrentReads,
            progress: progress,
            shouldContinue: shouldContinue
        )
    }

    /// Recursively uploads a local directory to a remote directory path.
    ///
    /// Traversio creates remote directories as needed and copies regular files.
    public func uploadDirectory(
        from localURL: URL,
        to remotePath: String,
        fileAttributes: SSHSFTPFileAttributes = .empty,
        directoryAttributes: SSHSFTPFileAttributes = .empty,
        chunkSize: UInt32 = 32 * 1_024,
        maxConcurrentWrites: Int = 16,
        syncAfterWrite: Bool = false,
        progress: SSHSFTPTransferProgressHandler? = nil,
        shouldContinue: SSHSFTPTransferContinuationHandler? = nil
    ) async throws -> SSHSFTPDirectoryTransferSummary {
        try self.validateLocalDirectoryURL(localURL)
        try await self.checkTransferContinuation(shouldContinue)
        return try await self.uploadDirectoryContents(
            localURL: localURL,
            remotePath: remotePath,
            startingBytes: 0,
            fileAttributes: fileAttributes,
            directoryAttributes: directoryAttributes,
            chunkSize: chunkSize,
            maxConcurrentWrites: maxConcurrentWrites,
            syncAfterWrite: syncAfterWrite,
            progress: progress,
            shouldContinue: shouldContinue
        )
    }

    private func downloadDirectoryContents(
        remotePath: String,
        localURL: URL,
        startingBytes: UInt64,
        chunkSize: UInt32,
        maxConcurrentReads: Int,
        progress: SSHSFTPTransferProgressHandler?,
        shouldContinue: SSHSFTPTransferContinuationHandler?
    ) async throws -> SSHSFTPDirectoryTransferSummary {
        try await self.checkTransferContinuation(shouldContinue)
        let entries = try await self.listRemoteDirectoryEntries(at: remotePath)
        try FileManager.default.createDirectory(
            at: localURL,
            withIntermediateDirectories: true
        )

        var summary = SSHSFTPDirectoryTransferSummary(
            bytesTransferred: 0,
            filesTransferred: 0,
            directoriesTraversed: 1,
            skippedEntries: 0
        )

        for entry in entries {
            try await self.checkTransferContinuation(shouldContinue)

            if entry.filename == "." || entry.filename == ".." {
                continue
            }

            let childRemotePath = self.appendingRemotePathComponent(
                entry.filename,
                to: remotePath
            )
            let childLocalURL = localURL.appendingPathComponent(
                entry.filename,
                isDirectory: self.remoteEntryKind(for: entry) == .directory
            )

            switch self.remoteEntryKind(for: entry) {
            case .directory:
                let childSummary = try await self.downloadDirectoryContents(
                    remotePath: childRemotePath,
                    localURL: childLocalURL,
                    startingBytes: startingBytes + summary.bytesTransferred,
                    chunkSize: chunkSize,
                    maxConcurrentReads: maxConcurrentReads,
                    progress: progress,
                    shouldContinue: shouldContinue
                )
                summary = summary.merging(childSummary)
            case .regularFile:
                let bytesDownloaded = try await self.downloadFile(
                    childRemotePath,
                    to: childLocalURL,
                    expectedSize: entry.attributes.size,
                    chunkSize: chunkSize,
                    maxConcurrentReads: maxConcurrentReads,
                    progress: self.cumulativeDirectoryProgressHandler(
                        startingBytes: startingBytes + summary.bytesTransferred,
                        progress: progress
                    ),
                    shouldContinue: shouldContinue
                )
                summary = summary.merging(
                    SSHSFTPDirectoryTransferSummary(
                        bytesTransferred: bytesDownloaded,
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

    private func uploadDirectoryContents(
        localURL: URL,
        remotePath: String,
        startingBytes: UInt64,
        fileAttributes: SSHSFTPFileAttributes,
        directoryAttributes: SSHSFTPFileAttributes,
        chunkSize: UInt32,
        maxConcurrentWrites: Int,
        syncAfterWrite: Bool,
        progress: SSHSFTPTransferProgressHandler?,
        shouldContinue: SSHSFTPTransferContinuationHandler?
    ) async throws -> SSHSFTPDirectoryTransferSummary {
        try await self.checkTransferContinuation(shouldContinue)
        try await self.ensureRemoteDirectoryExists(
            remotePath,
            attributes: directoryAttributes
        )
        try await self.checkTransferContinuation(shouldContinue)

        let resourceKeys: Set<URLResourceKey> = [
            .isDirectoryKey,
            .isRegularFileKey,
            .isSymbolicLinkKey,
        ]
        let children = try FileManager.default.contentsOfDirectory(
            at: localURL,
            includingPropertiesForKeys: Array(resourceKeys),
            options: []
        ).sorted { $0.lastPathComponent < $1.lastPathComponent }

        var summary = SSHSFTPDirectoryTransferSummary(
            bytesTransferred: 0,
            filesTransferred: 0,
            directoriesTraversed: 1,
            skippedEntries: 0
        )

        for child in children {
            try await self.checkTransferContinuation(shouldContinue)

            let values = try child.resourceValues(forKeys: resourceKeys)
            if values.isSymbolicLink == true {
                summary = summary.merging(
                    SSHSFTPDirectoryTransferSummary(
                        bytesTransferred: 0,
                        filesTransferred: 0,
                        directoriesTraversed: 0,
                        skippedEntries: 1
                    )
                )
                continue
            }

            let remoteChildPath = self.appendingRemotePathComponent(
                child.lastPathComponent,
                to: remotePath
            )

            if values.isDirectory == true {
                let childSummary = try await self.uploadDirectoryContents(
                    localURL: child,
                    remotePath: remoteChildPath,
                    startingBytes: startingBytes + summary.bytesTransferred,
                    fileAttributes: fileAttributes,
                    directoryAttributes: directoryAttributes,
                    chunkSize: chunkSize,
                    maxConcurrentWrites: maxConcurrentWrites,
                    syncAfterWrite: syncAfterWrite,
                    progress: progress,
                    shouldContinue: shouldContinue
                )
                summary = summary.merging(childSummary)
                continue
            }

            if values.isRegularFile == true {
                let bytesUploaded = try await self.uploadFile(
                    from: child,
                    to: remoteChildPath,
                    attributes: fileAttributes,
                    chunkSize: chunkSize,
                    maxConcurrentWrites: maxConcurrentWrites,
                    syncAfterWrite: syncAfterWrite,
                    progress: self.cumulativeDirectoryProgressHandler(
                        startingBytes: startingBytes + summary.bytesTransferred,
                        progress: progress
                    ),
                    shouldContinue: shouldContinue
                )
                summary = summary.merging(
                    SSHSFTPDirectoryTransferSummary(
                        bytesTransferred: bytesUploaded,
                        filesTransferred: 1,
                        directoriesTraversed: 0,
                        skippedEntries: 0
                    )
                )
                continue
            }

            summary = summary.merging(
                SSHSFTPDirectoryTransferSummary(
                    bytesTransferred: 0,
                    filesTransferred: 0,
                    directoriesTraversed: 0,
                    skippedEntries: 1
                )
            )
        }

        return summary
    }

    private func cumulativeDirectoryProgressHandler(
        startingBytes: UInt64,
        progress: SSHSFTPTransferProgressHandler?
    ) -> SSHSFTPTransferProgressHandler? {
        guard let progress else {
            return nil
        }

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

    private func validateLocalDirectoryURL(_ localURL: URL) throws {
        guard localURL.isFileURL else {
            throw SSHSFTPDirectoryTransferError.localURLMustReferenceDirectory(localURL)
        }

        var isDirectory = ObjCBool(false)
        let exists = FileManager.default.fileExists(
            atPath: localURL.path,
            isDirectory: &isDirectory
        )
        if exists && !isDirectory.boolValue {
            throw SSHSFTPDirectoryTransferError.localURLReferencesFile(localURL)
        }
    }

    private func listRemoteDirectoryEntries(
        at remotePath: String
    ) async throws -> [SSHSFTPNameEntry] {
        do {
            return try await self.listDirectory(remotePath)
        } catch {
            if try await self.remotePathReferencesDirectory(remotePath) == false {
                throw SSHSFTPDirectoryTransferError.remotePathIsNotDirectory(remotePath)
            }
            throw error
        }
    }

    private func ensureRemoteDirectoryExists(
        _ remotePath: String,
        attributes: SSHSFTPFileAttributes
    ) async throws {
        do {
            try await self.makeDirectory(remotePath, attributes: attributes)
        } catch {
            if try await self.remotePathReferencesDirectory(remotePath) {
                return
            }
            throw error
        }
    }

    private func remotePathReferencesDirectory(_ remotePath: String) async throws -> Bool {
        do {
            let attributes = try await self.stat(remotePath)
            if self.remoteEntryKind(for: attributes, longName: nil) == .directory {
                return true
            }
        } catch {
            return false
        }

        do {
            _ = try await self.listDirectory(remotePath)
            return true
        } catch {
            return false
        }
    }

    private func appendingRemotePathComponent(
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

    private func remoteEntryKind(for entry: SSHSFTPNameEntry) -> SSHSFTPDirectoryEntryKind {
        self.remoteEntryKind(
            for: entry.attributes,
            longName: entry.longName
        )
    }

    private func remoteEntryKind(
        for attributes: SSHSFTPFileAttributes,
        longName: String?
    ) -> SSHSFTPDirectoryEntryKind {
        if let permissions = attributes.permissions {
            switch permissions & SSHSFTPDirectoryEntryKind.typeMask {
            case SSHSFTPDirectoryEntryKind.regularFileBits:
                return .regularFile
            case SSHSFTPDirectoryEntryKind.directoryBits:
                return .directory
            case SSHSFTPDirectoryEntryKind.symbolicLinkBits:
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

private enum SSHSFTPDirectoryEntryKind: Sendable {
    static let typeMask: UInt32 = 0o170000
    static let regularFileBits: UInt32 = 0o100000
    static let directoryBits: UInt32 = 0o040000
    static let symbolicLinkBits: UInt32 = 0o120000

    case regularFile
    case directory
    case symbolicLink
    case other
}
