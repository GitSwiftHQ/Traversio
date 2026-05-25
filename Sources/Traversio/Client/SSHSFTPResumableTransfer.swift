// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Result returned by `SFTPClient.resumeUploadFile(...)`.
public struct SSHSFTPResumeUploadResult: Equatable, Sendable {
    /// Remote path that received the uploaded bytes.
    public let path: String

    /// Remote offset where this upload attempt started.
    public let startingOffset: UInt64

    /// Number of bytes uploaded by this attempt.
    public let bytesUploaded: UInt64

    /// Total local payload size after the upload completes.
    public let totalBytes: UInt64

    /// Creates a resumable upload result value.
    public init(
        path: String,
        startingOffset: UInt64,
        bytesUploaded: UInt64,
        totalBytes: UInt64
    ) {
        self.path = path
        self.startingOffset = startingOffset
        self.bytesUploaded = bytesUploaded
        self.totalBytes = totalBytes
    }

    /// Whether this transfer resumed from a non-zero remote offset.
    public var didResume: Bool {
        self.startingOffset > 0
    }

    /// Remote offset immediately after the uploaded bytes.
    public var finalOffset: UInt64 {
        self.startingOffset + self.bytesUploaded
    }
}

/// Result returned by `SFTPClient.resumeDownloadFile(...)`.
public struct SSHSFTPResumeDownloadResult: Equatable, Sendable {
    /// Remote path that provided the downloaded bytes.
    public let path: String

    /// Remote offset where this download attempt started.
    public let startingOffset: UInt64

    /// Number of bytes downloaded by this attempt.
    public let bytesDownloaded: UInt64

    /// Total remote file size observed for this download.
    public let totalBytes: UInt64

    /// Collected channel data.
    public let data: [UInt8]

    /// Creates a resumable download result value.
    public init(
        path: String,
        startingOffset: UInt64,
        bytesDownloaded: UInt64,
        totalBytes: UInt64,
        data: [UInt8]
    ) {
        self.path = path
        self.startingOffset = startingOffset
        self.bytesDownloaded = bytesDownloaded
        self.totalBytes = totalBytes
        self.data = data
    }

    /// Whether this transfer resumed from a non-zero remote offset.
    public var didResume: Bool {
        self.startingOffset > 0
    }

    /// Remote offset immediately after the downloaded bytes.
    public var finalOffset: UInt64 {
        self.startingOffset + self.bytesDownloaded
    }
}

/// Errors raised by resumable SFTP upload and download helpers.
public enum SSHSFTPResumeError: Error, Equatable, Sendable {
    /// The remote file size could not be obtained before resuming.
    case remoteFileSizeUnavailable(path: String)

    /// The existing remote file is larger than the local upload payload.
    case remoteFileIsLargerThanLocalData(
        path: String,
        remoteSize: UInt64,
        localSize: UInt64
    )

    /// The existing remote file is smaller than the local data required for the requested resume mode.
    case remoteFileIsSmallerThanLocalData(
        path: String,
        remoteSize: UInt64,
        localSize: UInt64
    )
}
