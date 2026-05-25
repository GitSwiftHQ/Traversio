// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// One offset-tagged chunk produced by `SFTPFileHandle.readChunks(...)`.
public struct SSHSFTPFileChunk: Equatable, Sendable {
    /// Offset.
    public let offset: UInt64
    /// Bytes.
    public let bytes: [UInt8]
    /// Count.

    public var count: Int {
        self.bytes.count
    }
    /// End offset.

    public var endOffset: UInt64 {
        self.offset + UInt64(self.bytes.count)
    }
    /// Creates an SSHSFTPFileChunk.

    public init(offset: UInt64, bytes: [UInt8]) {
        self.offset = offset
        self.bytes = bytes
    }
}

/// Async sequence for streaming a remote file in chunks.
public struct SSHSFTPFileChunkSequence: AsyncSequence, Sendable {
    /// Element type produced by this async sequence.
    public typealias Element = SSHSFTPFileChunk

    private let startingOffset: UInt64
    private let chunkSize: UInt32
    private let nextChunkReader: @Sendable (UInt64, UInt32) async throws -> [UInt8]?

    init(
        startingAt startingOffset: UInt64 = 0,
        chunkSize: UInt32 = 32 * 1_024,
        nextChunkReader: @escaping @Sendable (UInt64, UInt32) async throws -> [UInt8]?
    ) {
        self.startingOffset = startingOffset
        self.chunkSize = Swift.max(chunkSize, 1)
        self.nextChunkReader = nextChunkReader
    }

    /// Creates an async iterator for this sequence.
    public func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(
            nextOffset: self.startingOffset,
            chunkSize: self.chunkSize,
            nextChunkReader: self.nextChunkReader
        )
    }

    public struct AsyncIterator: AsyncIteratorProtocol {
        private var nextOffset: UInt64
        private let chunkSize: UInt32
        private let nextChunkReader: @Sendable (UInt64, UInt32) async throws -> [UInt8]?
        private var didReachEnd = false

        init(
            nextOffset: UInt64,
            chunkSize: UInt32,
            nextChunkReader: @escaping @Sendable (UInt64, UInt32) async throws -> [UInt8]?
        ) {
            self.nextOffset = nextOffset
            self.chunkSize = chunkSize
            self.nextChunkReader = nextChunkReader
        }

        public mutating func next() async throws -> SSHSFTPFileChunk? {
            guard !self.didReachEnd else {
                return nil
            }

            let chunkOffset = self.nextOffset
            guard let bytes = try await self.nextChunkReader(chunkOffset, self.chunkSize),
                  !bytes.isEmpty else {
                self.didReachEnd = true
                return nil
            }

            self.nextOffset += UInt64(bytes.count)
            return SSHSFTPFileChunk(offset: chunkOffset, bytes: bytes)
        }
    }
}
