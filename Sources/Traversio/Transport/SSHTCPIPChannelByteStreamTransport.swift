// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
actor SSHTCPIPChannelByteStreamTransport: SSHCancellationControllingByteStreamTransport {
    let handle: SSHTCPIPChannelHandle
    private var bufferedBytes: [UInt8] = []
    private var reachedEndOfStream = false
    private var channelCloseTask: Task<Void, Never>?

    init(handle: SSHTCPIPChannelHandle) {
        self.handle = handle
    }

    func send(_ bytes: [UInt8], endOfStream: Bool) async throws {
        try await self.send(bytes, endOfStream: endOfStream, respectCancellation: true)
    }

    func send(
        _ bytes: [UInt8],
        endOfStream: Bool,
        respectCancellation: Bool
    ) async throws {
        if respectCancellation {
            try Task.checkCancellation()
        }

        if !bytes.isEmpty {
            try await self.handle.write(bytes, respectCancellation: respectCancellation)
        }

        if endOfStream {
            try await self.handle.sendEOF(respectCancellation: respectCancellation)
        }

        if respectCancellation {
            try Task.checkCancellation()
        }
    }

    func receive(atLeast minimum: Int, atMost maximum: Int) async throws -> SSHByteStreamChunk {
        try await self.receive(
            atLeast: minimum,
            atMost: maximum,
            respectCancellation: true
        )
    }

    func receive(
        atLeast minimum: Int,
        atMost maximum: Int,
        respectCancellation: Bool
    ) async throws -> SSHByteStreamChunk {
        precondition(minimum > 0, "minimum receive size must be positive")
        precondition(maximum >= minimum, "maximum receive size must cover the minimum")

        if respectCancellation {
            try Task.checkCancellation()
        }

        while self.bufferedBytes.count < minimum && !self.reachedEndOfStream {
            guard let chunk = try await self.handle.readChunk(
                respectCancellation: respectCancellation
            ) else {
                self.reachedEndOfStream = true
                break
            }

            if chunk.isEmpty {
                continue
            }

            self.bufferedBytes += chunk
        }

        if respectCancellation {
            try Task.checkCancellation()
        }

        guard !self.bufferedBytes.isEmpty || self.reachedEndOfStream else {
            throw SSHTransportError.emptyReceive
        }

        let count = min(maximum, self.bufferedBytes.count)
        let output = Array(self.bufferedBytes.prefix(count))
        self.bufferedBytes.removeFirst(count)

        return SSHByteStreamChunk(
            bytes: output,
            endOfStream: self.reachedEndOfStream && self.bufferedBytes.isEmpty
        )
    }

    func close() async {
        self.reachedEndOfStream = true
        self.bufferedBytes.removeAll(keepingCapacity: false)
        guard self.channelCloseTask == nil else {
            return
        }

        let handle = self.handle
        self.channelCloseTask = Task {
            await handle.bestEffortCloseIgnoringCancellation()
        }
    }

    func abort() async {
        await self.close()
    }
}
actor SSHBufferedByteStreamTransport: SSHCancellationControllingByteStreamTransport {
    private let base: any SSHByteStreamTransport
    private var bufferedBytes: [UInt8]
    private var bufferedEndOfStream = false

    init(
        base: any SSHByteStreamTransport,
        bufferedBytes: [UInt8] = [],
        bufferedEndOfStream: Bool = false
    ) {
        self.base = base
        self.bufferedBytes = bufferedBytes
        self.bufferedEndOfStream = bufferedEndOfStream
    }

    func send(_ bytes: [UInt8], endOfStream: Bool) async throws {
        try await self.send(bytes, endOfStream: endOfStream, respectCancellation: true)
    }

    func send(
        _ bytes: [UInt8],
        endOfStream: Bool,
        respectCancellation: Bool
    ) async throws {
        if let base = self.base as? any SSHCancellationControllingByteStreamTransport {
            try await base.send(
                bytes,
                endOfStream: endOfStream,
                respectCancellation: respectCancellation
            )
            return
        }

        try await self.base.send(bytes, endOfStream: endOfStream)
    }

    func receive(atLeast minimum: Int, atMost maximum: Int) async throws -> SSHByteStreamChunk {
        try await self.receive(
            atLeast: minimum,
            atMost: maximum,
            respectCancellation: true
        )
    }

    func receive(
        atLeast minimum: Int,
        atMost maximum: Int,
        respectCancellation: Bool
    ) async throws -> SSHByteStreamChunk {
        precondition(minimum > 0, "minimum receive size must be positive")
        precondition(maximum >= minimum, "maximum receive size must cover the minimum")

        while self.bufferedBytes.count < minimum && !self.bufferedEndOfStream {
            let chunk: SSHByteStreamChunk
            if let base = self.base as? any SSHCancellationControllingByteStreamTransport {
                chunk = try await base.receive(
                    atLeast: 1,
                    atMost: max(maximum, minimum),
                    respectCancellation: respectCancellation
                )
            } else {
                chunk = try await self.base.receive(atLeast: 1, atMost: max(maximum, minimum))
            }
            if !chunk.bytes.isEmpty {
                self.bufferedBytes += chunk.bytes
            }
            if chunk.endOfStream {
                self.bufferedEndOfStream = true
            }
        }

        if self.bufferedBytes.isEmpty {
            if self.bufferedEndOfStream {
                return SSHByteStreamChunk(bytes: [], endOfStream: true)
            }
            throw SSHTransportError.emptyReceive
        }

        let outputCount = min(maximum, self.bufferedBytes.count)
        let output = Array(self.bufferedBytes.prefix(outputCount))
        self.bufferedBytes.removeFirst(outputCount)

        return SSHByteStreamChunk(
            bytes: output,
            endOfStream: self.bufferedEndOfStream && self.bufferedBytes.isEmpty
        )
    }

    func close() async {
        self.bufferedBytes.removeAll(keepingCapacity: false)
        self.bufferedEndOfStream = true
        await self.base.close()
    }

    func abort() async {
        self.bufferedBytes.removeAll(keepingCapacity: false)
        self.bufferedEndOfStream = true
        await self.base.abort()
    }
}
