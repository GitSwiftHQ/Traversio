// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

package struct SSHSocketEndpoint: Equatable, Sendable {
    package let host: String
    package let port: UInt16

    package init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
}

package struct SSHByteStreamChunk: Equatable, Sendable {
    package let bytes: [UInt8]
    package let endOfStream: Bool

    package init(bytes: [UInt8], endOfStream: Bool) {
        self.bytes = bytes
        self.endOfStream = endOfStream
    }
}

package protocol SSHByteStreamTransport: Sendable {
    func send(_ bytes: [UInt8], endOfStream: Bool) async throws
    func receive(atLeast minimum: Int, atMost maximum: Int) async throws -> SSHByteStreamChunk
    func setObservationHandler(
        _ handler: (@Sendable (SSHTransportObservationEvent) -> Void)?
    ) async
    func close() async
    func abort() async
}

package protocol SSHCancellationControllingByteStreamTransport: SSHByteStreamTransport {
    func send(_ bytes: [UInt8], endOfStream: Bool, respectCancellation: Bool) async throws
    func receive(
        atLeast minimum: Int,
        atMost maximum: Int,
        respectCancellation: Bool
    ) async throws -> SSHByteStreamChunk
}

package extension SSHByteStreamTransport {
    func setObservationHandler(
        _ handler: (@Sendable (SSHTransportObservationEvent) -> Void)?
    ) async {
    }

    func close() async {
    }

    func abort() async {
        await self.close()
    }
}
