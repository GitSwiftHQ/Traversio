// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

/// A raw SSH `direct-tcpip` channel.
///
/// Use this for protocols that the app wants to speak directly through an SSH
/// tunnel. For listener-style forwarding, prefer
/// `SSHConnection.withLocalPortForwarding(...)`.
public struct SSHDirectTCPIPChannel: Sendable {
    private let handle: SSHTCPIPChannelHandle
    private let lifetime: SSHConnectionLifetime
    private let metadata: SSHConnectionMetadata
    private let logHandler: SSHClientLogHandler

    init(
        handle: SSHTCPIPChannelHandle,
        lifetime: SSHConnectionLifetime,
        metadata: SSHConnectionMetadata,
        logHandler: SSHClientLogHandler
    ) {
        self.handle = handle
        self.lifetime = lifetime
        self.metadata = metadata
        self.logHandler = logHandler
    }

    /// Writes bytes to the channel.
    public func write(_ bytes: [UInt8]) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .directTCPIPChannel) {
            try await self.handle.write(bytes)
        }
    }

    /// Writes UTF-8 text to the channel.
    public func write(_ string: String) async throws {
        try await self.write(Array(string.utf8))
    }

    /// Sends channel EOF.
    public func sendEOF() async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .directTCPIPChannel) {
            try await self.handle.sendEOF()
        }
    }

    /// Closes this channel.
    public func close() async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .directTCPIPChannel) {
            try await self.handle.close()
        }
    }

    /// Reads the next data chunk, or `nil` after EOF or close.
    public func readChunk() async throws -> [UInt8]? {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .directTCPIPChannel) {
            try await self.handle.readChunk()
        }
    }

    /// Returns current receive and send window counters.
    public func channelWindowSnapshot() async throws -> SSHChannelWindowSnapshot {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .directTCPIPChannel) {
            try await self.handle.channelWindowSnapshot()
        }
    }

    /// Manually increases the local receive window.
    public func adjustReceiveWindow(by byteCount: UInt32) async throws -> SSHChannelWindowSnapshot {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .directTCPIPChannel) {
            try await self.handle.adjustReceiveWindow(by: byteCount)
        }
    }

    /// Reads the next structured channel event.
    public func nextEvent() async throws -> SSHTCPIPChannelEvent? {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .directTCPIPChannel) {
            try await self.handle.readEvent()
        }
    }

    /// Events.
    public var events: SSHTCPIPChannelEventSequence {
        SSHTCPIPChannelEventSequence(
            nextEventReader: { try await self.nextEvent() },
            cancelHandler: { await self.bestEffortCloseOnCancellation() }
        )
    }

    func bestEffortCloseOnCancellation() async {
        await self.handle.bestEffortCloseIgnoringCancellation()
    }

    /// Collects channel data until close.
    public func collectDataUntilClose() async throws -> SSHDirectTCPIPChannelOutput {
        try await self.lifetime.requireActive()
        let transcript = try await self.withMappedOperationFailure(scope: .directTCPIPChannel) {
            try await self.handle.collectDataUntilClose()
        }
        return SSHDirectTCPIPChannelOutput(transcript: transcript)
    }
}

extension SSHDirectTCPIPChannel: SSHOperationFailureMappingContext {
    var operationFailureMetadata: SSHConnectionMetadata { self.metadata }
    var operationFailureLogHandler: SSHClientLogHandler { self.logHandler }
    var operationFailureLocalChannelID: UInt32? { self.handle.channel.localChannelID }
    var operationFailureRemoteChannelID: UInt32? { self.handle.channel.remoteChannelID }

    func operationFailureSnapshot() async -> SSHTransportProtocolDiagnosticsSnapshot {
        await self.handle.diagnosticsSnapshot()
    }
}
