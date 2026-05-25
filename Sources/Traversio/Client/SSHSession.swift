// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

/// A session channel opened for exec, shell, or subsystem traffic.
///
/// `SSHSession` supports several reading styles. Choose one reading style per
/// session so stdout, stderr, and terminal events are not consumed by competing
/// readers.
///
/// Example:
///
/// ```swift
/// let session = try await connection.openShell()
/// try await session.write("ls -la\n")
/// for try await event in session.events {
///     // Update terminal state from stdout, stderr, EOF, and exit events.
/// }
/// ```
public struct SSHSession: Sendable {
    private let handle: SSHSessionHandle
    private let lifetime: SSHConnectionLifetime
    private let metadata: SSHConnectionMetadata
    private let logHandler: SSHClientLogHandler

    init(
        handle: SSHSessionHandle,
        lifetime: SSHConnectionLifetime,
        metadata: SSHConnectionMetadata,
        logHandler: SSHClientLogHandler
    ) {
        self.handle = handle
        self.lifetime = lifetime
        self.metadata = metadata
        self.logHandler = logHandler
    }

    /// Writes bytes to the session's standard input stream.
    public func write(_ bytes: [UInt8]) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .session) {
            try await self.handle.write(bytes)
        }
    }

    /// Writes UTF-8 text to the session's standard input stream.
    public func write(_ string: String) async throws {
        try await self.write(Array(string.utf8))
    }

    /// Writes bytes to the session's standard-error stream when the remote
    /// channel accepts extended data from the client.
    ///
    /// Most interactive client code should use `write(_:)` instead.
    public func writeStandardError(_ bytes: [UInt8]) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .session) {
            try await self.handle.writeStandardError(bytes)
        }
    }

    /// Writes UTF-8 text to the session's standard-error stream.
    public func writeStandardError(_ string: String) async throws {
        try await self.writeStandardError(Array(string.utf8))
    }

    /// Sends channel EOF to tell the remote process no more stdin bytes will be
    /// written.
    public func sendEOF() async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .session) {
            try await self.handle.sendEOF()
        }
    }

    /// Sends a channel close request for this session.
    ///
    /// Closing the session does not close the parent `SSHConnection`.
    public func close() async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(scope: .session) {
            try await self.handle.close()
        }
    }

    /// Sends an RFC 4254 signal request, such as `.interrupt`, to the remote
    /// process.
    public func sendSignal(_ signal: SSHSessionSignal) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(
            scope: .session,
            requestType: "signal"
        ) {
            try await self.handle.sendSignal(signal)
        }
    }

    /// Sends a PTY `window-change` request for an interactive shell.
    public func resizePseudoTerminal(
        characterWidth: UInt32,
        characterHeight: UInt32,
        pixelWidth: UInt32 = 0,
        pixelHeight: UInt32 = 0
    ) async throws {
        try await self.lifetime.requireActive()
        try await self.withMappedOperationFailure(
            scope: .session,
            requestType: "window-change"
        ) {
            try await self.handle.resizePseudoTerminal(
                characterWidth: characterWidth,
                characterHeight: characterHeight,
                pixelWidth: pixelWidth,
                pixelHeight: pixelHeight
            )
        }
    }

    /// Returns current receive and send window counters for this channel.
    ///
    /// This is mainly useful for diagnostics and advanced flow-control tuning.
    public func channelWindowSnapshot() async throws -> SSHChannelWindowSnapshot {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .session) {
            try await self.handle.channelWindowSnapshot()
        }
    }

    /// Manually increases the local receive window.
    ///
    /// Normal sessions replenish receive windows automatically. Call this only
    /// when building a custom reader that deliberately withholds window credit.
    public func adjustReceiveWindow(by byteCount: UInt32) async throws -> SSHChannelWindowSnapshot {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .session) {
            try await self.handle.adjustReceiveWindow(by: byteCount)
        }
    }

    /// Reads the next structured session event.
    ///
    /// Returns `nil` after the session reaches a terminal close state.
    public func nextEvent() async throws -> SSHSessionEvent? {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .session) {
            try await self.handle.readEvent()
        }
    }

    /// Events.
    public var events: SSHSessionEventSequence {
        SSHSessionEventSequence(session: self)
    }

    func bestEffortCloseOnCancellation() async {
        await self.handle.bestEffortCloseIgnoringCancellation()
    }

    /// Reads the next stdout chunk from a session opened in stdout-chunk mode.
    ///
    /// Returns `nil` after stdout reaches EOF or the channel closes.
    public func readStandardOutputChunk() async throws -> [UInt8]? {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .session) {
            try await self.handle.readStandardOutputChunk()
        }
    }

    /// Collects stdout, stderr, EOF, exit status, and exit signal until the
    /// channel closes.
    ///
    /// Use this for bounded command output. Use `events` or
    /// `readStandardOutputChunk()` for long-running or unbounded streams.
    public func collectOutputUntilClose() async throws -> SSHSessionOutput {
        try await self.lifetime.requireActive()
        let transcript = try await self.withMappedOperationFailure(scope: .session) {
            try await self.handle.collectOutputUntilClose()
        }
        return SSHSessionOutput(transcript: transcript)
    }
}

extension SSHSession: SSHOperationFailureMappingContext {
    var operationFailureMetadata: SSHConnectionMetadata { self.metadata }
    var operationFailureLogHandler: SSHClientLogHandler { self.logHandler }
    var operationFailureLocalChannelID: UInt32? { self.handle.channel.localChannelID }
    var operationFailureRemoteChannelID: UInt32? { self.handle.channel.remoteChannelID }

    func operationFailureSnapshot() async -> SSHTransportProtocolDiagnosticsSnapshot {
        await self.handle.diagnosticsSnapshot()
    }
}
