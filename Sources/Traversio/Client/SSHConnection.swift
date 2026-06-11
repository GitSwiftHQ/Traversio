// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// An authenticated SSH connection.
///
/// Use `SSHClient.connect(configuration:)` when the connection should stay open
/// across several operations. Use `SSHClient.withConnection(configuration:_:)`
/// when the connection should be closed automatically after one scoped task.
///
/// Example:
///
/// ```swift
/// let connection = try await SSHClient.connect(configuration: configuration)
/// defer {
///     Task { await connection.close() }
/// }
///
/// let result = try await connection.execute("uname -a")
/// let output = String(decoding: result.standardOutput, as: UTF8.self)
/// ```
public struct SSHConnection: Sendable {
    /// Redacted event metadata.
    public let metadata: SSHConnectionMetadata

    /// State Events.
    public let stateEvents: SSHConnectionStateEventSequence

    private let client: SSHTransportProtocolClient
    private let lifetime: SSHConnectionLifetime
    private let stateCoordinator: SSHConnectionStateCoordinator?
    private let logHandler: SSHClientLogHandler
    private let transportBackendPreference: SSHTCPTransportBackendPreference

    init(
        metadata: SSHConnectionMetadata,
        client: SSHTransportProtocolClient,
        lifetime: SSHConnectionLifetime,
        stateCoordinator: SSHConnectionStateCoordinator? = nil,
        stateEvents: SSHConnectionStateEventSequence = .finished,
        logHandler: SSHClientLogHandler,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic
    ) {
        self.metadata = metadata
        self.stateEvents = stateEvents
        self.client = client
        self.lifetime = lifetime
        self.stateCoordinator = stateCoordinator
        self.logHandler = logHandler
        self.transportBackendPreference = transportBackendPreference
    }

    /// Opens a session channel, runs a command, and collects stdout, stderr,
    /// exit status, and exit signal until the remote side closes the channel.
    ///
    /// Use `openExec(_:environment:)` instead when the command needs streamed
    /// input or output.
    ///
    /// Example:
    ///
    /// ```swift
    /// let result = try await connection.execute("df -h /")
    /// guard result.exitStatus == 0 else { throw MyCommandError.failed }
    /// ```
    public func execute(
        _ command: String,
        environment: [SSHSessionEnvironmentVariable] = []
    ) async throws -> SSHExecResult {
        let handle = try await self.openSessionHandle {
            try await self.client.openExecSession(
                command: command,
                environment: environment
            )
        }
        let session = self.makeSession(handle)
        let transcript = try await session.withMappedOperationFailure(scope: .session) {
            try await handle.collectOutputUntilClose()
        }
        return SSHExecResult(SSHSessionExecResult(transcript: transcript))
    }

    /// Opens an exec session without collecting output.
    ///
    /// The returned session exposes event and chunk readers. Choose exactly one
    /// output-reading style per session: `events`, `nextEvent()`,
    /// `readStandardOutputChunk()`, or `collectOutputUntilClose()`.
    ///
    /// Example:
    ///
    /// ```swift
    /// let session = try await connection.openExec("cat")
    /// try await session.write("hello\n")
    /// try await session.sendEOF()
    /// let output = try await session.collectOutputUntilClose()
    /// ```
    public func openExec(
        _ command: String,
        environment: [SSHSessionEnvironmentVariable] = []
    ) async throws -> SSHSession {
        let handle = try await self.openSessionHandle {
            try await self.client.openExecSession(
                command: command,
                environment: environment
            )
        }
        return self.makeSession(handle)
    }

    /// Closes the connection and all child channels owned by it.
    ///
    /// Calling `close()` more than once is allowed. After close, public
    /// operations fail with `SSHClientError.connectionScopeEnded`.
    public func close() async {
        await self.stateCoordinator?.recordExplicitClose()
        await self.lifetime.close()
    }

    /// Latency.
    public var latency: SSHConnectionLatency? {
        get async {
            await self.client.currentLatency()
        }
    }

    /// Latest Network.framework path snapshot reported by the active transport.
    ///
    /// This is an observation snapshot, not a separate network probe. A `nil`
    /// value means the selected backend has not reported path details yet.
    public var networkPath: SSHConnectionNetworkPath? {
        get async {
            await self.currentState().networkPath
        }
    }

    func abort() async {
        await self.lifetime.abort()
    }

    func hasInstalledBackgroundFailureHandler() async -> Bool {
        await self.client.hasBackgroundFailureHandler()
    }

    func lifecycleRetainProbe() -> SSHConnectionLifecycleRetainProbe {
        SSHConnectionLifecycleRetainProbe(
            client: self.client,
            lifetime: self.lifetime,
            stateCoordinator: self.stateCoordinator
        )
    }

    /// Returns the latest connection state snapshot.
    public func currentState() async -> SSHConnectionStateSnapshot {
        if let stateCoordinator {
            return await stateCoordinator.currentSnapshot()
        }

        return SSHConnectionStateSnapshot(state: .ready)
    }

    func makeJumpTransportHandle(
        to endpoint: SSHSocketEndpoint
    ) async throws -> SSHClientTransportHandle {
        let channel = try await self.client.openDirectTCPIPChannel(
            target: endpoint,
            originator: SSHSocketEndpoint(host: "127.0.0.1", port: 0),
            outputBufferingMode: .standardOutputChunks
        )
        return SSHClientTransportHandle(
            transport: SSHTCPIPChannelByteStreamTransport(handle: channel)
        )
    }

    /// Opens an interactive shell session with an optional pseudo-terminal.
    ///
    /// Example:
    ///
    /// ```swift
    /// let shell = try await connection.openShell()
    /// try await shell.write("whoami\n")
    /// for try await event in shell.events {
    ///     // Render stdout, stderr, EOF, and exit events in the terminal UI.
    /// }
    /// ```
    public func openShell(
        pseudoTerminalRequest: SSHPseudoTerminalRequest = .default,
        environment: [SSHSessionEnvironmentVariable] = []
    ) async throws -> SSHSession {
        let handle = try await self.openSessionHandle {
            try await self.client.openShellSession(
                pseudoTerminalRequest: pseudoTerminalRequest,
                environment: environment
            )
        }
        return self.makeSession(handle)
    }

    /// Opens a named SSH subsystem, such as `"sftp"`.
    ///
    /// Prefer `openSFTP(clientVersion:)` for SFTP because it performs the SFTP
    /// version exchange and returns the typed `SFTPClient` facade.
    public func openSubsystem(
        _ subsystem: String,
        environment: [SSHSessionEnvironmentVariable] = []
    ) async throws -> SSHSession {
        let handle = try await self.openSessionHandle {
            try await self.client.openSubsystemSession(
                subsystem: subsystem,
                environment: environment
            )
        }
        return self.makeSession(handle)
    }

    /// Opens an SFTP v3 client over a session channel.
    ///
    /// Example:
    ///
    /// ```swift
    /// let sftp = try await connection.openSFTP()
    /// let entries = try await sftp.listDirectory(".")
    /// ```
    public func openSFTP(clientVersion: UInt32 = 3) async throws -> SFTPClient {
        let session = try await self.openSFTPSubsystemSessionHandle()
        let client = SSHSFTPClient(
            session: session,
            responseTimeoutNanoseconds: self.client.responseTimeoutNanoseconds
        )
        let sftpClient = self.makeSFTPClient(client: client, session: session)
        _ = try await sftpClient.withMappedOperationFailure(scope: .sftp) {
            try await client.initialize(clientVersion: clientVersion)
        }
        return sftpClient
    }

    /// Opens a raw `direct-tcpip` channel through the SSH server.
    ///
    /// This is the low-level building block behind local forwarding. Use it
    /// when application code wants to speak a protocol itself over the channel.
    public func openDirectTCPIPChannel(
        targetHost: String,
        targetPort: UInt16,
        originatorAddress: String = "127.0.0.1",
        originatorPort: UInt16 = 0
    ) async throws -> SSHDirectTCPIPChannel {
        let handle = try await self.openDirectTCPIPChannelHandle(
            target: SSHSocketEndpoint(host: targetHost, port: targetPort),
            originator: SSHSocketEndpoint(
                host: originatorAddress,
                port: originatorPort
            )
        )
        return self.makeDirectTCPIPChannel(handle)
    }

    /// Opens an OpenSSH `direct-streamlocal@openssh.com` channel.
    ///
    /// The server must support the OpenSSH streamlocal extension.
    public func openDirectStreamLocalChannel(
        socketPath: String,
        originatorAddress: String = "127.0.0.1",
        originatorPort: UInt16 = 0
    ) async throws -> SSHDirectStreamLocalChannel {
        let handle = try await self.openDirectStreamLocalChannelHandle(
            socketPath: socketPath,
            originatorAddress: originatorAddress,
            originatorPort: originatorPort
        )
        return self.makeDirectStreamLocalChannel(handle)
    }

    /// Runs a local TCP listener that forwards accepted connections through the
    /// SSH server to `targetHost:targetPort`.
    ///
    /// The listener exists only for the duration of `body`; leaving the body
    /// closes the listener and waits for Traversio-owned bridge cleanup.
    ///
    /// Example:
    ///
    /// ```swift
    /// try await connection.withLocalPortForwarding(
    ///     targetHost: "127.0.0.1",
    ///     targetPort: 5432,
    ///     localPort: 15432
    /// ) { forward in
    ///     print("Listening on \(forward.localHost):\(forward.localPort)")
    ///     try await Task.never()
    /// }
    /// ```
    public func withLocalPortForwarding<Result>(
        targetHost: String,
        targetPort: UInt16,
        localHost: String = "127.0.0.1",
        localPort: UInt16 = 0,
        _ body: (SSHLocalPortForward) async throws -> Result
    ) async throws -> Result {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .localPortForward) {
            try await SSHLocalPortForwardService(
                client: self.client,
                lifetime: self.lifetime,
                requestedForward: SSHLocalPortForward(
                    localHost: localHost,
                    localPort: localPort,
                    targetHost: targetHost,
                    targetPort: targetPort
                ),
                transportBackendPreference: self.transportBackendPreference
            ).withListener(body)
        }
    }
    /// Requests a remote TCP listener and exposes each accepted forwarded
    /// connection to the body.
    ///
    /// Use this lower-level API when the app wants to inspect or handle each
    /// forwarded channel itself. Use `withRemotePortForwarding(...)` when
    /// Traversio should bridge remote connections to a local TCP endpoint.
    public func withRemotePortForwardListener<Result>(
        remoteHost: String = "127.0.0.1",
        remotePort: UInt16 = 0,
        _ body: (SSHRemotePortForwardListener) async throws -> Result
    ) async throws -> Result {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .remotePortForwardListener) {
            try await SSHRemotePortForwardListenerService(
                client: self.client,
                requestedForward: SSHTCPIPForwardingRequest(
                    addressToBind: remoteHost,
                    portToBind: remotePort
                ),
                lifetime: self.lifetime,
                metadata: self.metadata,
                logHandler: self.logHandler
            ).withListener(body)
        }
    }
    /// Requests an OpenSSH remote streamlocal listener and exposes accepted
    /// forwarded Unix-domain-socket channels to the body.
    public func withRemoteStreamLocalForwardListener<Result>(
        socketPath: String,
        _ body: (SSHRemoteStreamLocalForwardListener) async throws -> Result
    ) async throws -> Result {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .remoteStreamLocalForwardListener) {
            try await SSHRemoteStreamLocalForwardListenerService(
                client: self.client,
                requestedForward: SSHStreamLocalForwardingRequest(socketPath: socketPath),
                lifetime: self.lifetime,
                metadata: self.metadata,
                logHandler: self.logHandler
            ).withListener(body)
        }
    }
    /// Requests a remote TCP listener and bridges each accepted connection to a
    /// local TCP endpoint.
    ///
    /// The remote listener and local bridges exist only for the duration of
    /// `body`.
    public func withRemotePortForwarding<Result>(
        localPort: UInt16,
        remoteHost: String = "127.0.0.1",
        remotePort: UInt16 = 0,
        localHost: String = "127.0.0.1",
        _ body: (SSHRemotePortForward) async throws -> Result
    ) async throws -> Result {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .remotePortForward) {
            try await SSHRemotePortForwardService(
                client: self.client,
                requestedForward: SSHRemotePortForward(
                    localHost: localHost,
                    localPort: localPort,
                    remoteHost: remoteHost,
                    remotePort: remotePort
                ),
                lifetime: self.lifetime,
                metadata: self.metadata,
                logHandler: self.logHandler,
                transportBackendPreference: self.transportBackendPreference
            ).withForward(body)
        }
    }
    /// Runs a local SOCKS5 listener that opens SSH `direct-tcpip` channels for
    /// client-requested destinations.
    ///
    /// The listener exists only for the duration of `body`.
    public func withDynamicPortForwarding<Result>(
        localHost: String = "127.0.0.1",
        localPort: UInt16 = 0,
        socks5Authentication: SSHSOCKS5ProxyAuthentication = .none,
        _ body: (SSHDynamicPortForward) async throws -> Result
    ) async throws -> Result {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .localPortForward) {
            try await SSHDynamicPortForwardService(
                client: self.client,
                lifetime: self.lifetime,
                requestedForward: SSHDynamicPortForward(
                    localHost: localHost,
                    localPort: localPort
                ),
                socks5Authentication: socks5Authentication,
                transportBackendPreference: self.transportBackendPreference
            ).withListener(body)
        }
    }

    private func openSessionHandle(
        _ openOperation: @escaping @Sendable () async throws -> SSHSessionHandle
    ) async throws -> SSHSessionHandle {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .session) {
            try await openOperation()
        }
    }

    private func openSFTPSubsystemSessionHandle() async throws -> SSHSessionHandle {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .sftp) {
            try await self.client.openSFTPSubsystemSession()
        }
    }

    private func openDirectTCPIPChannelHandle(
        target: SSHSocketEndpoint,
        originator: SSHSocketEndpoint
    ) async throws -> SSHTCPIPChannelHandle {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .directTCPIPChannel) {
            try await self.client.openDirectTCPIPChannel(
                target: target,
                originator: originator
            )
        }
    }

    private func openDirectStreamLocalChannelHandle(
        socketPath: String,
        originatorAddress: String,
        originatorPort: UInt16
    ) async throws -> SSHTCPIPChannelHandle {
        try await self.lifetime.requireActive()
        return try await self.withMappedOperationFailure(scope: .directStreamLocalChannel) {
            try await self.client.openDirectStreamLocalChannel(
                socketPath: socketPath,
                originatorAddress: originatorAddress,
                originatorPort: originatorPort
            )
        }
    }

    private func makeSession(_ handle: SSHSessionHandle) -> SSHSession {
        SSHSession(
            handle: handle,
            lifetime: self.lifetime,
            metadata: self.metadata,
            logHandler: self.logHandler
        )
    }

    private func makeSFTPClient(
        client: SSHSFTPClient,
        session: SSHSessionHandle
    ) -> SFTPClient {
        SFTPClient(
            client: client,
            lifetime: self.lifetime,
            metadata: self.metadata,
            localChannelID: session.channel.localChannelID,
            remoteChannelID: session.channel.remoteChannelID,
            logHandler: self.logHandler
        )
    }

    private func makeDirectTCPIPChannel(
        _ handle: SSHTCPIPChannelHandle
    ) -> SSHDirectTCPIPChannel {
        SSHDirectTCPIPChannel(
            handle: handle,
            lifetime: self.lifetime,
            metadata: self.metadata,
            logHandler: self.logHandler
        )
    }

    private func makeDirectStreamLocalChannel(
        _ handle: SSHTCPIPChannelHandle
    ) -> SSHDirectStreamLocalChannel {
        SSHDirectStreamLocalChannel(
            handle: handle,
            lifetime: self.lifetime,
            metadata: self.metadata,
            logHandler: self.logHandler
        )
    }
}

final class SSHConnectionLifecycleRetainProbe {
    weak var client: SSHTransportProtocolClient?
    weak var lifetime: SSHConnectionLifetime?
    weak var stateCoordinator: SSHConnectionStateCoordinator?

    init(
        client: SSHTransportProtocolClient,
        lifetime: SSHConnectionLifetime,
        stateCoordinator: SSHConnectionStateCoordinator?
    ) {
        self.client = client
        self.lifetime = lifetime
        self.stateCoordinator = stateCoordinator
    }
}

extension SSHConnection: SSHOperationFailureMappingContext {
    var operationFailureMetadata: SSHConnectionMetadata { self.metadata }
    var operationFailureLogHandler: SSHClientLogHandler { self.logHandler }
    var operationFailureLocalChannelID: UInt32? { nil }
    var operationFailureRemoteChannelID: UInt32? { nil }

    func operationFailureSnapshot() async -> SSHTransportProtocolDiagnosticsSnapshot {
        await self.client.diagnosticsSnapshot()
    }
}
