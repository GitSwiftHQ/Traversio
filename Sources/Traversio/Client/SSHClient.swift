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

    fileprivate func makeJumpTransportHandle(
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

/// Entry points for connecting to SSH servers and running scoped SSH work.
///
/// Example:
///
/// ```swift
/// let configuration = SSHClientConfiguration(
///     host: "server.example.com",
///     username: "deploy",
///     authentication: .password("secret"),
///     hostKeyPolicy: .knownHostsFile("/Users/me/.ssh/known_hosts")
/// )
///
/// let result = try await SSHClient.withConnection(configuration: configuration) {
///     try await $0.execute("uptime")
/// }
/// ```
public enum SSHClient {
    private static let defaultGracefulCloseTimeoutNanoseconds: UInt64 = 1_000_000_000

    private actor TaskCompletionGate {
        private var continuation: CheckedContinuation<Bool, Never>?

        init(_ continuation: CheckedContinuation<Bool, Never>) {
            self.continuation = continuation
        }

        func resume(with value: Bool) {
            guard let continuation else {
                return
            }

            self.continuation = nil
            continuation.resume(returning: value)
        }
    }

    private actor ConnectionSetupCleanup {
        private enum State {
            case waitingForTransport
            case acquiredTransport(SSHClientTransportHandle, connectionSetupStarted: Bool)
            case closed
            case released
        }

        private var state: State = .waitingForTransport

        func register(_ transportHandle: SSHClientTransportHandle) -> Bool {
            guard case .waitingForTransport = self.state else {
                return false
            }

            self.state = .acquiredTransport(
                transportHandle,
                connectionSetupStarted: false
            )
            return true
        }

        func beginConnectionSetup() -> Bool {
            guard case let .acquiredTransport(transportHandle, _) = self.state else {
                return false
            }

            self.state = .acquiredTransport(
                transportHandle,
                connectionSetupStarted: true
            )
            return true
        }

        func claimSetupTimeoutClose() -> SSHClientTransportHandle? {
            guard case let .acquiredTransport(transportHandle, _) = self.state else {
                return nil
            }

            self.state = .closed
            return transportHandle
        }

        func claimClose() -> SSHClientTransportHandle? {
            guard case let .acquiredTransport(transportHandle, _) = self.state else {
                return nil
            }

            self.state = .closed
            return transportHandle
        }

        func release() {
            self.state = .released
        }
    }

    /// Connects, verifies the host key, authenticates, and returns an open
    /// connection.
    ///
    /// The caller owns the returned connection and must eventually call
    /// `SSHConnection.close()`.
    public static func connect(
        configuration: SSHClientConfiguration
    ) async throws -> SSHConnection {
        return try await self.connect(
            configuration: configuration,
            logHandler: .disabled
        )
    }

    /// Connects with a caller-provided log handler.
    ///
    /// Use `SSHClientLogRecorder` when the app wants a bounded, redacted support
    /// report after failures.
    public static func connect(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler
    ) async throws -> SSHConnection {
        return try await self.connect(
            configuration: configuration,
            logHandler: logHandler,
            transportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeDefaultTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy
                )
            },
            routeRootTransportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeDefaultRouteRootTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy
                )
            },
            jumpTransportFactory: self.makeJumpTransportHandle
        )
    }

    package static func connect(
        configuration: SSHClientConfiguration,
        transportBackendPreference: SSHTCPTransportBackendPreference
    ) async throws -> SSHConnection {
        return try await self.connect(
            configuration: configuration,
            logHandler: .disabled,
            transportBackendPreference: transportBackendPreference
        )
    }

    package static func connect(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportBackendPreference: SSHTCPTransportBackendPreference
    ) async throws -> SSHConnection {
        return try await self.connect(
            configuration: configuration,
            logHandler: logHandler,
            transportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeDefaultTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy,
                    preference: transportBackendPreference
                )
            },
            routeRootTransportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeDefaultRouteRootTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy,
                    preference: transportBackendPreference
                )
            },
            jumpTransportFactory: self.makeJumpTransportHandle,
            connectionTransportBackendPreference: transportBackendPreference
        )
    }

    /// Connects, runs `body`, and closes the connection when `body` returns or
    /// throws.
    ///
    /// This is the safest entry point for one-off operations.
    public static func withConnection<Result>(
        configuration: SSHClientConfiguration,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        try await self.withConnection(
            configuration: configuration,
            logHandler: .disabled,
            body
        )
    }

    /// Connects with logging, runs `body`, and closes the connection when
    /// `body` returns or throws.
    public static func withConnection<Result>(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        let connection = try await self.connect(
            configuration: configuration,
            logHandler: logHandler
        )

        do {
            let result = try await body(connection)
            await connection.close()
            return result
        } catch {
            await connection.close()
            throw error
        }
    }

    package static func withConnection<Result>(
        configuration: SSHClientConfiguration,
        transportBackendPreference: SSHTCPTransportBackendPreference,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        try await self.withConnection(
            configuration: configuration,
            logHandler: .disabled,
            transportBackendPreference: transportBackendPreference,
            body
        )
    }

    package static func withConnection<Result>(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportBackendPreference: SSHTCPTransportBackendPreference,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        let connection = try await self.connect(
            configuration: configuration,
            logHandler: logHandler,
            transportBackendPreference: transportBackendPreference
        )

        do {
            let result = try await body(connection)
            await connection.close()
            return result
        } catch {
            await connection.close()
            throw error
        }
    }

    static func connect(
        configuration: SSHClientConfiguration,
        transportFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> any SSHByteStreamTransport
    ) async throws -> SSHConnection {
        try await self.connect(
            configuration: configuration,
            logHandler: .disabled,
            transportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy,
                    transportFactory: transportFactory
                )
            }
        )
    }

    static func connect(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> any SSHByteStreamTransport
    ) async throws -> SSHConnection {
        try await self.connect(
            configuration: configuration,
            logHandler: logHandler,
            transportFactory: transportFactory,
            jumpTransportFactory: self.makeJumpTransportHandle,
            connectionTransportBackendPreference: .automatic
        )
    }

    static func connect(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> any SSHByteStreamTransport,
        jumpTransportFactory: @escaping @Sendable (
            _ upstreamConnection: SSHConnection,
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle
        ,
        connectionTransportBackendPreference: SSHTCPTransportBackendPreference = .automatic
    ) async throws -> SSHConnection {
        try await self.connect(
            configuration: configuration,
            logHandler: logHandler,
            transportHandleFactory: { endpoint in
                try await SSHConnectionProxyTransport.makeTransportHandle(
                    to: endpoint,
                    proxy: configuration.connectionProxy,
                    transportFactory: transportFactory
                )
            },
            jumpTransportFactory: jumpTransportFactory,
            connectionTransportBackendPreference: connectionTransportBackendPreference
        )
    }

    static func connect(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportHandleFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle,
        routeRootTransportHandleFactory: (@Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle)? = nil,
        jumpTransportFactory: @escaping @Sendable (
            _ upstreamConnection: SSHConnection,
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle
        ,
        connectionTransportBackendPreference: SSHTCPTransportBackendPreference = .automatic
    ) async throws -> SSHConnection {
        if configuration.proxyJumpHosts.isEmpty {
            let endpoint = SSHSocketEndpoint(host: configuration.host, port: configuration.port)
            logHandler.logConnectionStarted(
                endpoint: endpoint,
                username: configuration.username,
                authentication: configuration.authentication
            )

            return try await self.makeConnectionWithRouteSetupTimeout(
                configuration: configuration,
                endpoint: endpoint,
                transportHandleFactory: {
                    try await transportHandleFactory(endpoint)
                },
                transportBackendPreference: connectionTransportBackendPreference,
                logHandler: logHandler
            )
        }

        return try await self.connectViaProxyJump(
            configuration: configuration,
            logHandler: logHandler,
            transportHandleFactory: transportHandleFactory,
            routeRootTransportHandleFactory: routeRootTransportHandleFactory,
            jumpTransportFactory: jumpTransportFactory,
            connectionTransportBackendPreference: connectionTransportBackendPreference
        )
    }

    static func connect(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportHandleFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle
    ) async throws -> SSHConnection {
        try await self.connect(
            configuration: configuration,
            logHandler: logHandler,
            transportHandleFactory: transportHandleFactory,
            jumpTransportFactory: self.makeJumpTransportHandle
        )
    }

    static func makeJumpTransportHandle(
        upstreamConnection: SSHConnection,
        endpoint: SSHSocketEndpoint
    ) async throws -> SSHClientTransportHandle {
        try await upstreamConnection.makeJumpTransportHandle(to: endpoint)
    }

    static func withConnection<Result>(
        configuration: SSHClientConfiguration,
        transportRunner: (
            _ endpoint: SSHSocketEndpoint,
            _ handler: @escaping (any SSHByteStreamTransport) async throws -> Result
        ) async throws -> Result,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        try await self.withConnection(
            configuration: configuration,
            logHandler: .disabled,
            transportRunner: transportRunner,
            body
        )
    }

    static func withConnection<Result>(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportRunner: (
            _ endpoint: SSHSocketEndpoint,
            _ handler: @escaping (any SSHByteStreamTransport) async throws -> Result
        ) async throws -> Result,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        let endpoint = SSHSocketEndpoint(host: configuration.host, port: configuration.port)

        return try await transportRunner(endpoint) { transport in
            let connection = try await self.makeConnection(
                configuration: configuration,
                endpoint: endpoint,
                transportHandle: SSHClientTransportHandle(transport: transport),
                transportBackendPreference: .automatic,
                logHandler: logHandler
            )

            do {
                let result = try await body(connection)
                await connection.close()
                return result
            } catch {
                await connection.close()
                throw error
            }
        }
    }

    private static func makeConnectionWithRouteSetupTimeout(
        configuration: SSHClientConfiguration,
        endpoint: SSHSocketEndpoint,
        transportHandleFactory: @escaping @Sendable () async throws -> SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)? = nil,
        failedSetupDependentCloseOperation: (@Sendable () async -> Void)? = nil,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic,
        logHandler: SSHClientLogHandler
    ) async throws -> SSHConnection {
        let timeoutPolicy = SSHInternalTimeoutPolicy(configuration.timeoutPolicy)
        let connectionSetupBudget = SSHConnectionSetupTimeoutBudget(
            timeoutNanoseconds: timeoutPolicy.connectionSetupTimeoutNanoseconds
        )
        let setupCleanup = ConnectionSetupCleanup()
        do {
            let transportHandle = try await connectionSetupBudget.withTimeout {
                try await transportHandleFactory()
            }
            guard await setupCleanup.register(transportHandle) else {
                await transportHandle.abort()
                throw CancellationError()
            }
            guard await setupCleanup.beginConnectionSetup() else {
                await transportHandle.abort()
                throw CancellationError()
            }

            return try await self.makeConnection(
                configuration: configuration,
                endpoint: endpoint,
                transportHandle: transportHandle,
                dependentCloseOperation: dependentCloseOperation,
                failedSetupDependentCloseOperation: failedSetupDependentCloseOperation,
                transportBackendPreference: transportBackendPreference,
                logHandler: logHandler,
                setupCleanup: setupCleanup,
                connectionSetupBudget: connectionSetupBudget
            )
        } catch let error as SSHClientError {
            throw error
        } catch let error as CancellationError {
            throw error
        } catch {
            throw self.wrapEarlyConnectionSetupError(
                error,
                username: configuration.username,
                endpoint: endpoint,
                logHandler: logHandler
            )
        }
    }

    private static func withConnectionSetupTimeout<Result: Sendable>(
        _ connectionSetupBudget: SSHConnectionSetupTimeoutBudget,
        _ operation: @escaping @Sendable () async throws -> Result
    ) async throws -> Result {
        try await connectionSetupBudget.withTimeout(operation)
    }

    private static func makeConnection(
        configuration: SSHClientConfiguration,
        endpoint: SSHSocketEndpoint,
        transportHandle: SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)? = nil,
        failedSetupDependentCloseOperation: (@Sendable () async -> Void)? = nil,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic,
        logHandler: SSHClientLogHandler,
        setupCleanup: ConnectionSetupCleanup? = nil,
        connectionSetupBudget: SSHConnectionSetupTimeoutBudget? = nil
    ) async throws -> SSHConnection {
        let timeoutPolicy = SSHInternalTimeoutPolicy(configuration.timeoutPolicy)
        let connectionSetupBudget =
            connectionSetupBudget
            ?? SSHConnectionSetupTimeoutBudget(
                timeoutNanoseconds: timeoutPolicy.connectionSetupTimeoutNanoseconds
            )
        let transportConfiguration = SSHTransportProtocolClientConfiguration(
            preferredServerHostKeyAlgorithms:
                configuration.legacyAlgorithmOptions.preferredServerHostKeyAlgorithms,
            compressionPreference: configuration.compressionPreference,
            automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy(
                configuration.automaticRekeyPolicy
            ),
            keepalivePolicy: SSHTransportKeepalivePolicy(
                configuration.keepalivePolicy,
                defaultResponseTimeoutNanoseconds: timeoutPolicy.responseTimeoutNanoseconds
            ),
            responseTimeoutNanoseconds: timeoutPolicy.responseTimeoutNanoseconds
        )
        let client = SSHTransportProtocolClient(
            transport: transportHandle.transport,
            transportConfiguration: transportConfiguration
        )
        let transportObservationBuffer = SSHConnectionTransportObservationBuffer()
        await transportHandle.transport.setObservationHandler { event in
            Task {
                await transportObservationBuffer.record(event)
            }
        }
        do {
            let hostKeyTrustPolicy = try configuration.hostKeyPolicy.resolveTrustPolicy(
                for: endpoint
            )
            let versionExchange = try await self.withConnectionSetupTimeout(
                connectionSetupBudget
            ) {
                try await client.exchangeIdentifications()
            }
            let negotiation = try await self.withConnectionSetupTimeout(
                connectionSetupBudget
            ) {
                try await client.exchangeKeyExchangeInit()
            }
            let keyExchangeResult = try await self.withConnectionSetupTimeout(
                connectionSetupBudget
            ) {
                try await client.beginCurve25519KeyExchange(negotiation: negotiation)
            }
            let hostKeyTrustEvaluation = try await client.evaluateCurve25519HostKeyTrust(
                negotiation: negotiation,
                keyExchangeResult: keyExchangeResult,
                remoteEndpoint: endpoint,
                hostKeyTrustPolicy: hostKeyTrustPolicy,
                hostKeyTrustTimeoutNanoseconds: timeoutPolicy.hostKeyTrustTimeoutNanoseconds
            )
            let activation = try await self.withConnectionSetupTimeout(
                connectionSetupBudget
            ) {
                try await client.activateTrustedCurve25519Transport(
                    evaluation: hostKeyTrustEvaluation,
                    remoteEndpoint: endpoint,
                    hostKeyTrustPolicy: hostKeyTrustPolicy
                )
            }

            let authenticationBanners = try await self.withConnectionSetupTimeout(
                connectionSetupBudget
            ) {
                try await self.authenticateAny(
                    configuration.authenticationMethods,
                    username: configuration.username,
                    client: client,
                    endpoint: endpoint,
                    legacyAlgorithmOptions: configuration.legacyAlgorithmOptions,
                    logHandler: logHandler
                )
            }

            let metadata = SSHConnectionMetadata(
                endpointHost: endpoint.host,
                endpointPort: endpoint.port,
                username: configuration.username,
                clientIdentification: versionExchange.clientIdentification.rawValue,
                remoteIdentification: versionExchange.remoteIdentification.rawValue,
                preIdentificationLines: versionExchange.preIdentificationLines,
                authenticationBanners: authenticationBanners,
                hostKeyAlgorithm: activation.verifiedHostKey.algorithmName,
                hostKeyFingerprintSHA256: SSHTrustedHostKey(
                    verifiedHostKey: activation.verifiedHostKey
                ).fingerprintSHA256,
                hostKeyTrustMethod: activation.hostKeyTrust.method
            )
            let lifetime = SSHConnectionLifetime(closeOperation: { [client] in
                await self.closeTransportResources(
                    client: client,
                    transportHandle: transportHandle,
                    dependentCloseOperation: dependentCloseOperation,
                    gracefulCloseTimeoutNanoseconds: self.gracefulCloseTimeoutNanoseconds(
                        responseTimeoutNanoseconds: timeoutPolicy.responseTimeoutNanoseconds
                    )
                )
            }, abortOperation: {
                await self.abortTransportResources(
                    client: client,
                    transportHandle: transportHandle,
                    dependentCloseOperation: dependentCloseOperation
                )
            })
            let stateCoordinator = SSHConnectionStateCoordinator(
                client: client,
                logHandler: logHandler
            )
            await transportObservationBuffer.attach { [weak lifetime, weak stateCoordinator] event in
                guard let stateCoordinator else {
                    return
                }

                let shouldCloseLifetime = await stateCoordinator.recordTransportObservation(event)
                if shouldCloseLifetime {
                    await lifetime?.close()
                }
            }
            await client.setBackgroundFailureHandler { [weak lifetime, weak stateCoordinator] error in
                await stateCoordinator?.recordBackgroundFailure(error)
                await lifetime?.close()
            }
            let connection = SSHConnection(
                metadata: metadata,
                client: client,
                lifetime: lifetime,
                stateCoordinator: stateCoordinator,
                stateEvents: stateCoordinator.stateEvents,
                logHandler: logHandler,
                transportBackendPreference: transportBackendPreference
            )
            logHandler.logConnectionEstablished(metadata)
            await setupCleanup?.release()
            return connection
        } catch let error as SSHClientError {
            await self.closeFailedConnectionSetupResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation,
                setupCleanup: setupCleanup,
                timeoutPolicy: timeoutPolicy
            )
            throw error
        } catch let error as SSHHostKeyPolicyError {
            await self.closeFailedConnectionSetupResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation,
                setupCleanup: setupCleanup,
                timeoutPolicy: timeoutPolicy
            )
            throw error
        } catch let error as SSHAuthenticationMethodError {
            await self.closeFailedConnectionSetupResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation,
                setupCleanup: setupCleanup,
                timeoutPolicy: timeoutPolicy
            )
            throw error
        } catch let error as CancellationError {
            await self.closeFailedConnectionSetupResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation,
                setupCleanup: setupCleanup,
                timeoutPolicy: timeoutPolicy
            )
            throw error
        } catch {
            let snapshot = await client.diagnosticsSnapshot()
            await self.closeFailedConnectionSetupResources(
                client: client,
                transportHandle: transportHandle,
                dependentCloseOperation: failedSetupDependentCloseOperation,
                setupCleanup: setupCleanup,
                timeoutPolicy: timeoutPolicy
            )
            if let failure = self.wrapConnectionFailure(
                error,
                endpoint: endpoint,
                username: configuration.username,
                snapshot: snapshot
            ) {
                logHandler.logConnectionFailure(failure)
                throw SSHClientError.connectionFailed(failure)
            }

            logHandler.logUnwrappedConnectionFailure(
                error,
                endpoint: endpoint
            )
            throw error
        }
    }

    private static func closeFailedConnectionSetupResources(
        client _: SSHTransportProtocolClient,
        transportHandle: SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)? = nil,
        setupCleanup: ConnectionSetupCleanup? = nil,
        timeoutPolicy _: SSHInternalTimeoutPolicy
    ) async {
        if let setupCleanup {
            guard let claimedTransportHandle = await setupCleanup.claimClose() else {
                return
            }
            await claimedTransportHandle.abort()
            await dependentCloseOperation?()
            return
        }

        await transportHandle.abort()
        await dependentCloseOperation?()
    }

    private static func connectViaProxyJump(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportHandleFactory: @escaping @Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle,
        routeRootTransportHandleFactory: (@Sendable (
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle)? = nil,
        jumpTransportFactory: @escaping @Sendable (
            _ upstreamConnection: SSHConnection,
            _ endpoint: SSHSocketEndpoint
        ) async throws -> SSHClientTransportHandle
        ,
        connectionTransportBackendPreference: SSHTCPTransportBackendPreference = .automatic
    ) async throws -> SSHConnection {
        let routePlan = SSHRoutePlan(configuration: configuration)
        let routeGraph = SSHRouteLifecycleGraph(plan: routePlan)
        let finalEndpoint = routePlan.finalEndpoint
        let routeLifecycle = SSHRouteLifecycleOwner(graph: routeGraph)
        let rootTransportHandleFactory =
            routeRootTransportHandleFactory ?? transportHandleFactory
        let proxyJumpConnectionCount = routePlan.connectionCount
        logHandler.logProxyJumpSetupStarted(
            finalEndpoint: finalEndpoint,
            username: configuration.username,
            authentication: configuration.authentication,
            connectionCount: proxyJumpConnectionCount
        )

        do {
            for (hopIndex, hop) in configuration.proxyJumpHosts.enumerated() {
                let hopOrdinal = hopIndex + 1
                guard let hopEdgeID = routeGraph.sshHopEdgeID(ordinal: hopOrdinal) else {
                    preconditionFailure("Missing ProxyJump hop edge \(hopOrdinal)")
                }
                let endpoint = SSHSocketEndpoint(host: hop.host, port: hop.port)
                let hopConfiguration = SSHClientConfiguration(
                    host: hop.host,
                    port: hop.port,
                    username: hop.username,
                    authenticationMethods: hop.authenticationMethods,
                    hostKeyPolicy: hop.hostKeyPolicy,
                    compressionPreference: hop.compressionPreference,
                    legacyAlgorithmOptions: hop.legacyAlgorithmOptions,
                    automaticRekeyPolicy: hop.automaticRekeyPolicy,
                    keepalivePolicy: hop.keepalivePolicy,
                    timeoutPolicy: hop.timeoutPolicy
                )
                logHandler.logProxyJumpHopStarted(
                    endpoint: endpoint,
                    username: hop.username,
                    authentication: hop.authentication,
                    connectionIndex: hopOrdinal,
                    connectionCount: proxyJumpConnectionCount
                )
                if let upstreamConnection = await routeLifecycle.lastConnection() {
                    logHandler.logProxyJumpChannelOpening(
                        upstreamMetadata: upstreamConnection.metadata,
                        targetEndpoint: endpoint,
                        connectionIndex: hopOrdinal,
                        connectionCount: proxyJumpConnectionCount
                    )
                }

                let upstreamConnection = await routeLifecycle.lastConnection()
                await routeLifecycle.beginAcquiringConnection(edgeID: hopEdgeID)
                let connection = try await self.makeConnectionWithRouteSetupTimeout(
                    configuration: hopConfiguration,
                    endpoint: endpoint,
                    transportHandleFactory: {
                        if let upstreamConnection {
                            try await jumpTransportFactory(upstreamConnection, endpoint)
                        } else {
                            try await rootTransportHandleFactory(endpoint)
                        }
                    },
                    transportBackendPreference: connectionTransportBackendPreference,
                    logHandler: logHandler
                )
                await routeLifecycle.registerConnection(connection, edgeID: hopEdgeID)
            }

            if let upstreamConnection = await routeLifecycle.lastConnection() {
                logHandler.logProxyJumpChannelOpening(
                    upstreamMetadata: upstreamConnection.metadata,
                    targetEndpoint: finalEndpoint,
                    connectionIndex: proxyJumpConnectionCount,
                    connectionCount: proxyJumpConnectionCount
                )
            }
            let upstreamConnection = await routeLifecycle.lastConnection()

            logHandler.logProxyJumpTargetStarted(
                endpoint: finalEndpoint,
                username: configuration.username,
                authentication: configuration.authentication,
                connectionIndex: proxyJumpConnectionCount,
                connectionCount: proxyJumpConnectionCount
            )

            await routeLifecycle.beginAcquiringConnection(edgeID: routeGraph.finalSSHEdgeID)
            let finalConnection = try await self.makeConnectionWithRouteSetupTimeout(
                configuration: configuration,
                endpoint: finalEndpoint,
                transportHandleFactory: {
                    if let upstreamConnection {
                        try await jumpTransportFactory(upstreamConnection, finalEndpoint)
                    } else {
                        try await rootTransportHandleFactory(finalEndpoint)
                    }
                },
                dependentCloseOperation: {
                    await routeLifecycle.closeAfterExternalFinalClose()
                },
                failedSetupDependentCloseOperation: {
                    await routeLifecycle.abortAfterExternalFinalClose()
                },
                transportBackendPreference: connectionTransportBackendPreference,
                logHandler: logHandler
            )
            await routeLifecycle.registerFinalConnectionEstablished()
            return finalConnection
        } catch let error as SSHClientError {
            await routeLifecycle.abort()
            throw error
        } catch {
            await routeLifecycle.abort()
            throw self.wrapEarlyConnectionSetupError(
                error,
                username: configuration.username,
                endpoint: finalEndpoint,
                logHandler: logHandler
            )
        }
    }

    private static func gracefulCloseTimeoutNanoseconds(
        responseTimeoutNanoseconds: UInt64?
    ) -> UInt64 {
        guard let responseTimeoutNanoseconds else {
            return self.defaultGracefulCloseTimeoutNanoseconds
        }

        return max(
            1,
            min(
                responseTimeoutNanoseconds,
                self.defaultGracefulCloseTimeoutNanoseconds
            )
        )
    }

    private static func closeTransportResources(
        client: SSHTransportProtocolClient,
        transportHandle: SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)?,
        gracefulCloseTimeoutNanoseconds: UInt64
    ) async {
        await transportHandle.transport.setObservationHandler(nil)
        let hasPendingBackgroundTransportFailure =
            await client.hasPendingBackgroundTransportFailure()
        await client.prepareForTransportLifecycleClose()

        if !hasPendingBackgroundTransportFailure {
            let disconnectTask = Task {
                await client.disconnect()
            }

            let didDisconnectFinish = await self.waitForTaskCompletion(
                disconnectTask,
                upTo: gracefulCloseTimeoutNanoseconds
            )
            if !didDisconnectFinish {
                disconnectTask.cancel()
            }
        }

        await transportHandle.close()
        await dependentCloseOperation?()
    }

    private static func abortTransportResources(
        client: SSHTransportProtocolClient,
        transportHandle: SSHClientTransportHandle,
        dependentCloseOperation: (@Sendable () async -> Void)?
    ) async {
        await client.abortTransportLifecycle()
        await transportHandle.abort()
        await dependentCloseOperation?()
    }

    private static func waitForTaskCompletion(
        _ task: Task<Void, Never>,
        upTo nanoseconds: UInt64
    ) async -> Bool {
        await withCheckedContinuation { continuation in
            let gate = TaskCompletionGate(continuation)

            Task {
                await task.value
                await gate.resume(with: true)
            }

            Task {
                try? await Task.sleep(nanoseconds: nanoseconds)
                await gate.resume(with: false)
            }
        }
    }

    private static func publicAuthenticationBanners(
        _ banners: [SSHUserAuthenticationBannerMessage]
    ) -> [SSHAuthenticationBanner] {
        banners.map {
            SSHAuthenticationBanner(
                message: $0.message,
                languageTag: $0.languageTag
            )
        }
    }

    private static func authenticationRejectedError(
        methodName: String,
        failure: SSHUserAuthenticationFailureMessage,
        banners: [SSHUserAuthenticationBannerMessage]
    ) -> SSHClientError {
        SSHClientError.authenticationRejected(
            methodName: methodName,
            availableMethods: failure.authenticationsThatCanContinue,
            partialSuccess: failure.partialSuccess,
            banners: self.publicAuthenticationBanners(banners)
        )
    }

    private static func passwordChangeRequiredError(
        _ changeRequest: SSHUserAuthenticationPasswordChangeRequestMessage,
        banners: [SSHUserAuthenticationBannerMessage]
    ) -> SSHClientError {
        SSHClientError.passwordChangeRequired(
            prompt: changeRequest.prompt,
            languageTag: changeRequest.languageTag,
            banners: self.publicAuthenticationBanners(banners)
        )
    }

    private static func authenticatePassword(
        password: String,
        passwordChangeResponseProvider: (@Sendable (SSHPasswordChangeChallenge) async throws -> String)?,
        username: String,
        client: SSHTransportProtocolClient,
        endpoint: SSHSocketEndpoint,
        authentication: SSHAuthenticationMethod,
        logHandler: SSHClientLogHandler
    ) async throws -> [SSHAuthenticationBanner] {
        let initialResult = try await client.authenticatePassword(
            username: username,
            password: password
        )
        switch initialResult.outcome {
        case .success:
            logHandler.logAuthenticationSucceeded(
                method: authentication,
                endpoint: endpoint
            )
            return self.publicAuthenticationBanners(initialResult.banners)
        case let .failure(failure):
            logHandler.logAuthenticationRejected(
                method: authentication,
                endpoint: endpoint,
                availableMethods: failure.authenticationsThatCanContinue,
                partialSuccess: failure.partialSuccess,
                bannerCount: initialResult.banners.count
            )
            throw self.authenticationRejectedError(
                methodName: "password",
                failure: failure,
                banners: initialResult.banners
            )
        case let .passwordChangeRequired(changeRequest):
            guard let passwordChangeResponseProvider else {
                logHandler.logPasswordChangeRequired(endpoint: endpoint)
                throw self.passwordChangeRequiredError(
                    changeRequest,
                    banners: initialResult.banners
                )
            }

            let initialPublicBanners = self.publicAuthenticationBanners(initialResult.banners)
            let newPassword: String
            do {
                newPassword = try await passwordChangeResponseProvider(
                    SSHPasswordChangeChallenge(
                        username: initialResult.username,
                        serviceName: initialResult.serviceName,
                        prompt: changeRequest.prompt,
                        languageTag: changeRequest.languageTag,
                        banners: initialPublicBanners
                    )
                )
            } catch {
                throw SSHUserCallbackFailure(
                    source: .passwordChangeResponse,
                    error: error
                )
            }

            let changedResult = try await client.authenticatePasswordChange(
                username: username,
                oldPassword: password,
                newPassword: newPassword
            )
            let combinedBanners = initialResult.banners + changedResult.banners

            switch changedResult.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(combinedBanners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: combinedBanners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "password",
                    failure: failure,
                    banners: combinedBanners
                )
            case let .passwordChangeRequired(changeRequest):
                logHandler.logPasswordChangeRequired(endpoint: endpoint)
                throw self.passwordChangeRequiredError(
                    changeRequest,
                    banners: combinedBanners
                )
            }
        }
    }

    private static func authenticate(
        _ authentication: SSHAuthenticationMethod,
        username: String,
        client: SSHTransportProtocolClient,
        endpoint: SSHSocketEndpoint,
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions,
        logHandler: SSHClientLogHandler
    ) async throws -> [SSHAuthenticationBanner] {
        switch authentication {
        case let .password(password):
            return try await self.authenticatePassword(
                password: password,
                passwordChangeResponseProvider: nil,
                username: username,
                client: client,
                endpoint: endpoint,
                authentication: authentication,
                logHandler: logHandler
            )
        case let .passwordWithChangeResponse(password, responseProvider):
            return try await self.authenticatePassword(
                password: password,
                passwordChangeResponseProvider: responseProvider,
                username: username,
                client: client,
                endpoint: endpoint,
                authentication: authentication,
                logHandler: logHandler
            )
        case let .ed25519PrivateKey(rawRepresentation):
            let privateKey = try SSHEd25519PrivateKey(rawRepresentation: rawRepresentation)
            let result = try await client.authenticatePublicKey(
                username: username,
                privateKey: privateKey
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "publickey",
                    failure: failure,
                    banners: result.banners
                )
            }
        case let .rsaPrivateKey(pkcs1DERRepresentation):
            let privateKey = try SSHRSAPrivateKey(
                pkcs1DERRepresentation: pkcs1DERRepresentation
            )
            let result = try await self.authenticateRSAPublicKey(
                username: username,
                privateKey: privateKey,
                authentication: authentication,
                client: client,
                endpoint: endpoint,
                legacyAlgorithmOptions: legacyAlgorithmOptions,
                logHandler: logHandler
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "publickey",
                    failure: failure,
                    banners: result.banners
                )
            }
        case let .ecdsaP256PrivateKey(rawRepresentation):
            let result = try await client.authenticatePublicKey(
                username: username,
                privateKey: SSHECDSAPrivateKey.nistp256(rawRepresentation: rawRepresentation)
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "publickey",
                    failure: failure,
                    banners: result.banners
                )
            }
        case let .ecdsaP384PrivateKey(rawRepresentation):
            let result = try await client.authenticatePublicKey(
                username: username,
                privateKey: SSHECDSAPrivateKey.nistp384(rawRepresentation: rawRepresentation)
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "publickey",
                    failure: failure,
                    banners: result.banners
                )
            }
        case let .ecdsaP521PrivateKey(rawRepresentation):
            let result = try await client.authenticatePublicKey(
                username: username,
                privateKey: SSHECDSAPrivateKey.nistp521(rawRepresentation: rawRepresentation)
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "publickey",
                    failure: failure,
                    banners: result.banners
                )
            }
        case let .publicKey(algorithmNames, publicKey, signatureProvider):
            guard !algorithmNames.isEmpty else {
                throw SSHAuthenticationMethodError.emptyPublicKeyAuthenticationAlgorithmList
            }
            let effectiveAlgorithmNames = self.publicKeyAuthenticationAlgorithmNames(
                algorithmNames,
                legacyAlgorithmOptions: legacyAlgorithmOptions
            )
            guard !effectiveAlgorithmNames.isEmpty else {
                throw SSHAuthenticationMethodError.emptyPublicKeyAuthenticationAlgorithmList
            }
            guard !publicKey.isEmpty else {
                throw SSHAuthenticationMethodError.emptyPublicKeyAuthenticationPublicKey
            }

            let result = try await client.authenticatePublicKey(
                username: username,
                algorithmNames: effectiveAlgorithmNames,
                publicKey: publicKey,
                signatureProvider: { request in
                    do {
                        return try await signatureProvider(request)
                    } catch let error as SSHAuthenticationMethodError {
                        throw error
                    } catch {
                        throw SSHUserCallbackFailure(
                            source: .publicKeySignature,
                            error: error
                        )
                    }
                }
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "publickey",
                    failure: failure,
                    banners: result.banners
                )
            }
        case let .keyboardInteractive(submethods, responseProvider):
            let result = try await client.authenticateKeyboardInteractive(
                username: username,
                submethods: submethods,
                responseProvider: { challenge in
                    do {
                        return try await responseProvider(challenge)
                    } catch let error as SSHAuthenticationMethodError {
                        throw error
                    } catch {
                        throw SSHUserCallbackFailure(
                            source: .keyboardInteractiveResponse,
                            error: error
                        )
                    }
                }
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "keyboard-interactive",
                    failure: failure,
                    banners: result.banners
                )
            }
        }
    }

    private static func publicKeyAuthenticationAlgorithmNames(
        _ algorithmNames: [String],
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions
    ) -> [String] {
        guard !legacyAlgorithmOptions.allowsSSHRSA else {
            return algorithmNames
        }

        return algorithmNames.filter { $0 != "ssh-rsa" }
    }

    private static func authenticateAny(
        _ authentications: [SSHAuthenticationMethod],
        username: String,
        client: SSHTransportProtocolClient,
        endpoint: SSHSocketEndpoint,
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions,
        logHandler: SSHClientLogHandler
    ) async throws -> [SSHAuthenticationBanner] {
        precondition(!authentications.isEmpty, "authentications must not be empty")

        var accumulatedBanners: [SSHAuthenticationBanner] = []
        var lastRejection: SSHClientError?

        for authentication in authentications {
            do {
                let banners = try await self.authenticate(
                    authentication,
                    username: username,
                    client: client,
                    endpoint: endpoint,
                    legacyAlgorithmOptions: legacyAlgorithmOptions,
                    logHandler: logHandler
                )
                return accumulatedBanners + banners
            } catch let error as SSHClientError {
                guard case let .authenticationRejected(
                    methodName,
                    availableMethods,
                    partialSuccess,
                    banners
                ) = error else {
                    throw error
                }

                accumulatedBanners += banners
                lastRejection = .authenticationRejected(
                    methodName: methodName,
                    availableMethods: availableMethods,
                    partialSuccess: partialSuccess,
                    banners: accumulatedBanners
                )
                continue
            }
        }

        if let lastRejection {
            throw lastRejection
        }

        preconditionFailure("authentications must not be empty")
    }

    private static func authenticateRSAPublicKey(
        username: String,
        privateKey: SSHRSAPrivateKey,
        authentication: SSHAuthenticationMethod,
        client: SSHTransportProtocolClient,
        endpoint: SSHSocketEndpoint,
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions,
        logHandler: SSHClientLogHandler
    ) async throws -> SSHPublicKeyAuthenticationResult {
        let preferredAlgorithms = legacyAlgorithmOptions.preferredRSAPublicKeyAuthenticationAlgorithms
        let initialResult = try await client.authenticatePublicKey(
            username: username,
            privateKey: privateKey,
            preferredAlgorithmNames: preferredAlgorithms
        )

        guard legacyAlgorithmOptions.allowsSSHRSA,
              initialResult.algorithmName != "ssh-rsa",
              case let .failure(failure) = initialResult.outcome,
              failure.authenticationsThatCanContinue.contains("publickey") else {
            return initialResult
        }

        let fallbackResult = try await client.authenticatePublicKey(
            username: username,
            privateKey: privateKey,
            preferredAlgorithmNames: ["ssh-rsa"]
        )

        guard !initialResult.banners.isEmpty else {
            return fallbackResult
        }

        return SSHPublicKeyAuthenticationResult(
            username: fallbackResult.username,
            serviceName: fallbackResult.serviceName,
            algorithmName: fallbackResult.algorithmName,
            banners: initialResult.banners + fallbackResult.banners,
            outcome: fallbackResult.outcome
        )
    }

    private static func wrapEarlyConnectionSetupError(
        _ error: any Error,
        username: String,
        endpoint: SSHSocketEndpoint,
        logHandler: SSHClientLogHandler
    ) -> any Error {
        let snapshot = SSHTransportProtocolDiagnosticsSnapshot(
            phase: .identification,
            clientIdentification: SSHTransportProtocolClient.defaultClientIdentification.rawValue,
            remoteIdentification: nil,
            preIdentificationLines: [],
            keepaliveIntervalNanoseconds: nil,
            keepaliveReplyTimeoutNanoseconds: nil,
            responseTimeoutNanoseconds: nil,
            negotiatedAlgorithms: nil,
            didReceiveServerExtensionInfo: false,
            serverExtensionNames: [],
            serverSignatureAlgorithms: nil,
            remoteDisconnect: nil,
            remoteDebugMessages: []
        )

        if error is CancellationError {
            return error
        }

        if let failure = self.wrapConnectionFailure(
            error,
            endpoint: endpoint,
            username: username,
            snapshot: snapshot
        ) {
            logHandler.logConnectionFailure(failure)
            return SSHClientError.connectionFailed(failure)
        }

        logHandler.logUnwrappedConnectionFailure(
            error,
            endpoint: endpoint
        )
        return error
    }
}

struct SSHClientTransportHandle: Sendable {
    let transport: any SSHByteStreamTransport
    let closeOperation: (@Sendable () async -> Void)?
    let abortOperation: (@Sendable () async -> Void)?

    init(
        transport: any SSHByteStreamTransport,
        closeOperation: (@Sendable () async -> Void)? = nil,
        abortOperation: (@Sendable () async -> Void)? = nil
    ) {
        self.transport = transport
        self.closeOperation = closeOperation
        self.abortOperation = abortOperation
    }

    func close() async {
        await self.transport.setObservationHandler(nil)
        await self.transport.close()
        await self.closeOperation?()
    }

    func abort() async {
        await self.transport.setObservationHandler(nil)
        await self.transport.abort()
        if let abortOperation {
            await abortOperation()
        } else {
            await self.closeOperation?()
        }
    }
}
