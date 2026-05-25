// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Active dynamic SOCKS5 port-forward listener details.
///
/// Returned from `SSHConnection.withDynamicPortForwarding(...)` after the local
/// SOCKS5 listener is bound.
public struct SSHDynamicPortForward: Equatable, Sendable {
    /// Local host name or address.
    public let localHost: String
    /// Local port number.
    public let localPort: UInt16

    init(localHost: String, localPort: UInt16) {
        self.localHost = localHost
        self.localPort = localPort
    }
}
struct SSHDynamicPortForwardService: Sendable {
    private let client: SSHTransportProtocolClient
    private let lifetime: SSHConnectionLifetime
    private let requestedForward: SSHDynamicPortForward
    private let socks5Authentication: SSHDynamicSOCKS5Authentication
    private let transportBackendPreference: SSHTCPTransportBackendPreference
    private let bridge: SSHPortForwardingBridge

    init(
        client: SSHTransportProtocolClient,
        lifetime: SSHConnectionLifetime,
        requestedForward: SSHDynamicPortForward,
        socks5Authentication: SSHSOCKS5ProxyAuthentication = .none,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic,
        bridge: SSHPortForwardingBridge = SSHPortForwardingBridge()
    ) throws {
        self.client = client
        self.lifetime = lifetime
        self.requestedForward = requestedForward
        self.socks5Authentication = try SSHDynamicSOCKS5Authentication(
            validating: socks5Authentication
        )
        self.transportBackendPreference = transportBackendPreference
        self.bridge = bridge
    }

    func withListener<Result>(
        _ body: (SSHDynamicPortForward) async throws -> Result
    ) async throws -> Result {
        let listener = try SSHTCPListenerFactory.makeLifecycleControlledListener(
            localHost: self.requestedForward.localHost,
            localPort: self.requestedForward.localPort,
            preference: self.transportBackendPreference
        )
        let connectionTasks = SSHDynamicPortForwardConnectionTasks()
        let connectionMonitor = SSHForwardingConnectionMonitor(
            client: self.client,
            lifetime: self.lifetime
        )

        let listenerTask = Task {
            try await listener.run { acceptedConnection in
                guard let connectionID = await connectionTasks.reserveSlot() else {
                    await acceptedConnection.close()
                    return
                }

                let connectionTask = Task {
                    var didCompleteBridge = false

                    do {
                        try await self.handleAcceptedConnection(acceptedConnection)
                        didCompleteBridge = true
                    } catch is CancellationError {
                    } catch {
                        // Dynamic forwarding behaves like a local proxy: one rejected or failed
                        // client connection must not take the listener down for later clients.
                        // Overall SSH liveness still flows through the listener task, fallback
                        // keepalive, and the shared connection lifetime watchers.
                    }

                    if !didCompleteBridge {
                        await acceptedConnection.close()
                    }

                    await connectionTasks.finish(connectionID)
                }
                await connectionTasks.attach(connectionTask, for: connectionID)
            }
        }
        let connectionClosureTask = connectionMonitor.makeConnectionClosureTask {
            await self.cancel(
                listenerTask: listenerTask,
                connectionTasks: connectionTasks
            )
        }
        let fallbackLivenessTask = await connectionMonitor.makeFallbackLivenessTaskIfNeeded()
        defer {
            connectionClosureTask.cancel()
            fallbackLivenessTask?.cancel()
        }

        let activeForward: SSHDynamicPortForward
        do {
            activeForward = SSHDynamicPortForward(
                localHost: self.requestedForward.localHost,
                localPort: try await withTaskCancellationHandler {
                    try await listener.readyPort()
                } onCancel: {
                    listenerTask.cancel()
                }
            )
        } catch {
            await self.cancel(
                listenerTask: listenerTask,
                connectionTasks: connectionTasks
            )
            throw error
        }

        do {
            let result = try await body(activeForward)
            guard await self.lifetime.active() else {
                await self.cancel(
                    listenerTask: listenerTask,
                    connectionTasks: connectionTasks
                )
                throw SSHClientError.connectionScopeEnded
            }
            try await self.shutdown(
                listenerTask: listenerTask,
                connectionTasks: connectionTasks
            )
            return result
        } catch {
            await self.cancel(
                listenerTask: listenerTask,
                connectionTasks: connectionTasks
            )
            guard await self.lifetime.active() else {
                throw SSHClientError.connectionScopeEnded
            }
            throw error
        }
    }

    private func handleAcceptedConnection(
        _ acceptedConnection: SSHTCPAcceptedConnection
    ) async throws {
        let bufferedTransport = SSHBufferedByteStreamTransport(
            base: acceptedConnection.transport
        )
        let request: SSHSOCKSRequest
        do {
            request = try await SSHSOCKSRequest.read(
                from: bufferedTransport,
                socks5Authentication: self.socks5Authentication
            )
        } catch let error as SSHSOCKSRequestFailure {
            try? await error.reply(on: bufferedTransport)
            throw error.transportError
        }

        let remoteChannel: SSHTCPIPChannelHandle
        do {
            remoteChannel = try await self.client.openDirectTCPIPChannel(
                target: SSHSocketEndpoint(host: request.targetHost, port: request.targetPort),
                originator: try acceptedConnection.originator(),
                outputBufferingMode: .events
            )
        } catch {
            try? await request.replyFailure(on: bufferedTransport)
            throw error
        }

        do {
            try await request.replySuccess(on: bufferedTransport)
        } catch {
            try? await remoteChannel.close()
            throw error
        }

        do {
            try await self.bridge.bridge(
                localTransport: bufferedTransport,
                remoteChannel: remoteChannel
            )
        } catch {
            try? await remoteChannel.close()
            throw error
        }
    }

    private func shutdown(
        listenerTask: Task<Void, Error>,
        connectionTasks: SSHDynamicPortForwardConnectionTasks
    ) async throws {
        await connectionTasks.beginShutdown()

        var listenerError: (any Error)?
        listenerTask.cancel()
        do {
            try await listenerTask.value
        } catch is CancellationError {
        } catch {
            listenerError = error
        }

        await connectionTasks.waitForAll()

        if let listenerError {
            throw listenerError
        }
    }

    private func cancel(
        listenerTask: Task<Void, Error>,
        connectionTasks: SSHDynamicPortForwardConnectionTasks
    ) async {
        await connectionTasks.beginShutdown()
        listenerTask.cancel()
        _ = try? await listenerTask.value
        await connectionTasks.waitForAll()
    }
}
private enum SSHDynamicSOCKS5Authentication: Sendable {
    case none
    case usernamePassword(username: [UInt8], password: [UInt8])

    init(validating authentication: SSHSOCKS5ProxyAuthentication) throws {
        switch authentication {
        case .none:
            self = .none
        case .usernamePassword:
            let credentials = try authentication.validatedCredentialBytes {
                SSHTransportError.invalidSOCKSConfiguration($0)
            }
            guard let credentials else {
                preconditionFailure("username/password authentication must validate to credentials")
            }
            self = .usernamePassword(
                username: credentials.username,
                password: credentials.password
            )
        }
    }

    var requiresAuthentication: Bool {
        switch self {
        case .none:
            false
        case .usernamePassword:
            true
        }
    }

    func negotiate(
        on transport: SSHBufferedByteStreamTransport,
        clientMethods: [UInt8]
    ) async throws {
        switch self {
        case .none:
            guard clientMethods.contains(0x00) else {
                throw SSHSOCKSRequestFailure.socks5MethodSelectionFailed(
                    "SOCKS5 client did not offer the no-auth method required by this listener."
                )
            }
            try await transport.send([0x05, 0x00], endOfStream: false)
        case let .usernamePassword(expectedUsername, expectedPassword):
            guard clientMethods.contains(0x02) else {
                throw SSHSOCKSRequestFailure.socks5MethodSelectionFailed(
                    "SOCKS5 client did not offer username/password authentication."
                )
            }
            try await transport.send([0x05, 0x02], endOfStream: false)

            let authVersion = try await SSHSOCKSRequest.readByte(from: transport)
            guard authVersion == 0x01 else {
                throw SSHSOCKSRequestFailure.socks5AuthenticationFailed(
                    "SOCKS5 username/password auth used unsupported version \(authVersion)."
                )
            }

            let usernameLength = Int(try await SSHSOCKSRequest.readByte(from: transport))
            let username = try await SSHSOCKSRequest.readExactByteCount(
                usernameLength,
                from: transport
            )
            let passwordLength = Int(try await SSHSOCKSRequest.readByte(from: transport))
            let password = try await SSHSOCKSRequest.readExactByteCount(
                passwordLength,
                from: transport
            )

            guard username == expectedUsername, password == expectedPassword else {
                throw SSHSOCKSRequestFailure.socks5AuthenticationFailed(
                    "SOCKS5 username/password authentication failed."
                )
            }

            try await transport.send([0x01, 0x00], endOfStream: false)
        }
    }
}

private enum SSHSOCKSReplyCode {
    static let socks4RequestRejected: UInt8 = 0x5b
    static let socks4RequestGranted: UInt8 = 0x5a
    static let socks5GeneralFailure: UInt8 = 0x01
    static let socks5CommandUnsupported: UInt8 = 0x07
    static let socks5AddressUnsupported: UInt8 = 0x08
    static let socks5Success: UInt8 = 0x00
}

private enum SSHSOCKSVersion: UInt8 {
    case v4 = 0x04
    case v5 = 0x05
}
private struct SSHSOCKSRequest: Sendable {
    let version: SSHSOCKSVersion
    let targetHost: String
    let targetPort: UInt16
    let failureReplyCode: UInt8

    static func read(
        from transport: SSHBufferedByteStreamTransport,
        socks5Authentication: SSHDynamicSOCKS5Authentication
    ) async throws -> SSHSOCKSRequest {
        let version = try await Self.readByte(from: transport)
        guard let socksVersion = SSHSOCKSVersion(rawValue: version) else {
            throw SSHTransportError.socksHandshakeFailed(
                "Unsupported SOCKS version \(version)."
            )
        }

        switch socksVersion {
        case .v4:
            return try await self.readSOCKS4(
                from: transport,
                socks5Authentication: socks5Authentication
            )
        case .v5:
            return try await self.readSOCKS5(
                from: transport,
                socks5Authentication: socks5Authentication
            )
        }
    }

    func replySuccess(
        on transport: SSHBufferedByteStreamTransport
    ) async throws {
        switch self.version {
        case .v4:
            try await transport.send([0x00, SSHSOCKSReplyCode.socks4RequestGranted, 0, 0, 0, 0, 0, 0], endOfStream: false)
        case .v5:
            try await transport.send(
                [0x05, SSHSOCKSReplyCode.socks5Success, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
                endOfStream: false
            )
        }
    }

    func replyFailure(
        on transport: SSHBufferedByteStreamTransport
    ) async throws {
        switch self.version {
        case .v4:
            try await transport.send([0x00, self.failureReplyCode, 0, 0, 0, 0, 0, 0], endOfStream: false)
        case .v5:
            try await transport.send(
                [0x05, self.failureReplyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
                endOfStream: false
            )
        }
    }

    private static func readSOCKS4(
        from transport: SSHBufferedByteStreamTransport,
        socks5Authentication: SSHDynamicSOCKS5Authentication
    ) async throws -> SSHSOCKSRequest {
        if socks5Authentication.requiresAuthentication {
            throw SSHSOCKSRequestFailure.socks4Rejected(
                "SOCKS4 and SOCKS4a are unavailable when SOCKS5 username/password authentication is configured."
            )
        }

        let command = try await self.readByte(from: transport)
        guard command == 0x01 else {
            throw SSHSOCKSRequestFailure.socks4Rejected(
                "Only SOCKS4 CONNECT is supported."
            )
        }

        let portBytes = try await self.readExactByteCount(2, from: transport)
        let addressBytes = try await self.readExactByteCount(4, from: transport)
        _ = try await self.readNullTerminatedField(from: transport)

        let targetHost: String
        if addressBytes[0] == 0, addressBytes[1] == 0, addressBytes[2] == 0, addressBytes[3] != 0 {
            targetHost = try await self.readNullTerminatedField(from: transport)
        } else {
            targetHost = addressBytes.map { String($0) }.joined(separator: ".")
        }

        return SSHSOCKSRequest(
            version: .v4,
            targetHost: targetHost,
            targetPort: UInt16(portBytes[0]) << 8 | UInt16(portBytes[1]),
            failureReplyCode: SSHSOCKSReplyCode.socks4RequestRejected
        )
    }

    private static func readSOCKS5(
        from transport: SSHBufferedByteStreamTransport,
        socks5Authentication: SSHDynamicSOCKS5Authentication
    ) async throws -> SSHSOCKSRequest {
        let methodCount = Int(try await self.readByte(from: transport))
        let methods = try await self.readExactByteCount(methodCount, from: transport)
        try await socks5Authentication.negotiate(on: transport, clientMethods: methods)

        let requestHeader = try await self.readExactByteCount(4, from: transport)
        guard requestHeader[0] == 0x05 else {
            throw SSHSOCKSRequestFailure.socks5Failure(
                replyCode: SSHSOCKSReplyCode.socks5GeneralFailure,
                "SOCKS5 request used unsupported version \(requestHeader[0])."
            )
        }
        guard requestHeader[1] == 0x01 else {
            throw SSHSOCKSRequestFailure.socks5Failure(
                replyCode: SSHSOCKSReplyCode.socks5CommandUnsupported,
                "Only SOCKS5 CONNECT is supported."
            )
        }

        let targetHost: String
        switch requestHeader[3] {
        case 0x01:
            let addressBytes = try await self.readExactByteCount(4, from: transport)
            targetHost = addressBytes.map { String($0) }.joined(separator: ".")
        case 0x03:
            let length = Int(try await self.readByte(from: transport))
            let domainBytes = try await self.readExactByteCount(length, from: transport)
            targetHost = String(decoding: domainBytes, as: UTF8.self)
        case 0x04:
            let addressBytes = try await self.readExactByteCount(16, from: transport)
            targetHost = self.decodeIPv6(addressBytes)
        default:
            throw SSHSOCKSRequestFailure.socks5Failure(
                replyCode: SSHSOCKSReplyCode.socks5AddressUnsupported,
                "SOCKS5 address type 0x\(String(requestHeader[3], radix: 16)) is not supported."
            )
        }

        let portBytes = try await self.readExactByteCount(2, from: transport)

        return SSHSOCKSRequest(
            version: .v5,
            targetHost: targetHost,
            targetPort: UInt16(portBytes[0]) << 8 | UInt16(portBytes[1]),
            failureReplyCode: SSHSOCKSReplyCode.socks5GeneralFailure
        )
    }

    private static func decodeIPv6(_ addressBytes: [UInt8]) -> String {
        stride(from: 0, to: addressBytes.count, by: 2)
            .map { index in
                let segment = UInt16(addressBytes[index]) << 8 | UInt16(addressBytes[index + 1])
                return String(segment, radix: 16)
            }
            .joined(separator: ":")
    }

    fileprivate static func readByte(
        from transport: SSHBufferedByteStreamTransport
    ) async throws -> UInt8 {
        try await self.readExactByteCount(1, from: transport)[0]
    }

    fileprivate static func readExactByteCount(
        _ count: Int,
        from transport: SSHBufferedByteStreamTransport
    ) async throws -> [UInt8] {
        var bytes: [UInt8] = []

        while bytes.count < count {
            let chunk = try await transport.receive(
                atLeast: 1,
                atMost: count - bytes.count
            )
            if chunk.bytes.isEmpty {
                if chunk.endOfStream {
                    throw SSHTransportError.endOfStreamBeforeIdentification
                }
                continue
            }
            bytes += chunk.bytes
        }

        return bytes
    }

    private static func readNullTerminatedField(
        from transport: SSHBufferedByteStreamTransport
    ) async throws -> String {
        var bytes: [UInt8] = []

        while true {
            let byte = try await self.readByte(from: transport)
            if byte == 0 {
                return String(decoding: bytes, as: UTF8.self)
            }
            bytes.append(byte)
        }
    }
}
private struct SSHSOCKSRequestFailure: Error {
    let replyBytes: [UInt8]
    let transportError: SSHTransportError

    static func socks4Rejected(_ message: String) -> Self {
        Self(
            replyBytes: [0x00, SSHSOCKSReplyCode.socks4RequestRejected, 0, 0, 0, 0, 0, 0],
            transportError: .socksHandshakeFailed(message)
        )
    }

    static func socks5Failure(
        replyCode: UInt8,
        _ message: String
    ) -> Self {
        Self(
            replyBytes: [0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
            transportError: .socksHandshakeFailed(message)
        )
    }

    static func socks5MethodSelectionFailed(_ message: String) -> Self {
        Self(
            replyBytes: [0x05, 0xff],
            transportError: .socksHandshakeFailed(message)
        )
    }

    static func socks5AuthenticationFailed(_ message: String) -> Self {
        Self(
            replyBytes: [0x01, 0x01],
            transportError: .socksHandshakeFailed(message)
        )
    }

    func reply(on transport: SSHBufferedByteStreamTransport) async throws {
        try await transport.send(self.replyBytes, endOfStream: false)
    }
}
private actor SSHDynamicPortForwardConnectionTasks {
    private struct Entry {
        var task: Task<Void, Never>?
    }

    private var tasks: [UInt64: Entry] = [:]
    private var nextID: UInt64 = 0
    private var isStopping = false
    private var waitContinuations: [UUID: CheckedContinuation<Void, Never>] = [:]

    func reserveSlot() -> UInt64? {
        guard !self.isStopping else {
            return nil
        }

        let taskID = self.nextID
        self.nextID += 1
        self.tasks[taskID] = Entry(task: nil)
        return taskID
    }

    func attach(_ task: Task<Void, Never>, for taskID: UInt64) {
        guard var entry = self.tasks[taskID] else {
            task.cancel()
            return
        }

        entry.task = task
        self.tasks[taskID] = entry

        if self.isStopping {
            task.cancel()
        }
    }

    func finish(_ taskID: UInt64) {
        self.tasks.removeValue(forKey: taskID)
        self.resumeWaitIfNeeded()
    }

    func beginShutdown() {
        self.isStopping = true

        for entry in self.tasks.values {
            entry.task?.cancel()
        }

        self.resumeWaitIfNeeded()
    }

    func waitForAll() async {
        if self.tasks.isEmpty {
            return
        }

        let waiterID = UUID()
        await withCheckedContinuation { continuation in
            self.installWaitContinuation(continuation, waiterID: waiterID)
        }
    }

    private func installWaitContinuation(
        _ continuation: CheckedContinuation<Void, Never>,
        waiterID: UUID
    ) {
        if self.tasks.isEmpty {
            continuation.resume()
            return
        }

        self.waitContinuations[waiterID] = continuation
    }

    private func resumeWaitIfNeeded() {
        guard self.tasks.isEmpty else {
            return
        }

        let continuations = self.waitContinuations.values
        self.waitContinuations.removeAll(keepingCapacity: false)
        for continuation in continuations {
            continuation.resume()
        }
    }
}
