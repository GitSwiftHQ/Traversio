// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Severity level for Traversio client log events.
public enum SSHClientLogLevel: Int, Comparable, Sendable {
    /// Debug.
    case debug = 0
    /// Info.
    case info = 1
    /// Notice.
    case notice = 2
    /// Warning.
    case warning = 3
    /// Error.
    case error = 4

    public static func <(lhs: SSHClientLogLevel, rhs: SSHClientLogLevel) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

/// Functional area associated with a Traversio client log event.
public enum SSHClientLogCategory: String, Equatable, Sendable {
    /// Connection.
    case connection
    /// Authentication.
    case authentication
    /// Session.
    case session
    /// SFTP.
    case sftp
    /// Forwarding.
    case forwarding
    /// Transport.
    case transport
}

/// Redacted client log event emitted by `SSHClientLogHandler`.
public struct SSHClientLogEvent: Sendable {
    /// Event timestamp.
    public let timestamp: Date
    /// Log level.
    public let level: SSHClientLogLevel
    /// Log category.
    public let category: SSHClientLogCategory
    /// Diagnostic or server-provided message.
    public let message: String
    /// Redacted event metadata.
    public let metadata: [String: String]
    /// Creates an SSHClientLogEvent.

    public init(
        timestamp: Date = Date(),
        level: SSHClientLogLevel,
        category: SSHClientLogCategory,
        message: String,
        metadata: [String: String] = [:]
    ) {
        self.timestamp = timestamp
        self.level = level
        self.category = category
        self.message = sshDiagnosticRedacted(message)
        self.metadata = sshDiagnosticRedactedMetadata(metadata)
    }
}

/// Lightweight log sink used by high-level Traversio APIs.
///
/// Example:
///
/// ```swift
/// let handler = SSHClientLogHandler.sink(minimumLevel: .debug) { event in
///     print(event.formattedLine)
/// }
/// ```
public struct SSHClientLogHandler: Sendable {
    private let minimumLevel: SSHClientLogLevel
    private let emitter: @Sendable (SSHClientLogEvent) -> Void

    /// Disabled.
    public static let disabled = Self(
        minimumLevel: .error,
        emitter: { _ in }
    )
    /// Creates an SSHClientLogHandler.

    public init(
        minimumLevel: SSHClientLogLevel = .info,
        emitter: @escaping @Sendable (SSHClientLogEvent) -> Void
    ) {
        self.minimumLevel = minimumLevel
        self.emitter = emitter
    }

    /// Creates a handler that sends matching events to `emitter`.
    public static func sink(
        minimumLevel: SSHClientLogLevel = .info,
        _ emitter: @escaping @Sendable (SSHClientLogEvent) -> Void
    ) -> Self {
        Self(minimumLevel: minimumLevel, emitter: emitter)
    }

    /// Emits one event when `level` is at or above the handler minimum.
    public func emit(
        level: SSHClientLogLevel,
        category: SSHClientLogCategory,
        message: String,
        metadata: [String: String] = [:]
    ) {
        guard level >= self.minimumLevel else {
            return
        }

        self.emitter(
            SSHClientLogEvent(
                level: level,
                category: category,
                message: message,
                metadata: metadata
            )
        )
    }
}

func sshLogMetadata(_ entries: (String, String?)...) -> [String: String] {
    var metadata: [String: String] = [:]
    metadata.reserveCapacity(entries.count)

    for (key, value) in entries {
        guard let value else {
            continue
        }
        metadata[key] = value
    }

    return metadata
}

func sshLogCategory(for scope: SSHOperationFailureScope) -> SSHClientLogCategory {
    switch scope {
    case .session:
        return .session
    case .directTCPIPChannel, .directStreamLocalChannel, .forwardedTCPIPChannel, .forwardedStreamLocalChannel,
            .remotePortForwardListener, .remoteStreamLocalForwardListener, .localPortForward, .remotePortForward:
        return .forwarding
    case .sftp:
        return .sftp
    }
}

extension SSHClientLogHandler {
    func logConnectionStateEvent(_ event: SSHConnectionStateEvent) {
        self.emit(
            level: event.snapshot.state == .lost ? .warning : .info,
            category: .connection,
            message: "SSH connection state changed.",
            metadata: sshLogMetadata(
                ("connectionState", event.snapshot.state.rawValue),
                ("stateTrigger", event.trigger.rawValue),
                ("transportState", event.snapshot.transportState?.rawValue),
                ("pathStatus", event.snapshot.networkPath?.status.rawValue),
                (
                    "availableInterfaces",
                    event.snapshot.networkPath?.availableInterfaces
                        .map(\.rawValue)
                        .joined(separator: ",")
                ),
                (
                    "isTransportViable",
                    event.snapshot.isTransportViable.map(String.init(describing:))
                ),
                (
                    "betterPathAvailable",
                    event.snapshot.betterPathAvailable.map(String.init(describing:))
                ),
                (
                    "isExpensivePath",
                    event.snapshot.networkPath?.isExpensive.description
                ),
                (
                    "isConstrainedPath",
                    event.snapshot.networkPath?.isConstrained.description
                ),
                (
                    "supportsIPv4",
                    event.snapshot.networkPath?.supportsIPv4.description
                ),
                (
                    "supportsIPv6",
                    event.snapshot.networkPath?.supportsIPv6.description
                ),
                ("detail", event.snapshot.detail)
            )
        )
    }

    func logConnectionStarted(
        endpoint: SSHSocketEndpoint,
        username: String,
        authentication: SSHAuthenticationMethod
    ) {
        self.emit(
            level: .info,
            category: .connection,
            message: "Starting SSH connection setup.",
            metadata: sshLogMetadata(
                ("endpointHost", endpoint.host),
                ("endpointPort", String(endpoint.port)),
                ("username", username),
                ("authenticationMethod", authentication.loggingName)
            )
        )
    }

    func logProxyJumpSetupStarted(
        finalEndpoint: SSHSocketEndpoint,
        username: String,
        authentication: SSHAuthenticationMethod,
        connectionCount: Int
    ) {
        self.emit(
            level: .info,
            category: .connection,
            message: "Starting SSH connection setup through ProxyJump.",
            metadata: sshLogMetadata(
                ("endpointHost", finalEndpoint.host),
                ("endpointPort", String(finalEndpoint.port)),
                ("username", username),
                ("authenticationMethod", authentication.loggingName),
                ("proxyJumpConnectionCount", String(connectionCount))
            )
        )
    }

    func logProxyJumpHopStarted(
        endpoint: SSHSocketEndpoint,
        username: String,
        authentication: SSHAuthenticationMethod,
        connectionIndex: Int,
        connectionCount: Int
    ) {
        self.emit(
            level: .info,
            category: .connection,
            message: "Starting SSH ProxyJump hop.",
            metadata: sshLogMetadata(
                ("endpointHost", endpoint.host),
                ("endpointPort", String(endpoint.port)),
                ("username", username),
                ("authenticationMethod", authentication.loggingName),
                ("proxyJumpConnectionIndex", String(connectionIndex)),
                ("proxyJumpConnectionCount", String(connectionCount)),
                ("connectionRole", "proxy-jump-hop")
            )
        )
    }

    func logProxyJumpChannelOpening(
        upstreamMetadata: SSHConnectionMetadata,
        targetEndpoint: SSHSocketEndpoint,
        connectionIndex: Int,
        connectionCount: Int
    ) {
        self.emit(
            level: .info,
            category: .connection,
            message: "Opening SSH ProxyJump direct-tcpip channel.",
            metadata: sshLogMetadata(
                ("upstreamEndpointHost", upstreamMetadata.endpointHost),
                ("upstreamEndpointPort", String(upstreamMetadata.endpointPort)),
                ("targetEndpointHost", targetEndpoint.host),
                ("targetEndpointPort", String(targetEndpoint.port)),
                ("proxyJumpConnectionIndex", String(connectionIndex)),
                ("proxyJumpConnectionCount", String(connectionCount))
            )
        )
    }

    func logProxyJumpTargetStarted(
        endpoint: SSHSocketEndpoint,
        username: String,
        authentication: SSHAuthenticationMethod,
        connectionIndex: Int,
        connectionCount: Int
    ) {
        self.emit(
            level: .info,
            category: .connection,
            message: "Starting SSH ProxyJump final target connection.",
            metadata: sshLogMetadata(
                ("endpointHost", endpoint.host),
                ("endpointPort", String(endpoint.port)),
                ("username", username),
                ("authenticationMethod", authentication.loggingName),
                ("proxyJumpConnectionIndex", String(connectionIndex)),
                ("proxyJumpConnectionCount", String(connectionCount)),
                ("connectionRole", "proxy-jump-target")
            )
        )
    }

    func logConnectionEstablished(_ metadata: SSHConnectionMetadata) {
        self.emit(
            level: .info,
            category: .connection,
            message: "SSH connection established.",
            metadata: sshLogMetadata(
                ("endpointHost", metadata.endpointHost),
                ("endpointPort", String(metadata.endpointPort)),
                ("username", metadata.username),
                ("clientIdentification", metadata.clientIdentification),
                ("remoteIdentification", metadata.remoteIdentification),
                ("hostKeyAlgorithm", metadata.hostKeyAlgorithm),
                ("hostKeyFingerprintSHA256", metadata.hostKeyFingerprintSHA256),
                ("hostKeyTrustMethod", metadata.hostKeyTrustMethod.rawValue)
            )
        )
    }

    func logConnectionFailure(_ failure: SSHConnectionFailure) {
        self.emit(
            level: .error,
            category: .connection,
            message: failure.message,
            metadata: sshLogMetadata(
                ("endpointHost", failure.diagnostics.endpointHost),
                ("endpointPort", String(failure.diagnostics.endpointPort)),
                ("username", failure.diagnostics.username),
                ("stage", failure.stage.rawValue),
                ("code", failure.code.rawValue),
                ("clientIdentification", failure.diagnostics.clientIdentification),
                (
                    "preIdentificationLineCount",
                    String(failure.diagnostics.preIdentificationLines.count)
                ),
                ("remoteIdentification", failure.diagnostics.remoteIdentification),
                (
                    "serverExtensionNames",
                    failure.diagnostics.serverExtensionNames.isEmpty
                        ? nil
                        : failure.diagnostics.serverExtensionNames.joined(separator: ",")
                ),
                (
                    "serverSignatureAlgorithms",
                    failure.diagnostics.serverSignatureAlgorithms?.joined(separator: ",")
                ),
                (
                    "remoteDisconnectReasonCode",
                    failure.diagnostics.remoteDisconnect.map { String($0.reasonCode) }
                ),
                (
                    "remoteDebugMessageCount",
                    String(failure.diagnostics.remoteDebugMessages.count)
                ),
                (
                    "keyExchangeAlgorithm",
                    failure.diagnostics.negotiatedAlgorithms?.keyExchangeAlgorithm
                ),
                (
                    "serverHostKeyAlgorithm",
                    failure.diagnostics.negotiatedAlgorithms?.serverHostKeyAlgorithm
                ),
                (
                    "usesStrictKeyExchange",
                    failure.diagnostics.negotiatedAlgorithms.map {
                        String($0.usesStrictKeyExchange)
                    }
                ),
                (
                    "compressionAlgorithmClientToServer",
                    failure.diagnostics.negotiatedAlgorithms?.compressionAlgorithmClientToServer
                ),
                (
                    "compressionAlgorithmServerToClient",
                    failure.diagnostics.negotiatedAlgorithms?.compressionAlgorithmServerToClient
                ),
                (
                    "effectiveIntegrityAlgorithmClientToServer",
                    failure.diagnostics.negotiatedAlgorithms?.effectiveIntegrityAlgorithmClientToServer
                ),
                (
                    "effectiveIntegrityAlgorithmServerToClient",
                    failure.diagnostics.negotiatedAlgorithms?.effectiveIntegrityAlgorithmServerToClient
                ),
                (
                    "callbackFailureSource",
                    failure.diagnostics.callbackFailure?.source.rawValue
                ),
                (
                    "callbackFailureErrorType",
                    failure.diagnostics.callbackFailure?.errorType
                ),
                (
                    "callbackFailureDiagnosticCode",
                    failure.diagnostics.callbackFailure?.diagnosticCode
                ),
                (
                    "callbackFailureDiagnosticSummary",
                    failure.diagnostics.callbackFailure?.diagnosticSummary
                )
            )
        )
    }

    func logUnwrappedConnectionFailure(
        _ error: any Error,
        endpoint: SSHSocketEndpoint
    ) {
        self.emit(
            level: .error,
            category: .connection,
            message: "SSH connection setup failed with an unwrapped error.",
            metadata: sshLogMetadata(
                ("endpointHost", endpoint.host),
                ("endpointPort", String(endpoint.port)),
                ("errorType", String(reflecting: type(of: error))),
                ("description", String(describing: error))
            )
        )
    }

    func logAuthenticationSucceeded(
        method: SSHAuthenticationMethod,
        endpoint: SSHSocketEndpoint
    ) {
        self.emit(
            level: .info,
            category: .authentication,
            message: "SSH authentication succeeded.",
            metadata: sshLogMetadata(
                ("endpointHost", endpoint.host),
                ("endpointPort", String(endpoint.port)),
                ("authenticationMethod", method.loggingName)
            )
        )
    }

    func logAuthenticationRejected(
        method: SSHAuthenticationMethod,
        endpoint: SSHSocketEndpoint,
        availableMethods: [String],
        partialSuccess: Bool,
        bannerCount: Int = 0
    ) {
        self.emit(
            level: .warning,
            category: .authentication,
            message: "SSH authentication was rejected by the server.",
            metadata: sshLogMetadata(
                ("endpointHost", endpoint.host),
                ("endpointPort", String(endpoint.port)),
                ("authenticationMethod", method.loggingName),
                ("availableMethods", availableMethods.joined(separator: ",")),
                ("partialSuccess", String(partialSuccess)),
                ("bannerCount", String(bannerCount))
            )
        )
    }

    func logPasswordChangeRequired(endpoint: SSHSocketEndpoint) {
        self.emit(
            level: .notice,
            category: .authentication,
            message: "SSH authentication requires a password change before login can continue.",
            metadata: sshLogMetadata(
                ("endpointHost", endpoint.host),
                ("endpointPort", String(endpoint.port))
            )
        )
    }

    func logOperationFailure(_ failure: SSHOperationFailure) {
        self.emit(
            level: .error,
            category: sshLogCategory(for: failure.scope),
            message: failure.message,
            metadata: sshLogMetadata(
                ("endpointHost", failure.diagnostics.endpointHost),
                ("endpointPort", String(failure.diagnostics.endpointPort)),
                ("username", failure.diagnostics.username),
                ("scope", failure.scope.rawValue),
                ("code", failure.code.rawValue),
                ("clientIdentification", failure.diagnostics.clientIdentification),
                ("remoteIdentification", failure.diagnostics.remoteIdentification),
                ("localChannelID", failure.diagnostics.localChannelID.map(String.init)),
                ("remoteChannelID", failure.diagnostics.remoteChannelID.map(String.init)),
                ("requestType", failure.diagnostics.requestType),
                (
                    "serverExtensionNames",
                    failure.diagnostics.serverExtensionNames.isEmpty
                        ? nil
                        : failure.diagnostics.serverExtensionNames.joined(separator: ",")
                ),
                (
                    "remoteDisconnectReasonCode",
                    failure.diagnostics.remoteDisconnect.map { String($0.reasonCode) }
                ),
                (
                    "remoteDebugMessageCount",
                    String(failure.diagnostics.remoteDebugMessages.count)
                ),
                (
                    "effectiveIntegrityAlgorithmClientToServer",
                    failure.diagnostics.negotiatedAlgorithms?.effectiveIntegrityAlgorithmClientToServer
                ),
                (
                    "effectiveIntegrityAlgorithmServerToClient",
                    failure.diagnostics.negotiatedAlgorithms?.effectiveIntegrityAlgorithmServerToClient
                ),
                ("sftpStatusCode", failure.diagnostics.sftpStatus.map { String($0.code) }),
                ("sftpStatusName", failure.diagnostics.sftpStatus?.standardName),
                ("sftpStatusMessage", failure.diagnostics.sftpStatus?.message)
            )
        )
    }

    func logUnwrappedOperationError(
        _ error: any Error,
        scope: SSHOperationFailureScope,
        metadata: SSHConnectionMetadata,
        localChannelID: UInt32?,
        remoteChannelID: UInt32?,
        requestType: String?
    ) {
        self.emit(
            level: .error,
            category: sshLogCategory(for: scope),
            message: "SSH operation failed with an unwrapped error.",
            metadata: sshLogMetadata(
                ("endpointHost", metadata.endpointHost),
                ("endpointPort", String(metadata.endpointPort)),
                ("scope", scope.rawValue),
                ("localChannelID", localChannelID.map(String.init)),
                ("remoteChannelID", remoteChannelID.map(String.init)),
                ("requestType", requestType),
                ("errorType", String(reflecting: type(of: error))),
                ("description", String(describing: error))
            )
        )
    }
}

extension SSHAuthenticationMethod {
    var loggingName: String {
        switch self {
        case .password, .passwordWithChangeResponse:
            return "password"
        case .ed25519PrivateKey, .rsaPrivateKey, .ecdsaP256PrivateKey,
                .ecdsaP384PrivateKey, .ecdsaP521PrivateKey, .publicKey:
            return "publickey"
        case .keyboardInteractive:
            return "keyboard-interactive"
        }
    }
}
