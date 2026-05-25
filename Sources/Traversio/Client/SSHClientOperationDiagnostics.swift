// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Network

/// Public operation area where a post-auth failure occurred.
public enum SSHOperationFailureScope: String, Equatable, Sendable {
    /// Session.
    case session
    /// Direct TCP/IP Channel.
    case directTCPIPChannel
    /// Direct Stream Local Channel.
    case directStreamLocalChannel
    /// Forwarded TCP/IP Channel.
    case forwardedTCPIPChannel
    /// Forwarded Stream Local Channel.
    case forwardedStreamLocalChannel
    /// Remote Port Forward Listener.
    case remotePortForwardListener
    /// Remote Stream Local Forward Listener.
    case remoteStreamLocalForwardListener
    /// Local Port Forward.
    case localPortForward
    /// Remote Port Forward.
    case remotePortForward
    /// SFTP.
    case sftp
}

/// Stable post-auth operation failure code for app branching and support
/// reports.
public enum SSHOperationFailureCode: String, Equatable, Sendable {
    /// Authenticated Connection Required.
    case authenticatedConnectionRequired
    /// Timeout.
    case timeout
    /// Transport Closed.
    case transportClosed
    /// Transport Error.
    case transportError
    /// Remote Disconnect.
    case remoteDisconnect
    /// Unexpected transport message.
    case unexpectedTransportMessage
    /// Unexpected connection message.
    case unexpectedConnectionMessage
    /// Unexpected channel message.
    case unexpectedChannelMessage
    /// Unexpected SFTP message.
    case unexpectedSFTPMessage
    /// Channel Open Failed.
    case channelOpenFailed
    /// Request Failed.
    case requestFailed
    /// Unknown Channel.
    case unknownChannel
    /// Channel Receive Window Exceeded.
    case channelReceiveWindowExceeded
    /// Channel Receive Window Overflow.
    case channelReceiveWindowOverflow
    /// Channel Send Window Overflow.
    case channelSendWindowOverflow
    /// Channel Closed.
    case channelClosed
    /// Concurrent Write.
    case concurrentWrite
    /// Invalid Protocol Message.
    case invalidProtocolMessage
    /// Invalid Response.
    case invalidResponse
    /// Unsupported Request.
    case unsupportedRequest
    /// Version Exchange Required.
    case versionExchangeRequired
}

/// SFTP status details captured from a failed SFTP operation.
public struct SSHSFTPStatusDetails: Equatable, Sendable {
    /// Code.
    public let code: UInt32
    /// Status Code.
    public let statusCode: SSHSFTPStatusCode
    /// Diagnostic or server-provided message.
    public let message: String?
    /// Server-provided language tag.
    public let languageTag: String?
    /// Creates an SSHSFTPStatusDetails.

    public init(code: UInt32, message: String?, languageTag: String?) {
        self.code = code
        self.statusCode = SSHSFTPStatusCode(rawValue: code)
        self.message = message
        self.languageTag = languageTag
    }
    /// Creates an SSHSFTPStatusDetails.

    public init(statusCode: SSHSFTPStatusCode, message: String?, languageTag: String?) {
        self.code = statusCode.rawValue
        self.statusCode = statusCode
        self.message = message
        self.languageTag = languageTag
    }

    /// Standard Name.
    public var standardName: String? {
        self.statusCode.standardName
    }
}

/// Diagnostic context captured when a post-auth operation fails.
public struct SSHOperationFailureDiagnostics: Equatable, Sendable {
    /// Endpoint host name or address.
    public let endpointHost: String
    /// Endpoint port number.
    public let endpointPort: UInt16
    /// SSH username.
    public let username: String
    /// client identification.
    public let clientIdentification: String
    /// remote identification.
    public let remoteIdentification: String
    /// Keepalive Interval Nanoseconds.
    public let keepaliveIntervalNanoseconds: UInt64?
    /// Keepalive Reply Timeout Nanoseconds.
    public let keepaliveReplyTimeoutNanoseconds: UInt64?
    /// Response Timeout Nanoseconds.
    public let responseTimeoutNanoseconds: UInt64?
    /// Negotiated Algorithms.
    public let negotiatedAlgorithms: SSHNegotiatedTransportAlgorithms?
    /// Did Receive server extension Info.
    public let didReceiveServerExtensionInfo: Bool
    /// server extension Names.
    public let serverExtensionNames: [String]
    /// Remote Disconnect.
    public let remoteDisconnect: SSHRemoteDisconnect?
    /// remote debug Messages.
    public let remoteDebugMessages: [SSHRemoteDebugMessage]
    /// Local Channel ID.
    public let localChannelID: UInt32?
    /// Remote Channel ID.
    public let remoteChannelID: UInt32?
    /// Request Type.
    public let requestType: String?
    /// SFTP Status.
    public let sftpStatus: SSHSFTPStatusDetails?
}

/// Structured post-auth operation failure returned through
/// `SSHClientError.operationFailed`.
public struct SSHOperationFailure: Equatable, Sendable {
    /// Scope.
    public let scope: SSHOperationFailureScope
    /// Code.
    public let code: SSHOperationFailureCode
    /// Diagnostic or server-provided message.
    public let message: String
    /// Structured diagnostic context.
    public let diagnostics: SSHOperationFailureDiagnostics
}

extension SSHOperationFailureDiagnostics {
    init(
        metadata: SSHConnectionMetadata,
        snapshot: SSHTransportProtocolDiagnosticsSnapshot,
        localChannelID: UInt32?,
        remoteChannelID: UInt32?,
        requestType: String?,
        sftpStatus: SSHSFTPStatusDetails?
    ) {
        self.endpointHost = metadata.endpointHost
        self.endpointPort = metadata.endpointPort
        self.username = metadata.username
        self.clientIdentification = metadata.clientIdentification
        self.remoteIdentification = metadata.remoteIdentification
        self.keepaliveIntervalNanoseconds = snapshot.keepaliveIntervalNanoseconds
        self.keepaliveReplyTimeoutNanoseconds = snapshot.keepaliveReplyTimeoutNanoseconds
        self.responseTimeoutNanoseconds = snapshot.responseTimeoutNanoseconds
        self.negotiatedAlgorithms = snapshot.negotiatedAlgorithms.map {
            SSHNegotiatedTransportAlgorithms(snapshot: $0)
        }
        self.didReceiveServerExtensionInfo = snapshot.didReceiveServerExtensionInfo
        self.serverExtensionNames = snapshot.serverExtensionNames
        self.remoteDisconnect = snapshot.remoteDisconnect.map {
            SSHRemoteDisconnect(snapshot: $0)
        }
        self.remoteDebugMessages = snapshot.remoteDebugMessages.map {
            SSHRemoteDebugMessage(snapshot: $0)
        }
        self.localChannelID = localChannelID
        self.remoteChannelID = remoteChannelID
        self.requestType = requestType
        self.sftpStatus = sftpStatus
    }
}

protocol SSHOperationFailureMappingContext: Sendable {
    var operationFailureMetadata: SSHConnectionMetadata { get }
    var operationFailureLogHandler: SSHClientLogHandler { get }
    var operationFailureLocalChannelID: UInt32? { get }
    var operationFailureRemoteChannelID: UInt32? { get }

    func operationFailureSnapshot() async -> SSHTransportProtocolDiagnosticsSnapshot
}

extension SSHOperationFailureMappingContext {
    func withMappedOperationFailure<Result>(
        scope: SSHOperationFailureScope,
        requestType: String? = nil,
        _ operation: () async throws -> Result
    ) async throws -> Result {
        try await withOperationFailureMapping(
            metadata: self.operationFailureMetadata,
            snapshotProvider: { await self.operationFailureSnapshot() },
            scope: scope,
            logHandler: self.operationFailureLogHandler,
            localChannelID: self.operationFailureLocalChannelID,
            remoteChannelID: self.operationFailureRemoteChannelID,
            requestType: requestType,
            operation
        )
    }
}

func withOperationFailureMapping<Result>(
    metadata: SSHConnectionMetadata,
    snapshotProvider: @escaping @Sendable () async -> SSHTransportProtocolDiagnosticsSnapshot,
    scope: SSHOperationFailureScope,
    logHandler: SSHClientLogHandler = .disabled,
    localChannelID: UInt32? = nil,
    remoteChannelID: UInt32? = nil,
    requestType: String? = nil,
    _ operation: () async throws -> Result
) async throws -> Result {
    do {
        return try await operation()
    } catch let error as SSHClientError {
        throw error
    } catch {
        let snapshot = await snapshotProvider()
        if let failure = operationFailure(
            from: error,
            metadata: metadata,
            snapshot: snapshot,
            scope: scope,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            fallbackRequestType: requestType
        ) {
            logHandler.logOperationFailure(failure)
            throw SSHClientError.operationFailed(failure)
        }

        logHandler.logUnwrappedOperationError(
            error,
            scope: scope,
            metadata: metadata,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: requestType
        )
        throw error
    }
}

private func operationFailure(
    from error: Error,
    metadata: SSHConnectionMetadata,
    snapshot: SSHTransportProtocolDiagnosticsSnapshot,
    scope: SSHOperationFailureScope,
    localChannelID: UInt32?,
    remoteChannelID: UInt32?,
    fallbackRequestType: String?
) -> SSHOperationFailure? {
    switch error {
    case let timeoutError as SSHTimeoutError:
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType ?? timeoutError.requestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .timeout,
            message: timeoutError.message,
            diagnostics: diagnostics
        )
    case let transportError as SSHTransportError:
        return wrapTransportOperationFailure(
            transportError,
            metadata: metadata,
            snapshot: snapshot,
            scope: scope,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            fallbackRequestType: fallbackRequestType
        )
    case let wireError as SSHWireError:
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: message(for: wireError),
            diagnostics: diagnostics
        )
    case let connectionError as SSHConnectionError:
        return wrapConnectionOperationFailure(
            connectionError,
            metadata: metadata,
            snapshot: snapshot,
            scope: scope,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            fallbackRequestType: fallbackRequestType
        )
    case let authenticationError as SSHUserAuthenticationError:
        return wrapUnexpectedPostAuthenticationFailure(
            authenticationError,
            metadata: metadata,
            snapshot: snapshot,
            scope: scope,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            fallbackRequestType: fallbackRequestType
        )
    case let sftpError as SSHSFTPError:
        return wrapSFTPOperationFailure(
            sftpError,
            metadata: metadata,
            snapshot: snapshot,
            scope: scope,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            fallbackRequestType: fallbackRequestType
        )
    case let posixError as POSIXError:
        return wrapExternalTransportOperationFailure(
            posixError,
            metadata: metadata,
            snapshot: snapshot,
            scope: scope,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            fallbackRequestType: fallbackRequestType
        )
    default:
        if #available(macOS 10.14, iOS 12.0, tvOS 12.0, watchOS 5.0, visionOS 1.0, *),
           let networkError = error as? NWError {
            return wrapExternalTransportOperationFailure(
                networkError,
                metadata: metadata,
                snapshot: snapshot,
                scope: scope,
                localChannelID: localChannelID,
                remoteChannelID: remoteChannelID,
                fallbackRequestType: fallbackRequestType
            )
        }
        let nsError = error as NSError
        if nsError.domain == NSPOSIXErrorDomain {
            return wrapExternalTransportOperationFailure(
                nsError,
                metadata: metadata,
                snapshot: snapshot,
                scope: scope,
                localChannelID: localChannelID,
                remoteChannelID: remoteChannelID,
                fallbackRequestType: fallbackRequestType
            )
        }
        return nil
    }
}

private func wrapExternalTransportOperationFailure(
    _ error: any Error,
    metadata: SSHConnectionMetadata,
    snapshot: SSHTransportProtocolDiagnosticsSnapshot,
    scope: SSHOperationFailureScope,
    localChannelID: UInt32?,
    remoteChannelID: UInt32?,
    fallbackRequestType: String?
) -> SSHOperationFailure {
    let diagnostics = SSHOperationFailureDiagnostics(
        metadata: metadata,
        snapshot: snapshot,
        localChannelID: localChannelID,
        remoteChannelID: remoteChannelID,
        requestType: fallbackRequestType,
        sftpStatus: nil
    )
    return SSHOperationFailure(
        scope: scope,
        code: .transportError,
        message: String(describing: error),
        diagnostics: diagnostics
    )
}

private func wrapTransportOperationFailure(
    _ error: SSHTransportError,
    metadata: SSHConnectionMetadata,
    snapshot: SSHTransportProtocolDiagnosticsSnapshot,
    scope: SSHOperationFailureScope,
    localChannelID: UInt32?,
    remoteChannelID: UInt32?,
    fallbackRequestType: String?
) -> SSHOperationFailure {
    let diagnostics = SSHOperationFailureDiagnostics(
        metadata: metadata,
        snapshot: snapshot,
        localChannelID: localChannelID,
        remoteChannelID: remoteChannelID,
        requestType: fallbackRequestType,
        sftpStatus: nil
    )

    switch error {
    case let .strictKeyExchangeViolation(details):
        return SSHOperationFailure(
            scope: scope,
            code: .unexpectedTransportMessage,
            message: "Strict key exchange violation: \(details)",
            diagnostics: diagnostics
        )
    case let .unexpectedTransportMessage(expected, received):
        if received == .disconnect, diagnostics.remoteDisconnect != nil {
            return SSHOperationFailure(
                scope: scope,
                code: .remoteDisconnect,
                message: remoteDisconnectMessage(
                    from: diagnostics,
                    scope: scope
                ),
                diagnostics: diagnostics
            )
        }

        return SSHOperationFailure(
            scope: scope,
            code: .unexpectedTransportMessage,
            message: "Expected SSH transport message \(transportMessageName(expected)), but received \(transportMessageName(received)).",
            diagnostics: diagnostics
        )
    case .endOfStreamBeforeIdentification:
        return SSHOperationFailure(
            scope: scope,
            code: .transportClosed,
            message: "The remote peer closed the byte stream before sending an SSH identification line.",
            diagnostics: diagnostics
        )
    case .endOfStreamBeforePacket:
        return SSHOperationFailure(
            scope: scope,
            code: .transportClosed,
            message: "The remote peer closed the byte stream before sending the next SSH packet.",
            diagnostics: diagnostics
        )
    case .emptyReceive:
        return SSHOperationFailure(
            scope: scope,
            code: .transportError,
            message: "The transport returned an empty read without signaling EOF.",
            diagnostics: diagnostics
        )
    case .versionExchangeRequired:
        return SSHOperationFailure(
            scope: scope,
            code: .transportError,
            message: "A transport operation ran before version exchange completed.",
            diagnostics: diagnostics
        )
    case let .invalidPort(port):
        return SSHOperationFailure(
            scope: scope,
            code: .transportError,
            message: "Invalid TCP port \(port).",
            diagnostics: diagnostics
        )
    case let .invalidProxyConfiguration(details):
        return SSHOperationFailure(
            scope: scope,
            code: .transportError,
            message: details,
            diagnostics: diagnostics
        )
    case let .invalidSOCKSConfiguration(details):
        return SSHOperationFailure(
            scope: scope,
            code: .transportError,
            message: details,
            diagnostics: diagnostics
        )
    case let .proxyHandshakeFailed(details):
        return SSHOperationFailure(
            scope: scope,
            code: .transportError,
            message: "Connection proxy handshake failed: \(details)",
            diagnostics: diagnostics
        )
    case let .unsupportedTransportBackend(details):
        return SSHOperationFailure(
            scope: scope,
            code: .transportError,
            message: details,
            diagnostics: diagnostics
        )
    case .transportClosed:
        return SSHOperationFailure(
            scope: scope,
            code: .transportClosed,
            message: "The local transport was closed before the operation completed.",
            diagnostics: diagnostics
        )
    case let .socksHandshakeFailed(details):
        return SSHOperationFailure(
            scope: scope,
            code: .transportError,
            message: "SOCKS handshake failed: \(details)",
            diagnostics: diagnostics
        )
    case let .unsupportedEndpoint(endpoint):
        return SSHOperationFailure(
            scope: scope,
            code: .transportError,
            message: "Unsupported endpoint value: \(endpoint).",
            diagnostics: diagnostics
        )
    case .listenerDidNotReportPort:
        return SSHOperationFailure(
            scope: scope,
            code: .transportError,
            message: "The local listener did not report its bound port.",
            diagnostics: diagnostics
        )
    case let .internalInvariantBroken(details):
        return SSHOperationFailure(
            scope: scope,
            code: .transportError,
            message: details,
            diagnostics: diagnostics
        )
    }
}

private func wrapUnexpectedPostAuthenticationFailure(
    _ error: SSHUserAuthenticationError,
    metadata: SSHConnectionMetadata,
    snapshot: SSHTransportProtocolDiagnosticsSnapshot,
    scope: SSHOperationFailureScope,
    localChannelID: UInt32?,
    remoteChannelID: UInt32?,
    fallbackRequestType: String?
) -> SSHOperationFailure {
    switch error {
    case let .unexpectedTransportMessage(messageID):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        if messageID == .disconnect, diagnostics.remoteDisconnect != nil {
            return SSHOperationFailure(
                scope: scope,
                code: .remoteDisconnect,
                message: remoteDisconnectMessage(
                    from: diagnostics,
                    scope: scope
                ),
                diagnostics: diagnostics
            )
        }

        return SSHOperationFailure(
            scope: scope,
            code: .unexpectedTransportMessage,
            message: "Received unexpected SSH transport message \(transportMessageName(messageID)).",
            diagnostics: diagnostics
        )
    case let .unexpectedAuthenticationMessage(messageID):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "Received unexpected SSH userauth message \(authenticationMessageName(messageID)) after authentication completed.",
            diagnostics: diagnostics
        )
    case let .unexpectedServiceAccept(expected, received):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: expected,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "Expected service accept for \(expected), but the server accepted \(received) after authentication completed.",
            diagnostics: diagnostics
        )
    case let .unexpectedPostAuthenticationMessage(messageID):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "Received unexpected SSH packet \(messageID) after authentication completed.",
            diagnostics: diagnostics
        )
    case .confidentialTransportRequired:
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "An authenticated operation attempted to run before encrypted transport was active.",
            diagnostics: diagnostics
        )
    case .sessionIdentifierRequired:
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "An authenticated operation required a session identifier before it was available.",
            diagnostics: diagnostics
        )
    case .publicKeyConfirmationMismatch:
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "The server confirmed a different public key than the client offered after authentication completed.",
            diagnostics: diagnostics
        )
    }
}

private func wrapConnectionOperationFailure(
    _ error: SSHConnectionError,
    metadata: SSHConnectionMetadata,
    snapshot: SSHTransportProtocolDiagnosticsSnapshot,
    scope: SSHOperationFailureScope,
    localChannelID: UInt32?,
    remoteChannelID: UInt32?,
    fallbackRequestType: String?
) -> SSHOperationFailure {
    switch error {
    case .authenticatedConnectionRequired:
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .authenticatedConnectionRequired,
            message: "The SSH operation requires an authenticated connection service.",
            diagnostics: diagnostics
        )
    case let .unexpectedConnectionMessage(expected, received):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .unexpectedConnectionMessage,
            message: "Expected SSH connection message \(connectionMessageName(expected)), but received \(connectionMessageName(received)).",
            diagnostics: diagnostics
        )
    case let .channelOpenFailure(failure):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID ?? failure.recipientChannel,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .channelOpenFailed,
            message: channelOpenFailureMessage(failure),
            diagnostics: diagnostics
        )
    case let .channelRequestFailed(channelID, requestType):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID ?? channelID,
            remoteChannelID: remoteChannelID,
            requestType: requestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .requestFailed,
            message: "The server rejected SSH channel request \(requestType) on local channel \(channelID).",
            diagnostics: diagnostics
        )
    case let .globalRequestFailed(requestType):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: requestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .requestFailed,
            message: "The server rejected SSH global request \(requestType).",
            diagnostics: diagnostics
        )
    case let .invalidGlobalRequestResponse(requestType):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: requestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidResponse,
            message: "The server sent an invalid success response for SSH global request \(requestType).",
            diagnostics: diagnostics
        )
    case let .unexpectedChannelMessage(expected, received):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID ?? expected,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .unexpectedChannelMessage,
            message: "Expected data for local channel \(expected), but received it for local channel \(received).",
            diagnostics: diagnostics
        )
    case let .unknownChannel(channelID):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID ?? channelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .unknownChannel,
            message: "The SSH connection no longer tracks local channel \(channelID).",
            diagnostics: diagnostics
        )
    case let .channelReceiveWindowExceeded(channelID, received, remaining):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID ?? channelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .channelReceiveWindowExceeded,
            message: "The peer sent \(received) bytes on local channel \(channelID) with only \(remaining) bytes remaining in the receive window.",
            diagnostics: diagnostics
        )
    case let .channelReceiveWindowOverflow(channelID, current, adjustment):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID ?? channelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .channelReceiveWindowOverflow,
            message: "Applying local receive-window adjustment \(adjustment) on local channel \(channelID) would overflow the current window \(current).",
            diagnostics: diagnostics
        )
    case let .channelSendWindowOverflow(channelID, current, adjustment):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID ?? channelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .channelSendWindowOverflow,
            message: "Applying remote window adjustment \(adjustment) on local channel \(channelID) would overflow the current window \(current).",
            diagnostics: diagnostics
        )
    case let .channelClosedBeforeSending(channelID, unsentByteCount):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID ?? channelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .channelClosed,
            message: "Local channel \(channelID) closed before sending \(unsentByteCount) queued bytes.",
            diagnostics: diagnostics
        )
    case let .channelClosedBeforeReceiving(channelID):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID ?? channelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .channelClosed,
            message: "Local channel \(channelID) closed before the expected inbound data arrived.",
            diagnostics: diagnostics
        )
    case let .concurrentChannelWrite(channelID):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID ?? channelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .concurrentWrite,
            message: "Concurrent writes are not allowed on local channel \(channelID).",
            diagnostics: diagnostics
        )
    case let .incompatibleSessionOutputConsumer(channelID, activeConsumer, requestedConsumer):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID ?? channelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "Local channel \(channelID) is already using \(activeConsumer.rawValue) output consumption and cannot switch to \(requestedConsumer.rawValue).",
            diagnostics: diagnostics
        )
    case let .invalidChannelRequest(requestType):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: requestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "Encountered invalid SSH channel request \(requestType).",
            diagnostics: diagnostics
        )
    case let .invalidGlobalRequest(requestType):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: requestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "Encountered invalid SSH global request \(requestType).",
            diagnostics: diagnostics
        )
    case let .invalidChannelOpen(channelType):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "Encountered invalid SSH channel-open payload for channel type \(channelType).",
            diagnostics: diagnostics
        )
    case let .invalidTCPIPPort(port):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "Encountered invalid TCP/IP port value \(port) in SSH connection data.",
            diagnostics: diagnostics
        )
    case .invalidPseudoTerminalModes:
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: "pty-req",
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "Encountered invalid pseudo-terminal mode data.",
            diagnostics: diagnostics
        )
    }
}

private func wrapSFTPOperationFailure(
    _ error: SSHSFTPError,
    metadata: SSHConnectionMetadata,
    snapshot: SSHTransportProtocolDiagnosticsSnapshot,
    scope: SSHOperationFailureScope,
    localChannelID: UInt32?,
    remoteChannelID: UInt32?,
    fallbackRequestType: String?
) -> SSHOperationFailure {
    switch error {
    case let .unexpectedMessage(expected, received):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .unexpectedSFTPMessage,
            message: "Expected SFTP message \(sftpMessageName(expected)), but received \(sftpMessageName(received)).",
            diagnostics: diagnostics
        )
    case let .unexpectedResponseRequestID(expected, received):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidResponse,
            message: "Expected SFTP response for request \(expected), but received response \(received).",
            diagnostics: diagnostics
        )
    case let .unexpectedResponseWithoutPendingRequest(received):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidResponse,
            message: "Received SFTP response \(received) without a matching pending request.",
            diagnostics: diagnostics
        )
    case let .unexpectedNameCount(expected, received):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidResponse,
            message: "Expected \(expected) SFTP name entries, but received \(received).",
            diagnostics: diagnostics
        )
    case let .unexpectedDataLength(maximum, received):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidResponse,
            message: "Expected at most \(maximum) SFTP data bytes, but received \(received).",
            diagnostics: diagnostics
        )
    case let .unsupportedExtendedRequest(requestType):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: requestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .unsupportedRequest,
            message: "The server does not support SFTP extended request \(requestType).",
            diagnostics: diagnostics
        )
    case let .status(statusMessage):
        let sftpStatus = SSHSFTPStatusDetails(
            statusCode: statusMessage.statusCode,
            message: statusMessage.errorMessage,
            languageTag: statusMessage.languageTag
        )
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: sftpStatus
        )
        return SSHOperationFailure(
            scope: scope,
            code: .requestFailed,
            message: sftpStatusMessage(from: statusMessage),
            diagnostics: diagnostics
        )
    case .versionExchangeRequired:
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .versionExchangeRequired,
            message: "SFTP version exchange must complete before this operation can run.",
            diagnostics: diagnostics
        )
    case .channelClosedBeforePacket:
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .channelClosed,
            message: "The SFTP channel closed before the next packet arrived.",
            diagnostics: diagnostics
        )
    case let .invalidPacketLength(length):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "Encountered invalid SFTP packet length \(length).",
            diagnostics: diagnostics
        )
    case let .packetTooLarge(length, maximum):
        let diagnostics = SSHOperationFailureDiagnostics(
            metadata: metadata,
            snapshot: snapshot,
            localChannelID: localChannelID,
            remoteChannelID: remoteChannelID,
            requestType: fallbackRequestType,
            sftpStatus: nil
        )
        return SSHOperationFailure(
            scope: scope,
            code: .invalidProtocolMessage,
            message: "Encountered SFTP packet length \(length) above the supported maximum \(maximum).",
            diagnostics: diagnostics
        )
    }
}

private func remoteDisconnectMessage(
    from diagnostics: SSHOperationFailureDiagnostics,
    scope: SSHOperationFailureScope
) -> String {
    let operationName = operationDisplayName(scope)
    if let remoteDisconnect = diagnostics.remoteDisconnect {
        if remoteDisconnect.description.isEmpty {
            return "The server disconnected during \(operationName) with reason code \(remoteDisconnect.reasonCode)."
        }

        return "The server disconnected during \(operationName) with reason code \(remoteDisconnect.reasonCode): \(remoteDisconnect.description)"
    }

    return "The server disconnected during \(operationName)."
}

private func operationDisplayName(_ scope: SSHOperationFailureScope) -> String {
    switch scope {
    case .session:
        return "a session operation"
    case .directTCPIPChannel:
        return "a direct-tcpip channel operation"
    case .directStreamLocalChannel:
        return "a direct-streamlocal channel operation"
    case .forwardedTCPIPChannel:
        return "a forwarded-tcpip channel operation"
    case .forwardedStreamLocalChannel:
        return "a forwarded-streamlocal channel operation"
    case .remotePortForwardListener:
        return "remote port-forward listener accept"
    case .remoteStreamLocalForwardListener:
        return "remote streamlocal-forward listener accept"
    case .localPortForward:
        return "local port forwarding"
    case .remotePortForward:
        return "remote port forwarding"
    case .sftp:
        return "an SFTP operation"
    }
}

private func channelOpenFailureMessage(_ failure: SSHChannelOpenFailureMessage) -> String {
    let reason = channelOpenFailureReasonName(failure.reasonCode)
    if failure.description.isEmpty {
        return "The server rejected SSH channel open for local channel \(failure.recipientChannel) with reason \(reason) (\(failure.reasonCode.rawValue))."
    }

    return "The server rejected SSH channel open for local channel \(failure.recipientChannel) with reason \(reason) (\(failure.reasonCode.rawValue)): \(failure.description)"
}

private func channelOpenFailureReasonName(
    _ reasonCode: SSHChannelOpenFailureReasonCode
) -> String {
    switch reasonCode {
    case .administrativelyProhibited:
        return "administratively-prohibited"
    case .connectFailed:
        return "connect-failed"
    case .unknownChannelType:
        return "unknown-channel-type"
    case .resourceShortage:
        return "resource-shortage"
    default:
        return "unknown"
    }
}

private func transportMessageName(_ messageID: SSHTransportMessageID) -> String {
    switch messageID {
    case .disconnect:
        return "disconnect"
    case .ignore:
        return "ignore"
    case .unimplemented:
        return "unimplemented"
    case .debug:
        return "debug"
    case .serviceRequest:
        return "service-request"
    case .serviceAccept:
        return "service-accept"
    case .extensionInfo:
        return "extension-info"
    case .keyExchangeInit:
        return "kexinit"
    case .newKeys:
        return "newkeys"
    case .keyExchangeECDHInit:
        return "kex-ecdh-init"
    case .keyExchangeECDHReply:
        return "kex-ecdh-reply"
    }
}

private func connectionMessageName(_ messageID: SSHConnectionMessageID) -> String {
    switch messageID {
    case .globalRequest:
        return "global-request"
    case .requestSuccess:
        return "request-success"
    case .requestFailure:
        return "request-failure"
    case .channelOpen:
        return "channel-open"
    case .channelOpenConfirmation:
        return "channel-open-confirmation"
    case .channelOpenFailure:
        return "channel-open-failure"
    case .channelWindowAdjust:
        return "channel-window-adjust"
    case .channelData:
        return "channel-data"
    case .channelExtendedData:
        return "channel-extended-data"
    case .channelEOF:
        return "channel-eof"
    case .channelClose:
        return "channel-close"
    case .channelRequest:
        return "channel-request"
    case .channelSuccess:
        return "channel-success"
    case .channelFailure:
        return "channel-failure"
    }
}

private func sftpMessageName(_ messageID: SSHSFTPMessageID) -> String {
    switch messageID {
    case .initialize:
        return "init"
    case .openFile:
        return "open"
    case .close:
        return "close"
    case .version:
        return "version"
    case .readFile:
        return "read"
    case .writeFile:
        return "write"
    case .lstat:
        return "lstat"
    case .fstat:
        return "fstat"
    case .setstat:
        return "setstat"
    case .fsetstat:
        return "fsetstat"
    case .removeFile:
        return "remove"
    case .makeDirectory:
        return "mkdir"
    case .removeDirectory:
        return "rmdir"
    case .openDirectory:
        return "opendir"
    case .readDirectory:
        return "readdir"
    case .realPath:
        return "realpath"
    case .stat:
        return "stat"
    case .rename:
        return "rename"
    case .readLink:
        return "readlink"
    case .symbolicLink:
        return "symlink"
    case .status:
        return "status"
    case .handle:
        return "handle"
    case .data:
        return "data"
    case .name:
        return "name"
    case .attributes:
        return "attrs"
    case .extended:
        return "extended"
    case .extendedReply:
        return "extended-reply"
    }
}

private func authenticationMessageName(
    _ messageID: SSHUserAuthenticationMessageID
) -> String {
    switch messageID {
    case .request:
        return "request"
    case .failure:
        return "failure"
    case .success:
        return "success"
    case .banner:
        return "banner"
    case .passwordChangeRequest:
        return "password-change-request"
    }
}

private func sftpStatusMessage(from statusMessage: SSHSFTPStatusMessage) -> String {
    let message = statusMessage.errorMessage?.trimmingCharacters(
        in: .whitespacesAndNewlines
    )
    if let message, !message.isEmpty {
        return "The SFTP server returned status \(statusMessage.statusCode.rawValue): \(message)"
    }

    return "The SFTP server returned status \(statusMessage.statusCode.rawValue)."
}

private func message(for error: SSHWireError) -> String {
    switch error {
    case let .insufficientBytes(expected, remaining):
        return "A wire payload ended early: expected \(expected) bytes but only \(remaining) remained."
    case let .invalidBoolean(value):
        return "Encountered invalid SSH boolean value \(value)."
    case .invalidUTF8String:
        return "Encountered an invalid UTF-8 string in SSH wire data."
    case .invalidNameList:
        return "Encountered an invalid SSH name-list in wire data."
    case .invalidMPInt:
        return "Encountered an invalid SSH mpint value."
    case let .unknownMessageType(messageType):
        return "Encountered unknown SSH message type \(messageType)."
    case let .trailingMessageBytes(byteCount):
        return "Encountered \(byteCount) trailing bytes after parsing an SSH message."
    case let .invalidKeyExchangeCookieLength(length):
        return "Encountered invalid SSH key-exchange cookie length \(length)."
    case let .emptyRequiredNameList(field):
        return "Encountered empty required SSH name-list field \(field)."
    case .identificationTooLong:
        return "The SSH identification line exceeded the supported maximum length."
    case .invalidIdentification:
        return "Encountered an invalid SSH identification line."
    case let .unsupportedProtocolVersion(version):
        return "The peer advertised unsupported SSH protocol version \(version)."
    case .unexpectedPreIdentificationLine:
        return "Encountered an unexpected pre-identification line after the SSH identification."
    case let .invalidPacketLength(length):
        return "Encountered invalid SSH packet length \(length)."
    case let .invalidPacketPadding(padding):
        return "Encountered invalid SSH packet padding length \(padding)."
    case let .packetTooLarge(length):
        return "Encountered SSH packet length \(length) above the supported maximum."
    }
}
