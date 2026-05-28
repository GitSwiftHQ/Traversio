// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Network

/// Connection setup stage where a failure occurred.
public enum SSHConnectionFailureStage: String, Equatable, Sendable {
    /// Configuration.
    case configuration
    /// Transport.
    case transport
    /// Identification.
    case identification
    /// key exchange.
    case keyExchange
    /// host key Verification.
    case hostKeyVerification
    /// host key Trust.
    case hostKeyTrust
    /// Authentication.
    case authentication
}

/// Stable connection failure code for app branching and support reports.
public enum SSHConnectionFailureCode: String, Equatable, Sendable {
    /// Invalid Configuration.
    case invalidConfiguration
    /// Invalid Authentication Material.
    case invalidAuthenticationMaterial
    /// Callback Failed.
    case callbackFailed
    /// No Matching Known Host.
    case noMatchingKnownHost
    /// Timeout.
    case timeout
    /// Transport Closed.
    case transportClosed
    /// Transport Error.
    case transportError
    /// Unexpected transport message.
    case unexpectedTransportMessage
    /// Remote Disconnect.
    case remoteDisconnect
    /// Algorithm Negotiation Failed.
    case algorithmNegotiationFailed
    /// key exchange Failed.
    case keyExchangeFailed
    /// Key Derivation Failed.
    case keyDerivationFailed
    /// host key Verification Failed.
    case hostKeyVerificationFailed
    /// host key Trust Failed.
    case hostKeyTrustFailed
    /// Authentication Protocol Violation.
    case authenticationProtocolViolation
    /// Unexpected Authentication Message.
    case unexpectedAuthenticationMessage
    /// Unexpected Service Response.
    case unexpectedServiceResponse
}

/// App callback category that produced a connection setup failure.
public enum SSHConnectionFailureCallbackSource: String, Equatable, Sendable {
    /// host key Policy.
    case hostKeyPolicy
    /// Password Change Response.
    case passwordChangeResponse
    /// keyboard-interactive Response.
    case keyboardInteractiveResponse
    /// public key Signature.
    case publicKeySignature
}

/// Safe callback-failure details copied from app-thrown errors.
public struct SSHConnectionFailureCallbackDetails: Equatable, Sendable {
    /// Source of the value.
    public let source: SSHConnectionFailureCallbackSource
    /// Error Type.
    public let errorType: String
    /// Diagnostic Code.
    public let diagnosticCode: String?
    /// Diagnostic Summary.
    public let diagnosticSummary: String?
}

/// Algorithms negotiated for one SSH transport connection.
public struct SSHNegotiatedTransportAlgorithms: Equatable, Sendable {
    /// key exchange Algorithm.
    public let keyExchangeAlgorithm: String
    /// Server host key Algorithm.
    public let serverHostKeyAlgorithm: String
    /// Encryption Algorithm Client To Server.
    public let encryptionAlgorithmClientToServer: String
    /// Encryption Algorithm Server To Client.
    public let encryptionAlgorithmServerToClient: String
    /// MAC Algorithm Client To Server.
    public let macAlgorithmClientToServer: String
    /// MAC Algorithm Server To Client.
    public let macAlgorithmServerToClient: String
    /// Compression Algorithm Client To Server.
    public let compressionAlgorithmClientToServer: String
    /// Compression Algorithm Server To Client.
    public let compressionAlgorithmServerToClient: String
    /// Uses Strict key exchange.
    public let usesStrictKeyExchange: Bool
    /// Effective Integrity Algorithm Client To Server.

    public var effectiveIntegrityAlgorithmClientToServer: String {
        SSHTransportProtocolNegotiatedAlgorithmsSnapshot.effectiveIntegrityAlgorithm(
            encryptionAlgorithm: self.encryptionAlgorithmClientToServer,
            macAlgorithm: self.macAlgorithmClientToServer
        )
    }
    /// Effective Integrity Algorithm Server To Client.

    public var effectiveIntegrityAlgorithmServerToClient: String {
        SSHTransportProtocolNegotiatedAlgorithmsSnapshot.effectiveIntegrityAlgorithm(
            encryptionAlgorithm: self.encryptionAlgorithmServerToClient,
            macAlgorithm: self.macAlgorithmServerToClient
        )
    }
}

/// SSH disconnect message sent by the remote peer.
public struct SSHRemoteDisconnect: Equatable, Sendable {
    /// Reason Code.
    public let reasonCode: UInt32
    /// Description.
    public let description: String
    /// Server-provided language tag.
    public let languageTag: String
}

/// SSH debug message sent by the remote peer.
public struct SSHRemoteDebugMessage: Equatable, Sendable {
    /// Always Display.
    public let alwaysDisplay: Bool
    /// Diagnostic or server-provided message.
    public let message: String
    /// Server-provided language tag.
    public let languageTag: String
}

/// Diagnostic context captured when connection setup fails.
public struct SSHConnectionFailureDiagnostics: Equatable, Sendable {
    /// Endpoint host name or address.
    public let endpointHost: String
    /// Endpoint port number.
    public let endpointPort: UInt16
    /// SSH username.
    public let username: String
    /// client identification.
    public let clientIdentification: String
    /// remote identification.
    public let remoteIdentification: String?
    /// pre-identification Lines.
    public let preIdentificationLines: [String]
    /// Callback Failure.
    public let callbackFailure: SSHConnectionFailureCallbackDetails?
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
    /// Server Signature Algorithms.
    public let serverSignatureAlgorithms: [String]?
    /// Remote Disconnect.
    public let remoteDisconnect: SSHRemoteDisconnect?
    /// remote debug Messages.
    public let remoteDebugMessages: [SSHRemoteDebugMessage]
}

/// Structured connection setup failure returned through
/// `SSHClientError.connectionFailed`.
public struct SSHConnectionFailure: Equatable, Sendable {
    /// Stage.
    public let stage: SSHConnectionFailureStage
    /// Code.
    public let code: SSHConnectionFailureCode
    /// Diagnostic or server-provided message.
    public let message: String
    /// Structured diagnostic context.
    public let diagnostics: SSHConnectionFailureDiagnostics
}

extension SSHNegotiatedTransportAlgorithms {
    init(snapshot: SSHTransportProtocolNegotiatedAlgorithmsSnapshot) {
        self.keyExchangeAlgorithm = snapshot.keyExchangeAlgorithm
        self.serverHostKeyAlgorithm = snapshot.serverHostKeyAlgorithm
        self.encryptionAlgorithmClientToServer = snapshot.encryptionAlgorithmClientToServer
        self.encryptionAlgorithmServerToClient = snapshot.encryptionAlgorithmServerToClient
        self.macAlgorithmClientToServer = snapshot.macAlgorithmClientToServer
        self.macAlgorithmServerToClient = snapshot.macAlgorithmServerToClient
        self.compressionAlgorithmClientToServer = snapshot.compressionAlgorithmClientToServer
        self.compressionAlgorithmServerToClient = snapshot.compressionAlgorithmServerToClient
        self.usesStrictKeyExchange = snapshot.usesStrictKeyExchange
    }
}

extension SSHRemoteDisconnect {
    init(snapshot: SSHTransportProtocolRemoteDisconnectSnapshot) {
        self.reasonCode = snapshot.reasonCode
        self.description = snapshot.description
        self.languageTag = snapshot.languageTag
    }
}

extension SSHRemoteDebugMessage {
    init(snapshot: SSHTransportProtocolRemoteDebugSnapshot) {
        self.alwaysDisplay = snapshot.alwaysDisplay
        self.message = snapshot.message
        self.languageTag = snapshot.languageTag
    }
}

extension SSHConnectionFailureDiagnostics {
    init(
        endpoint: SSHSocketEndpoint,
        username: String,
        snapshot: SSHTransportProtocolDiagnosticsSnapshot,
        callbackFailure: SSHConnectionFailureCallbackDetails? = nil
    ) {
        self.endpointHost = endpoint.host
        self.endpointPort = endpoint.port
        self.username = username
        self.clientIdentification = snapshot.clientIdentification
        self.remoteIdentification = snapshot.remoteIdentification
        self.preIdentificationLines = snapshot.preIdentificationLines
        self.callbackFailure = callbackFailure
        self.keepaliveIntervalNanoseconds = snapshot.keepaliveIntervalNanoseconds
        self.keepaliveReplyTimeoutNanoseconds = snapshot.keepaliveReplyTimeoutNanoseconds
        self.responseTimeoutNanoseconds = snapshot.responseTimeoutNanoseconds
        self.negotiatedAlgorithms = snapshot.negotiatedAlgorithms.map {
            SSHNegotiatedTransportAlgorithms(snapshot: $0)
        }
        self.didReceiveServerExtensionInfo = snapshot.didReceiveServerExtensionInfo
        self.serverExtensionNames = snapshot.serverExtensionNames
        self.serverSignatureAlgorithms = snapshot.serverSignatureAlgorithms
        self.remoteDisconnect = snapshot.remoteDisconnect.map {
            SSHRemoteDisconnect(snapshot: $0)
        }
        self.remoteDebugMessages = snapshot.remoteDebugMessages.map {
            SSHRemoteDebugMessage(snapshot: $0)
        }
    }
}
extension SSHClient {
    static func wrapConnectionFailure(
        _ error: Error,
        endpoint: SSHSocketEndpoint,
        username: String,
        snapshot: SSHTransportProtocolDiagnosticsSnapshot
    ) -> SSHConnectionFailure? {
        let diagnostics = SSHConnectionFailureDiagnostics(
            endpoint: endpoint,
            username: username,
            snapshot: snapshot
        )

        switch error {
        case let error as SSHTimeoutError:
            return SSHConnectionFailure(
                stage: self.stage(for: error, phase: snapshot.phase),
                code: .timeout,
                message: error.message,
                diagnostics: diagnostics
            )
        case let error as SSHKnownHostsError:
            switch error {
            case let .noMatchingHostKey(missingEndpoint):
                return SSHConnectionFailure(
                    stage: .configuration,
                    code: .noMatchingKnownHost,
                    message: "No known_hosts entry matched \(missingEndpoint.host):\(missingEndpoint.port).",
                    diagnostics: diagnostics
                )
            }
        case let error as SSHEd25519PublicKeyAuthenticationError:
            return SSHConnectionFailure(
                stage: .configuration,
                code: .invalidAuthenticationMaterial,
                message: self.message(for: error),
                diagnostics: diagnostics
            )
        case let error as SSHRSAPrivateKeyError:
            return SSHConnectionFailure(
                stage: .configuration,
                code: .invalidAuthenticationMaterial,
                message: self.message(for: error),
                diagnostics: diagnostics
            )
        case let error as SSHECDSAPrivateKeyError:
            return SSHConnectionFailure(
                stage: .configuration,
                code: .invalidAuthenticationMaterial,
                message: self.message(for: error),
                diagnostics: diagnostics
            )
        case let error as SSHUserCallbackFailure:
            return SSHConnectionFailure(
                stage: self.stage(for: error),
                code: .callbackFailed,
                message: self.message(for: error),
                diagnostics: SSHConnectionFailureDiagnostics(
                    endpoint: endpoint,
                    username: username,
                    snapshot: snapshot,
                    callbackFailure: SSHConnectionFailureCallbackDetails(
                        callbackFailure: error
                    )
                )
            )
        case let error as SSHTransportError:
            return self.wrapTransportError(
                error,
                diagnostics: diagnostics,
                snapshot: snapshot
            )
        case let error as SSHWireError:
            return SSHConnectionFailure(
                stage: self.stage(for: snapshot.phase),
                code: .transportError,
                message: self.message(for: error),
                diagnostics: diagnostics
            )
        case let error as SSHAlgorithmNegotiationError:
            return SSHConnectionFailure(
                stage: .keyExchange,
                code: .algorithmNegotiationFailed,
                message: self.message(for: error),
                diagnostics: diagnostics
            )
        case let error as SSHCurve25519KeyExchangeError:
            return SSHConnectionFailure(
                stage: .keyExchange,
                code: .keyExchangeFailed,
                message: self.message(for: error),
                diagnostics: diagnostics
            )
        case let error as SSHTransportKeyDerivationError:
            return SSHConnectionFailure(
                stage: .keyExchange,
                code: .keyDerivationFailed,
                message: self.message(for: error),
                diagnostics: diagnostics
            )
        case let error as SSHHostKeyVerificationError:
            return SSHConnectionFailure(
                stage: .hostKeyVerification,
                code: .hostKeyVerificationFailed,
                message: self.message(for: error),
                diagnostics: diagnostics
            )
        case let error as SSHHostKeyTrustError:
            return SSHConnectionFailure(
                stage: .hostKeyTrust,
                code: .hostKeyTrustFailed,
                message: self.message(for: error),
                diagnostics: diagnostics
            )
        case let error as SSHUserAuthenticationError:
            return self.wrapAuthenticationError(
                error,
                diagnostics: diagnostics
            )
        case let error as CocoaError:
            return SSHConnectionFailure(
                stage: .configuration,
                code: .invalidConfiguration,
                message: error.localizedDescription,
                diagnostics: diagnostics
            )
        case let error as NWError:
            return SSHConnectionFailure(
                stage: .transport,
                code: .transportError,
                message: String(describing: error),
                diagnostics: diagnostics
            )
        case let error as POSIXError:
            return SSHConnectionFailure(
                stage: .transport,
                code: .transportError,
                message: String(describing: error),
                diagnostics: diagnostics
            )
        default:
            let nsError = error as NSError
            if nsError.domain == NSPOSIXErrorDomain {
                return SSHConnectionFailure(
                    stage: .transport,
                    code: .transportError,
                    message: nsError.localizedDescription,
                    diagnostics: diagnostics
                )
            }
            return nil
        }
    }

    private static func wrapTransportError(
        _ error: SSHTransportError,
        diagnostics: SSHConnectionFailureDiagnostics,
        snapshot: SSHTransportProtocolDiagnosticsSnapshot
    ) -> SSHConnectionFailure {
        switch error {
        case let .invalidPort(port):
            return SSHConnectionFailure(
                stage: .transport,
                code: .invalidConfiguration,
                message: "Invalid TCP port \(port).",
                diagnostics: diagnostics
            )
        case let .invalidProxyConfiguration(details):
            return SSHConnectionFailure(
                stage: .configuration,
                code: .invalidConfiguration,
                message: details,
                diagnostics: diagnostics
            )
        case let .invalidSOCKSConfiguration(details):
            return SSHConnectionFailure(
                stage: .configuration,
                code: .invalidConfiguration,
                message: details,
                diagnostics: diagnostics
            )
        case let .proxyHandshakeFailed(details):
            return SSHConnectionFailure(
                stage: .transport,
                code: .transportError,
                message: "Connection proxy handshake failed: \(details)",
                diagnostics: diagnostics
            )
        case let .socksHandshakeFailed(details):
            return SSHConnectionFailure(
                stage: .transport,
                code: .transportError,
                message: "SOCKS handshake failed: \(details)",
                diagnostics: diagnostics
            )
        case let .unsupportedTransportBackend(details):
            return SSHConnectionFailure(
                stage: .configuration,
                code: .invalidConfiguration,
                message: details,
                diagnostics: diagnostics
            )
        case .transportClosed:
            return SSHConnectionFailure(
                stage: self.stage(for: snapshot.phase),
                code: .transportClosed,
                message: "The local transport was closed before the operation completed.",
                diagnostics: diagnostics
            )
        case .emptyReceive:
            return SSHConnectionFailure(
                stage: .transport,
                code: .transportError,
                message: "The transport returned an empty read without signaling EOF.",
                diagnostics: diagnostics
            )
        case .endOfStreamBeforeIdentification:
            return SSHConnectionFailure(
                stage: .identification,
                code: .transportClosed,
                message: "The remote peer closed the byte stream before sending an SSH identification line.",
                diagnostics: diagnostics
            )
        case .endOfStreamBeforePacket:
            return SSHConnectionFailure(
                stage: self.stage(for: snapshot.phase),
                code: .transportClosed,
                message: "The remote peer closed the byte stream before sending the next SSH packet.",
                diagnostics: diagnostics
            )
        case let .strictKeyExchangeViolation(details):
            return SSHConnectionFailure(
                stage: self.stage(for: snapshot.phase),
                code: .unexpectedTransportMessage,
                message: "Strict key exchange violation: \(details)",
                diagnostics: diagnostics
            )
        case let .unexpectedTransportMessage(expected, received):
            if received == .disconnect, diagnostics.remoteDisconnect != nil {
                return SSHConnectionFailure(
                    stage: self.stage(for: snapshot.phase),
                    code: .remoteDisconnect,
                    message: self.remoteDisconnectMessage(from: diagnostics),
                    diagnostics: diagnostics
                )
            }

            return SSHConnectionFailure(
                stage: self.stage(for: snapshot.phase),
                code: .unexpectedTransportMessage,
                message: "Expected SSH transport message \(self.transportMessageName(expected)), but received \(self.transportMessageName(received)).",
                diagnostics: diagnostics
            )
        case let .unsupportedEndpoint(endpoint):
            return SSHConnectionFailure(
                stage: .transport,
                code: .invalidConfiguration,
                message: "Unsupported endpoint value: \(endpoint).",
                diagnostics: diagnostics
            )
        case .listenerDidNotReportPort:
            return SSHConnectionFailure(
                stage: .transport,
                code: .transportError,
                message: "The local listener did not report its bound port.",
                diagnostics: diagnostics
            )
        case let .internalInvariantBroken(details):
            return SSHConnectionFailure(
                stage: .transport,
                code: .transportError,
                message: details,
                diagnostics: diagnostics
            )
        case .versionExchangeRequired:
            return SSHConnectionFailure(
                stage: self.stage(for: snapshot.phase),
                code: .transportError,
                message: "A transport operation ran before version exchange completed.",
                diagnostics: diagnostics
            )
        }
    }

    private static func wrapAuthenticationError(
        _ error: SSHUserAuthenticationError,
        diagnostics: SSHConnectionFailureDiagnostics
    ) -> SSHConnectionFailure {
        switch error {
        case .confidentialTransportRequired:
            return SSHConnectionFailure(
                stage: .authentication,
                code: .authenticationProtocolViolation,
                message: "User authentication started before an encrypted transport was active.",
                diagnostics: diagnostics
            )
        case .sessionIdentifierRequired:
            return SSHConnectionFailure(
                stage: .authentication,
                code: .authenticationProtocolViolation,
                message: "Public-key authentication required a session identifier before it was available.",
                diagnostics: diagnostics
            )
        case .publicKeyConfirmationMismatch:
            return SSHConnectionFailure(
                stage: .authentication,
                code: .authenticationProtocolViolation,
                message: "The server confirmed a different public key than the one the client offered.",
                diagnostics: diagnostics
            )
        case let .unexpectedServiceAccept(expected, received):
            return SSHConnectionFailure(
                stage: .authentication,
                code: .unexpectedServiceResponse,
                message: "Expected service accept for \(expected), but the server accepted \(received).",
                diagnostics: diagnostics
            )
        case let .unexpectedTransportMessage(messageID):
            if messageID == .disconnect, diagnostics.remoteDisconnect != nil {
                return SSHConnectionFailure(
                    stage: .authentication,
                    code: .remoteDisconnect,
                    message: self.remoteDisconnectMessage(from: diagnostics),
                    diagnostics: diagnostics
                )
            }

            return SSHConnectionFailure(
                stage: .authentication,
                code: .unexpectedTransportMessage,
                message: "Received unexpected SSH transport message \(self.transportMessageName(messageID)) during user authentication.",
                diagnostics: diagnostics
            )
        case let .unexpectedAuthenticationMessage(messageID):
            return SSHConnectionFailure(
                stage: .authentication,
                code: .unexpectedAuthenticationMessage,
                message: "Received unexpected SSH userauth message \(self.authenticationMessageName(messageID)).",
                diagnostics: diagnostics
            )
        case let .unexpectedPostAuthenticationMessage(messageID):
            return SSHConnectionFailure(
                stage: .authentication,
                code: .authenticationProtocolViolation,
                message: "Received unexpected SSH packet \(messageID) while waiting for a userauth response.",
                diagnostics: diagnostics
            )
        }
    }

    private static func stage(
        for timeoutError: SSHTimeoutError,
        phase: SSHTransportProtocolSetupPhase
    ) -> SSHConnectionFailureStage {
        switch timeoutError {
        case .hostKeyTrust:
            return .hostKeyTrust
        default:
            return self.stage(for: phase)
        }
    }

    private static func stage(
        for callbackFailure: SSHUserCallbackFailure
    ) -> SSHConnectionFailureStage {
        switch callbackFailure.source {
        case .hostKeyPolicy:
            return .hostKeyTrust
        case .passwordChangeResponse:
            return .authentication
        case .keyboardInteractiveResponse:
            return .authentication
        case .publicKeySignature:
            return .authentication
        }
    }

    private static func stage(
        for phase: SSHTransportProtocolSetupPhase
    ) -> SSHConnectionFailureStage {
        switch phase {
        case .identification:
            return .identification
        case .keyExchange:
            return .keyExchange
        case .authentication, .authenticated:
            return .authentication
        }
    }

    private static func remoteDisconnectMessage(
        from diagnostics: SSHConnectionFailureDiagnostics
    ) -> String {
        if let remoteDisconnect = diagnostics.remoteDisconnect {
            if remoteDisconnect.description.isEmpty {
                return "The server disconnected during connection setup with reason code \(remoteDisconnect.reasonCode)."
            }

            return "The server disconnected during connection setup with reason code \(remoteDisconnect.reasonCode): \(remoteDisconnect.description)"
        }

        return "The server disconnected during connection setup."
    }

    private static func transportMessageName(_ messageID: SSHTransportMessageID) -> String {
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

    private static func authenticationMessageName(
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

    private static func message(for error: SSHWireError) -> String {
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

    private static func message(for error: SSHUserCallbackFailure) -> String {
        switch error.source {
        case .hostKeyPolicy:
            return "The custom host-key policy callback failed with error type \(error.errorType)."
        case .passwordChangeResponse:
            return "The password-change response callback failed with error type \(error.errorType)."
        case .keyboardInteractiveResponse:
            return "The keyboard-interactive response callback failed with error type \(error.errorType)."
        case .publicKeySignature:
            return "The public-key signature callback failed with error type \(error.errorType)."
        }
    }

    private static func message(for error: SSHAlgorithmNegotiationError) -> String {
        switch error {
        case let .noCommonAlgorithm(category):
            return "The client and server had no common \(category.rawValue) algorithm."
        }
    }

    private static func message(for error: SSHCurve25519KeyExchangeError) -> String {
        switch error {
        case let .unsupportedKeyExchangeAlgorithm(algorithm):
            return "The negotiated key-exchange algorithm \(algorithm) is not implemented."
        case let .invalidRemotePublicKeyLength(length):
            return "The server sent an invalid key-exchange public-key length \(length)."
        case .invalidRemotePublicKey:
            return "The server sent an invalid key-exchange public key."
        case .allZeroSharedSecret:
            return "The Curve25519 key exchange produced an all-zero shared secret."
        }
    }

    private static func message(for error: SSHTransportKeyDerivationError) -> String {
        switch error {
        case let .unsupportedKeyExchangeAlgorithm(algorithm):
            return "Transport key derivation does not support key-exchange algorithm \(algorithm)."
        case let .unsupportedEncryptionAlgorithm(algorithm):
            return "Transport key derivation does not support encryption algorithm \(algorithm)."
        case let .unsupportedMACAlgorithm(algorithm):
            return "Transport key derivation does not support MAC algorithm \(algorithm)."
        }
    }

    private static func message(for error: SSHHostKeyVerificationError) -> String {
        switch error {
        case let .unsupportedHostKeyAlgorithm(algorithm):
            return "The server host-key algorithm \(algorithm) is not supported."
        case let .unsupportedSignatureAlgorithm(algorithm):
            return "The server host-key signature algorithm \(algorithm) is not supported."
        case let .unsupportedCertificateAuthorityAlgorithm(algorithm):
            return "The server host certificate uses unsupported CA algorithm \(algorithm)."
        case let .hostKeyAlgorithmMismatch(expected, received):
            return "Expected server host-key algorithm \(expected), but received \(received)."
        case let .signatureAlgorithmMismatch(expected, received):
            return "Expected server signature algorithm \(expected), but received \(received)."
        case let .invalidEd25519PublicKeyLength(length):
            return "The server sent an invalid Ed25519 host-key length \(length)."
        case let .invalidEd25519SignatureLength(length):
            return "The server sent an invalid Ed25519 signature length \(length)."
        case .invalidEd25519PublicKey:
            return "The server sent an invalid Ed25519 host key."
        case let .invalidECDSACurveName(expected, received):
            return "Expected ECDSA curve \(expected), but the server sent \(received)."
        case .invalidECDSAPublicKey:
            return "The server sent an invalid ECDSA host key."
        case .invalidECDSASignature:
            return "The server sent an invalid ECDSA signature."
        case .invalidRSAPublicKey:
            return "The server sent an invalid RSA host key."
        case .invalidHostCertificate:
            return "The server sent an invalid host certificate."
        case let .invalidHostCertificateType(certificateType):
            return "The server sent a non-host OpenSSH certificate of type \(certificateType)."
        case .invalidHostCertificateAuthorityKey:
            return "The server host certificate included an invalid certificate-authority key."
        case .invalidHostCertificateSignature:
            return "The server host certificate signature did not validate."
        case .invalidSignature:
            return "The server host-key signature did not validate."
        }
    }

    private static func message(for error: SSHHostKeyTrustError) -> String {
        switch error {
        case let .invalidHostCertificate(receivedAlgorithmName, reason, _):
            switch reason {
            case let .notYetValid(validAfter):
                return "The server host certificate \(receivedAlgorithmName) is not valid before \(self.certificateTimestampDescription(validAfter))."
            case let .expired(validBefore):
                return "The server host certificate \(receivedAlgorithmName) expired at \(self.certificateTimestampDescription(validBefore))."
            case .missingPrincipals:
                return "The server host certificate \(receivedAlgorithmName) does not include any valid principals."
            case .missingRemoteEndpoint:
                return "The server host certificate \(receivedAlgorithmName) could not be matched because the remote endpoint host is unavailable."
            case let .principalMismatch(expectedHost, principals):
                let principalList = principals.joined(separator: ", ")
                return "The server host certificate \(receivedAlgorithmName) does not permit host \(expectedHost). Presented principals: \(principalList)."
            }
        case let .hostCertificateAuthorityRevoked(
            receivedAlgorithmName,
            certificateAuthorityAlgorithmName,
            certificateAuthorityFingerprintSHA256,
            _,
            _
        ):
            return "The server host certificate \(receivedAlgorithmName) was signed by revoked certificate authority \(certificateAuthorityAlgorithmName) \(certificateAuthorityFingerprintSHA256)."
        case let .hostCertificateAuthorityNotTrusted(
            receivedAlgorithmName,
            certificateAuthorityAlgorithmName,
            certificateAuthorityFingerprintSHA256,
            trustedCertificateAuthorities,
            _
        ):
            return "The server host certificate \(receivedAlgorithmName) was signed by untrusted certificate authority \(certificateAuthorityAlgorithmName) \(certificateAuthorityFingerprintSHA256). Trusted certificate-authority candidate count: \(trustedCertificateAuthorities.count)."
        case let .mismatchedHostKey(
            expectedAlgorithmName,
            receivedAlgorithmName,
            expectedFingerprintSHA256,
            receivedFingerprintSHA256,
            _
        ):
            return "Expected trusted host key \(expectedAlgorithmName) \(expectedFingerprintSHA256), but received \(receivedAlgorithmName) \(receivedFingerprintSHA256)."
        case let .hostKeyRevoked(
            receivedAlgorithmName,
            receivedFingerprintSHA256,
            _,
            _
        ):
            return "The received host key \(receivedAlgorithmName) \(receivedFingerprintSHA256) is revoked."
        case let .hostKeyNotTrusted(
            receivedAlgorithmName,
            receivedFingerprintSHA256,
            trustedHostKeys,
            _
        ):
            return "The received host key \(receivedAlgorithmName) \(receivedFingerprintSHA256) did not match any trusted key out of \(trustedHostKeys.count) candidate(s)."
        }
    }

    private static func certificateTimestampDescription(_ timestamp: UInt64) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(
            from: Date(timeIntervalSince1970: TimeInterval(timestamp))
        )
    }

    private static func message(for error: SSHEd25519PublicKeyAuthenticationError) -> String {
        switch error {
        case let .invalidPrivateKeyLength(length):
            return "The Ed25519 private key must be 32 bytes, but received \(length)."
        case .invalidPrivateKey:
            return "The Ed25519 private key bytes are invalid."
        }
    }

    private static func message(for error: SSHRSAPrivateKeyError) -> String {
        switch error {
        case .invalidPKCS1PrivateKey:
            return "The RSA private key is not valid PKCS#1 DER."
        case .invalidRSAPrivateKey:
            return "The RSA private key could not be loaded."
        case let .unsupportedSignatureAlgorithm(algorithm):
            return "The RSA private key does not support signature algorithm \(algorithm)."
        }
    }

    private static func message(for error: SSHECDSAPrivateKeyError) -> String {
        switch error {
        case .invalidP256PrivateKey:
            return "The P-256 private key bytes are invalid."
        case .invalidP384PrivateKey:
            return "The P-384 private key bytes are invalid."
        case .invalidP521PrivateKey:
            return "The P-521 private key bytes are invalid."
        }
    }
}

extension SSHConnectionFailureCallbackDetails {
    init(callbackFailure: SSHUserCallbackFailure) {
        self.source = SSHConnectionFailureCallbackSource(
            callbackFailureSource: callbackFailure.source
        )
        self.errorType = callbackFailure.errorType
        self.diagnosticCode = callbackFailure.diagnosticCode
        self.diagnosticSummary = callbackFailure.diagnosticSummary
    }
}

extension SSHConnectionFailureCallbackSource {
    init(callbackFailureSource: SSHUserCallbackFailureSource) {
        switch callbackFailureSource {
        case .hostKeyPolicy:
            self = .hostKeyPolicy
        case .passwordChangeResponse:
            self = .passwordChangeResponse
        case .keyboardInteractiveResponse:
            self = .keyboardInteractiveResponse
        case .publicKeySignature:
            self = .publicKeySignature
        }
    }
}
