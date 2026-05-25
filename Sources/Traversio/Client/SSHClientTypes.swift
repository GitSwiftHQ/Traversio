// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// Public errors thrown by high-level SSH client operations.
///
/// Use the associated diagnostic payloads for branching and support reports
/// instead of parsing the English `message` strings.
public enum SSHClientError: Error, Equatable, Sendable {
    /// All configured authentication methods were rejected by the server.
    case authenticationRejected(
        methodName: String,
        availableMethods: [String],
        partialSuccess: Bool,
        banners: [SSHAuthenticationBanner] = []
    )
    /// The server requires the user to change an expired password.
    case passwordChangeRequired(
        prompt: String,
        languageTag: String = "",
        banners: [SSHAuthenticationBanner] = []
    )
    /// The SSH connection failed before an authenticated session was available.
    case connectionFailed(SSHConnectionFailure)
    /// An operation on an established SSH connection failed.
    case operationFailed(SSHOperationFailure)
    /// The connection-scoped API was used after its lifetime ended.
    case connectionScopeEnded
}

/// Optional protocol for errors thrown by app-provided callbacks.
///
/// Conform host-key, password-change, keyboard-interactive, or public-key
/// callback errors to surface a stable diagnostic code in Traversio support
/// reports.
///
/// Example:
///
/// ```swift
/// enum TrustError: Error, SSHCallbackFailureDiagnosticProviding {
///     case userRejected
///
///     var sshCallbackFailureDiagnosticCode: String { "user-rejected-host-key" }
/// }
/// ```
public protocol SSHCallbackFailureDiagnosticProviding: Error, Sendable {
    /// Stable machine-readable code for the callback failure.
    var sshCallbackFailureDiagnosticCode: String { get }

    /// Optional human-readable summary for support diagnostics.
    var sshCallbackFailureDiagnosticSummary: String? { get }
}

public extension SSHCallbackFailureDiagnosticProviding {
    /// Default callback-failure summary used when conforming errors only provide a code.
    var sshCallbackFailureDiagnosticSummary: String? { nil }
}

enum SSHUserCallbackFailureSource: Sendable {
    case hostKeyPolicy
    case passwordChangeResponse
    case keyboardInteractiveResponse
    case publicKeySignature
}

struct SSHUserCallbackFailure: Error, Equatable, Sendable {
    let source: SSHUserCallbackFailureSource
    let errorType: String
    let diagnosticCode: String?
    let diagnosticSummary: String?

    init(source: SSHUserCallbackFailureSource, error: any Error) {
        self.source = source
        self.errorType = String(reflecting: type(of: error))
        if let diagnostic = error as? any SSHCallbackFailureDiagnosticProviding {
            self.diagnosticCode = diagnostic.sshCallbackFailureDiagnosticCode
            self.diagnosticSummary = diagnostic.sshCallbackFailureDiagnosticSummary
        } else {
            self.diagnosticCode = nil
            self.diagnosticSummary = nil
        }
    }
}

/// One prompt in an SSH keyboard-interactive authentication challenge.
public struct SSHKeyboardInteractivePrompt: Equatable, Sendable {
    /// Prompt text displayed to the user or credential provider.
    public let prompt: String

    /// Whether typed input is intended to be visible while answering the prompt.
    public let shouldEcho: Bool

    /// Creates a keyboard-interactive prompt value.
    public init(prompt: String, shouldEcho: Bool) {
        self.prompt = prompt
        self.shouldEcho = shouldEcho
    }
}

/// A keyboard-interactive authentication challenge sent by the server.
public struct SSHKeyboardInteractiveChallenge: Equatable, Sendable {
    /// SSH username.
    public let username: String

    /// SSH service name associated with the challenge.
    public let serviceName: String

    /// Server-provided challenge title.
    public let name: String

    /// Server-provided instructions displayed before the prompts.
    public let instruction: String

    /// Server-provided language tag.
    public let languageTag: String

    /// Prompts that must be answered in order.
    public let prompts: [SSHKeyboardInteractivePrompt]

    /// Creates a keyboard-interactive challenge value.
    public init(
        username: String,
        serviceName: String,
        name: String,
        instruction: String,
        languageTag: String,
        prompts: [SSHKeyboardInteractivePrompt]
    ) {
        self.username = username
        self.serviceName = serviceName
        self.name = name
        self.instruction = instruction
        self.languageTag = languageTag
        self.prompts = prompts
    }
}

/// A server request to change an expired password during password auth.
public struct SSHPasswordChangeChallenge: Equatable, Sendable {
    /// SSH username.
    public let username: String

    /// SSH service name associated with the challenge.
    public let serviceName: String

    /// Server-provided password-change prompt.
    public let prompt: String

    /// Server-provided language tag.
    public let languageTag: String

    /// Authentication banners sent by the server.
    public let banners: [SSHAuthenticationBanner]

    /// Creates a password-change challenge value.
    public init(
        username: String,
        serviceName: String,
        prompt: String,
        languageTag: String,
        banners: [SSHAuthenticationBanner] = []
    ) {
        self.username = username
        self.serviceName = serviceName
        self.prompt = prompt
        self.languageTag = languageTag
        self.banners = banners
    }
}

/// Data passed to a custom public-key signature provider.
///
/// Sign `signatureData` using the private key that matches `publicKey`, then
/// return `makeSignatureBlob(rawSignature:)`.
public struct SSHPublicKeyAuthenticationSigningRequest: Equatable, Sendable {
    /// SSH username.
    public let username: String

    /// SSH service name associated with the signature request.
    public let serviceName: String

    /// SSH algorithm name.
    public let algorithmName: String

    /// SSH public key bytes.
    public let publicKey: [UInt8]

    /// Exact bytes the SSH client is asking the private key to sign.
    public let signatureData: [UInt8]

    /// Creates a public-key signing request value.
    public init(
        username: String,
        serviceName: String,
        algorithmName: String,
        publicKey: [UInt8],
        signatureData: [UInt8]
    ) {
        self.username = username
        self.serviceName = serviceName
        self.algorithmName = algorithmName
        self.publicKey = publicKey
        self.signatureData = signatureData
    }

    /// Wraps a raw cryptographic signature in the SSH signature-blob format.
    public func makeSignatureBlob(rawSignature: [UInt8]) -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(utf8: self.algorithmName)
        writer.write(string: rawSignature)
        return writer.bytes
    }
}

/// Authentication method candidates for SSH user authentication.
///
/// `SSHClientConfiguration(authenticationMethods:)` tries candidates in order
/// on the same SSH userauth connection.
///
/// Example:
///
/// ```swift
/// let methods: [SSHAuthenticationMethod] = [
///     try .openSSHPrivateKey(contentsOfFile: "/Users/me/.ssh/id_ed25519"),
///     .password("fallback-password")
/// ]
/// ```
public enum SSHAuthenticationMethod: Sendable {
    /// Authenticate with a plain password.
    case password(String)

    /// Authenticate with a password and answer a server password-change request.
    case passwordWithChangeResponse(
        password: String,
        responseProvider: @Sendable (SSHPasswordChangeChallenge) async throws -> String
    )

    /// Authenticate with an Ed25519 private key raw representation.
    case ed25519PrivateKey(rawRepresentation: [UInt8])

    /// Authenticate with an RSA private key in PKCS#1 DER form.
    case rsaPrivateKey(pkcs1DERRepresentation: [UInt8])

    /// Authenticate with an ECDSA P-256 private key raw representation.
    case ecdsaP256PrivateKey(rawRepresentation: [UInt8])

    /// Authenticate with an ECDSA P-384 private key raw representation.
    case ecdsaP384PrivateKey(rawRepresentation: [UInt8])

    /// Authenticate with an ECDSA P-521 private key raw representation.
    case ecdsaP521PrivateKey(rawRepresentation: [UInt8])

    /// Authenticate with an app-provided public key and async signature provider.
    case publicKey(
        algorithmNames: [String],
        publicKey: [UInt8],
        signatureProvider: @Sendable (SSHPublicKeyAuthenticationSigningRequest) async throws -> [UInt8]
    )

    /// Authenticate by answering server-provided keyboard-interactive prompts.
    case keyboardInteractive(
        submethods: [String],
        responseProvider: @Sendable (SSHKeyboardInteractiveChallenge) async throws -> [String]
    )
}

extension SSHAuthenticationMethod: Equatable {
    public static func ==(lhs: SSHAuthenticationMethod, rhs: SSHAuthenticationMethod) -> Bool {
        switch (lhs, rhs) {
        case let (.password(lhsPassword), .password(rhsPassword)):
            return lhsPassword == rhsPassword
        case let (
            .passwordWithChangeResponse(password: lhsPassword, responseProvider: _),
            .passwordWithChangeResponse(password: rhsPassword, responseProvider: _)
        ):
            return lhsPassword == rhsPassword
        case let (
            .ed25519PrivateKey(rawRepresentation: lhsRawRepresentation),
            .ed25519PrivateKey(rawRepresentation: rhsRawRepresentation)
        ):
            return lhsRawRepresentation == rhsRawRepresentation
        case let (
            .rsaPrivateKey(pkcs1DERRepresentation: lhsRepresentation),
            .rsaPrivateKey(pkcs1DERRepresentation: rhsRepresentation)
        ):
            return lhsRepresentation == rhsRepresentation
        case let (
            .ecdsaP256PrivateKey(rawRepresentation: lhsRawRepresentation),
            .ecdsaP256PrivateKey(rawRepresentation: rhsRawRepresentation)
        ):
            return lhsRawRepresentation == rhsRawRepresentation
        case let (
            .ecdsaP384PrivateKey(rawRepresentation: lhsRawRepresentation),
            .ecdsaP384PrivateKey(rawRepresentation: rhsRawRepresentation)
        ):
            return lhsRawRepresentation == rhsRawRepresentation
        case let (
            .ecdsaP521PrivateKey(rawRepresentation: lhsRawRepresentation),
            .ecdsaP521PrivateKey(rawRepresentation: rhsRawRepresentation)
        ):
            return lhsRawRepresentation == rhsRawRepresentation
        case let (
            .publicKey(algorithmNames: lhsAlgorithms, publicKey: lhsPublicKey, signatureProvider: _),
            .publicKey(algorithmNames: rhsAlgorithms, publicKey: rhsPublicKey, signatureProvider: _)
        ):
            return lhsAlgorithms == rhsAlgorithms && lhsPublicKey == rhsPublicKey
        case let (
            .keyboardInteractive(submethods: lhsSubmethods, responseProvider: _),
            .keyboardInteractive(submethods: rhsSubmethods, responseProvider: _)
        ):
            return lhsSubmethods == rhsSubmethods
        default:
            return false
        }
    }
}

/// Controls Traversio-initiated SSH transport rekeying.
public struct SSHAutomaticRekeyPolicy: Equatable, Sendable {
    /// Outbound Packet Threshold.
    public let outboundPacketThreshold: UInt64?
    /// Inbound Packet Threshold.
    public let inboundPacketThreshold: UInt64?
    /// Idle time interval.
    public let idleTimeInterval: TimeInterval?
    /// Disabled.

    public static let disabled = Self(
        outboundPacketThreshold: nil,
        inboundPacketThreshold: nil,
        idleTimeInterval: nil
    )
    /// Current Profile Default.

    public static let currentProfileDefault = Self(
        outboundPacketThreshold: 1_048_576,
        inboundPacketThreshold: 1_048_576,
        idleTimeInterval: nil
    )
    /// Creates an SSHAutomaticRekeyPolicy.

    public init(
        outboundPacketThreshold: UInt64?,
        inboundPacketThreshold: UInt64?,
        idleTimeInterval: TimeInterval? = nil
    ) {
        precondition(
            idleTimeInterval == nil || (idleTimeInterval!.isFinite && idleTimeInterval! > 0),
            "idleTimeInterval must be a finite value greater than zero"
        )
        self.outboundPacketThreshold = outboundPacketThreshold
        self.inboundPacketThreshold = inboundPacketThreshold
        self.idleTimeInterval = idleTimeInterval
    }
}

/// Compression preference advertised during key exchange.
///
/// Compression is opt-in. `.delayedZlib` matches OpenSSH's
/// `zlib@openssh.com` behavior after authentication.
public enum SSHCompressionPreference: Equatable, Sendable {
    /// Disabled.
    case disabled
    /// Zlib.
    case zlib
    /// Delayed Zlib.
    case delayedZlib
}

/// Explicit compatibility switches for legacy algorithms.
///
/// Traversio does not silently enable legacy `ssh-rsa`; callers must opt in per
/// connection or jump host when they intentionally need that compatibility.
public struct SSHLegacyAlgorithmOptions: Equatable, Sendable {
    /// Allows SSHRSA.
    public let allowsSSHRSA: Bool
/// Disabled.

    /// Disabled.
    public static let disabled = Self(allowsSSHRSA: false)
    /// SSH RSA.
    public static let sshRSA = Self(allowsSSHRSA: true)
    /// Creates an SSHLegacyAlgorithmOptions.

    public init(allowsSSHRSA: Bool = false) {
        self.allowsSSHRSA = allowsSSHRSA
    }
}

/// Configuration for a final SSH target connection.
///
/// Example:
///
/// ```swift
/// let configuration = SSHClientConfiguration(
///     host: "server.example.com",
///     port: 22,
///     username: "deploy",
///     authentication: .password("secret"),
///     hostKeyPolicy: .knownHostsFile("/Users/me/.ssh/known_hosts")
/// )
/// ```
public struct SSHClientConfiguration: Equatable, Sendable {
    /// Host name or address.
    public let host: String
    /// Port number.
    public let port: UInt16
    /// SSH username.
    public let username: String
    /// Authentication candidates tried in order.
    public let authenticationMethods: [SSHAuthenticationMethod]
    /// Host-key verification policy.
    public let hostKeyPolicy: SSHHostKeyPolicy
    /// Compression preference.
    public let compressionPreference: SSHCompressionPreference
    /// Legacy algorithm compatibility options.
    public let legacyAlgorithmOptions: SSHLegacyAlgorithmOptions
    /// Automatic rekey policy.
    public let automaticRekeyPolicy: SSHAutomaticRekeyPolicy
    /// Keepalive policy.
    public let keepalivePolicy: SSHKeepalivePolicy
    /// Timeout policy.
    public let timeoutPolicy: SSHTimeoutPolicy
    /// First-hop connection proxy.
    public let connectionProxy: SSHConnectionProxy?
    /// ProxyJump hosts used before the final target.
    public let proxyJumpHosts: [SSHProxyJumpHost]

    /// Authentication setting.
    public var authentication: SSHAuthenticationMethod {
        self.authenticationMethods[0]
    }

    /// Creates an SSHClientConfiguration.
    public init(
        host: String,
        port: UInt16 = 22,
        username: String,
        authentication: SSHAuthenticationMethod,
        hostKeyPolicy: SSHHostKeyPolicy,
        compressionPreference: SSHCompressionPreference = .disabled,
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions = .disabled,
        automaticRekeyPolicy: SSHAutomaticRekeyPolicy = .currentProfileDefault,
        keepalivePolicy: SSHKeepalivePolicy = .disabled,
        timeoutPolicy: SSHTimeoutPolicy = .currentProfileDefault,
        connectionProxy: SSHConnectionProxy? = nil,
        proxyJumpHosts: [SSHProxyJumpHost] = []
    ) {
        self.init(
            host: host,
            port: port,
            username: username,
            authenticationMethods: [authentication],
            hostKeyPolicy: hostKeyPolicy,
            compressionPreference: compressionPreference,
            legacyAlgorithmOptions: legacyAlgorithmOptions,
            automaticRekeyPolicy: automaticRekeyPolicy,
            keepalivePolicy: keepalivePolicy,
            timeoutPolicy: timeoutPolicy,
            connectionProxy: connectionProxy,
            proxyJumpHosts: proxyJumpHosts
        )
    }

    /// Creates an SSHClientConfiguration.
    public init(
        host: String,
        port: UInt16 = 22,
        username: String,
        authenticationMethods: [SSHAuthenticationMethod],
        hostKeyPolicy: SSHHostKeyPolicy,
        compressionPreference: SSHCompressionPreference = .disabled,
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions = .disabled,
        automaticRekeyPolicy: SSHAutomaticRekeyPolicy = .currentProfileDefault,
        keepalivePolicy: SSHKeepalivePolicy = .disabled,
        timeoutPolicy: SSHTimeoutPolicy = .currentProfileDefault,
        connectionProxy: SSHConnectionProxy? = nil,
        proxyJumpHosts: [SSHProxyJumpHost] = []
    ) {
        precondition(!authenticationMethods.isEmpty, "authenticationMethods must not be empty")
        self.host = host
        self.port = port
        self.username = username
        self.authenticationMethods = authenticationMethods
        self.hostKeyPolicy = hostKeyPolicy
        self.compressionPreference = compressionPreference
        self.legacyAlgorithmOptions = legacyAlgorithmOptions
        self.automaticRekeyPolicy = automaticRekeyPolicy
        self.keepalivePolicy = keepalivePolicy
        self.timeoutPolicy = timeoutPolicy
        self.connectionProxy = connectionProxy
        self.proxyJumpHosts = proxyJumpHosts
    }
}

/// Configuration for one SSH ProxyJump hop.
///
/// Jump-host host-key policy and authentication are evaluated independently
/// from the final target.
public struct SSHProxyJumpHost: Equatable, Sendable {
    /// Host name or address.
    public let host: String
    /// Port number.
    public let port: UInt16
    /// SSH username.
    public let username: String
    /// Authentication candidates tried in order.
    public let authenticationMethods: [SSHAuthenticationMethod]
    /// Host-key verification policy.
    public let hostKeyPolicy: SSHHostKeyPolicy
    /// Compression preference.
    public let compressionPreference: SSHCompressionPreference
    /// Legacy algorithm compatibility options.
    public let legacyAlgorithmOptions: SSHLegacyAlgorithmOptions
    /// Automatic rekey policy.
    public let automaticRekeyPolicy: SSHAutomaticRekeyPolicy
    /// Keepalive policy.
    public let keepalivePolicy: SSHKeepalivePolicy
    /// Timeout policy.
    public let timeoutPolicy: SSHTimeoutPolicy
    /// Authentication setting.

    public var authentication: SSHAuthenticationMethod {
        self.authenticationMethods[0]
    }

    /// Creates an SSHProxyJumpHost.
    public init(
        host: String,
        port: UInt16 = 22,
        username: String,
        authentication: SSHAuthenticationMethod,
        hostKeyPolicy: SSHHostKeyPolicy,
        compressionPreference: SSHCompressionPreference = .disabled,
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions = .disabled,
        automaticRekeyPolicy: SSHAutomaticRekeyPolicy = .currentProfileDefault,
        keepalivePolicy: SSHKeepalivePolicy = .disabled,
        timeoutPolicy: SSHTimeoutPolicy = .currentProfileDefault
    ) {
        self.init(
            host: host,
            port: port,
            username: username,
            authenticationMethods: [authentication],
            hostKeyPolicy: hostKeyPolicy,
            compressionPreference: compressionPreference,
            legacyAlgorithmOptions: legacyAlgorithmOptions,
            automaticRekeyPolicy: automaticRekeyPolicy,
            keepalivePolicy: keepalivePolicy,
            timeoutPolicy: timeoutPolicy
        )
    }

    /// Creates an SSHProxyJumpHost.
    public init(
        host: String,
        port: UInt16 = 22,
        username: String,
        authenticationMethods: [SSHAuthenticationMethod],
        hostKeyPolicy: SSHHostKeyPolicy,
        compressionPreference: SSHCompressionPreference = .disabled,
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions = .disabled,
        automaticRekeyPolicy: SSHAutomaticRekeyPolicy = .currentProfileDefault,
        keepalivePolicy: SSHKeepalivePolicy = .disabled,
        timeoutPolicy: SSHTimeoutPolicy = .currentProfileDefault
    ) {
        precondition(!authenticationMethods.isEmpty, "authenticationMethods must not be empty")
        self.host = host
        self.port = port
        self.username = username
        self.authenticationMethods = authenticationMethods
        self.hostKeyPolicy = hostKeyPolicy
        self.compressionPreference = compressionPreference
        self.legacyAlgorithmOptions = legacyAlgorithmOptions
        self.automaticRekeyPolicy = automaticRekeyPolicy
        self.keepalivePolicy = keepalivePolicy
        self.timeoutPolicy = timeoutPolicy
    }
}

extension SSHCompressionPreference {
    var keyExchangeCompressionAlgorithms: [String] {
        switch self {
        case .disabled:
            return ["none"]
        case .zlib:
            return ["zlib", "none"]
        case .delayedZlib:
            return ["zlib@openssh.com", "none"]
        }
    }
}

extension SSHLegacyAlgorithmOptions {
    var preferredServerHostKeyAlgorithms: [String] {
        var algorithms = SSHClientKeyExchangePreferences.default.serverHostKeyAlgorithms
        if self.allowsSSHRSA && !algorithms.contains("ssh-rsa") {
            algorithms.append("ssh-rsa")
        }
        return algorithms
    }

    var preferredRSAPublicKeyAuthenticationAlgorithms: [String] {
        if self.allowsSSHRSA {
            return ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
        }

        return ["rsa-sha2-512", "rsa-sha2-256"]
    }
}

/// Metadata captured after successful connection setup and authentication.
public struct SSHConnectionMetadata: Equatable, Sendable {
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
    /// pre-identification Lines.
    public let preIdentificationLines: [String]
    /// Authentication Banners.
    public let authenticationBanners: [SSHAuthenticationBanner]
    /// host key Algorithm.
    public let hostKeyAlgorithm: String
    /// host key Fingerprint SHA256.
    public let hostKeyFingerprintSHA256: String
    /// host key Trust Method.
    public let hostKeyTrustMethod: SSHHostKeyTrustMethod
    /// Creates an SSHConnectionMetadata.

    public init(
        endpointHost: String,
        endpointPort: UInt16,
        username: String,
        clientIdentification: String,
        remoteIdentification: String,
        preIdentificationLines: [String],
        authenticationBanners: [SSHAuthenticationBanner] = [],
        hostKeyAlgorithm: String,
        hostKeyFingerprintSHA256: String,
        hostKeyTrustMethod: SSHHostKeyTrustMethod
    ) {
        self.endpointHost = endpointHost
        self.endpointPort = endpointPort
        self.username = username
        self.clientIdentification = clientIdentification
        self.remoteIdentification = remoteIdentification
        self.preIdentificationLines = preIdentificationLines
        self.authenticationBanners = authenticationBanners
        self.hostKeyAlgorithm = hostKeyAlgorithm
        self.hostKeyFingerprintSHA256 = hostKeyFingerprintSHA256
        self.hostKeyTrustMethod = hostKeyTrustMethod
    }
}

/// SSH operation type that produced a connection latency sample.
public enum SSHConnectionLatencySource: String, Equatable, Sendable {
    /// Channel Open.
    case channelOpen
    /// Channel Request.
    case channelRequest
    /// Global Request.
    case globalRequest
    /// Keepalive.
    case keepalive
}

/// Latest round-trip timing observed on an established SSH connection.
public struct SSHConnectionLatency: Equatable, Sendable {
    /// Round Trip Time Nanoseconds.
    public let roundTripTimeNanoseconds: UInt64
    /// Measured At Uptime Nanoseconds.
    public let measuredAtUptimeNanoseconds: UInt64
    /// Source of the value.
    public let source: SSHConnectionLatencySource
    /// Round Trip Time Milliseconds.

    public var roundTripTimeMilliseconds: Double {
        Double(roundTripTimeNanoseconds) / 1_000_000
    }
    /// Round Trip Time.

    public var roundTripTime: TimeInterval {
        TimeInterval(roundTripTimeNanoseconds) / 1_000_000_000
    }
    /// Creates an SSHConnectionLatency.

    public init(
        roundTripTimeNanoseconds: UInt64,
        measuredAtUptimeNanoseconds: UInt64,
        source: SSHConnectionLatencySource
    ) {
        self.roundTripTimeNanoseconds = roundTripTimeNanoseconds
        self.measuredAtUptimeNanoseconds = measuredAtUptimeNanoseconds
        self.source = source
    }
}

/// Complete output collected from a remote exec command.
public struct SSHExecResult: Equatable, Sendable {
    /// Collected standard output bytes.
    public let standardOutput: [UInt8]
    /// Collected standard error bytes.
    public let standardError: [UInt8]
    /// Remote process exit status, when reported.
    public let exitStatus: UInt32?
    /// Exit Signal.
    public let exitSignal: SSHSessionExitSignal?
    /// Whether channel EOF was observed before close.
    public let didReceiveEOF: Bool

    init(_ result: SSHSessionExecResult) {
        self.standardOutput = result.standardOutput
        self.standardError = result.standardError
        self.exitStatus = result.exitStatus
        self.exitSignal = result.exitSignal
        self.didReceiveEOF = result.didReceiveEOF
    }
}

/// Complete output collected from an open session until channel close.
public struct SSHSessionOutput: Equatable, Sendable {
    /// Collected standard output bytes.
    public let standardOutput: [UInt8]
    /// Collected standard error bytes.
    public let standardError: [UInt8]
    /// Remote process exit status, when reported.
    public let exitStatus: UInt32?
    /// Exit Signal.
    public let exitSignal: SSHSessionExitSignal?
    /// Whether channel EOF was observed before close.
    public let didReceiveEOF: Bool

    init(transcript: SSHSessionTranscript) {
        self.standardOutput = transcript.standardOutput
        self.standardError = transcript.standardError
        self.exitStatus = transcript.exitStatus
        self.exitSignal = transcript.exitSignal
        self.didReceiveEOF = transcript.didReceiveEOF
    }
}

/// Async sequence over `SSHSessionEvent` values.
public struct SSHSessionEventSequence: AsyncSequence, Sendable {
    /// Element type produced by this async sequence.
    public typealias Element = SSHSessionEvent

    private let nextEventReader: @Sendable () async throws -> SSHSessionEvent?
    private let cancelHandler: @Sendable () async -> Void

    init(session: SSHSession) {
        self.nextEventReader = { try await session.nextEvent() }
        self.cancelHandler = { await session.bestEffortCloseOnCancellation() }
    }

    /// Creates an async iterator for this sequence.
    public func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(
            nextEventReader: self.nextEventReader,
            cancelHandler: self.cancelHandler
        )
    }

    public struct AsyncIterator: AsyncIteratorProtocol {
        private let nextEventReader: @Sendable () async throws -> SSHSessionEvent?
        private let terminationState: SSHEventSequenceTerminationState
        private var didReachEnd = false

        init(
            nextEventReader: @escaping @Sendable () async throws -> SSHSessionEvent?,
            cancelHandler: @escaping @Sendable () async -> Void
        ) {
            self.nextEventReader = nextEventReader
            self.terminationState = SSHEventSequenceTerminationState(
                cancelHandler: cancelHandler
            )
        }

        public mutating func next() async throws -> SSHSessionEvent? {
            guard !self.didReachEnd else {
                return nil
            }

            let nextEventReader = self.nextEventReader
            let terminationState = self.terminationState
            let nextEvent = try await withTaskCancellationHandler {
                try await nextEventReader()
            } onCancel: {
                terminationState.closeIfNeeded()
            }

            guard let event = nextEvent else {
                self.didReachEnd = true
                self.terminationState.markTerminal()
                return nil
            }
            return event
        }
    }
}

/// Async sequence over TCP/IP or streamlocal channel events.
public struct SSHTCPIPChannelEventSequence: AsyncSequence, Sendable {
    /// Element type produced by this async sequence.
    public typealias Element = SSHTCPIPChannelEvent

    private let nextEventReader: @Sendable () async throws -> SSHTCPIPChannelEvent?
    private let cancelHandler: @Sendable () async -> Void

    init(
        nextEventReader: @escaping @Sendable () async throws -> SSHTCPIPChannelEvent?,
        cancelHandler: @escaping @Sendable () async -> Void
    ) {
        self.nextEventReader = nextEventReader
        self.cancelHandler = cancelHandler
    }

    /// Creates an async iterator for this sequence.
    public func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(
            nextEventReader: self.nextEventReader,
            cancelHandler: self.cancelHandler
        )
    }

    public struct AsyncIterator: AsyncIteratorProtocol {
        private let nextEventReader: @Sendable () async throws -> SSHTCPIPChannelEvent?
        private let terminationState: SSHEventSequenceTerminationState
        private var didReachEnd = false

        init(
            nextEventReader: @escaping @Sendable () async throws -> SSHTCPIPChannelEvent?,
            cancelHandler: @escaping @Sendable () async -> Void
        ) {
            self.nextEventReader = nextEventReader
            self.terminationState = SSHEventSequenceTerminationState(
                cancelHandler: cancelHandler
            )
        }

        public mutating func next() async throws -> SSHTCPIPChannelEvent? {
            guard !self.didReachEnd else {
                return nil
            }

            let nextEventReader = self.nextEventReader
            let terminationState = self.terminationState
            let nextEvent = try await withTaskCancellationHandler {
                try await nextEventReader()
            } onCancel: {
                terminationState.closeIfNeeded()
            }

            guard let event = nextEvent else {
                self.didReachEnd = true
                self.terminationState.markTerminal()
                return nil
            }
            return event
        }
    }
}

private final class SSHEventSequenceTerminationState: @unchecked Sendable {
    private let lock = NSLock()
    private let cancelHandler: @Sendable () async -> Void
    private var shouldCloseOnDeinit = true
    private var didScheduleClose = false

    // Sendable invariant: mutable termination state is protected by `lock`.
    init(cancelHandler: @escaping @Sendable () async -> Void) {
        self.cancelHandler = cancelHandler
    }

    deinit {
        self.closeIfNeeded()
    }

    func markTerminal() {
        self.lock.lock()
        self.shouldCloseOnDeinit = false
        self.lock.unlock()
    }

    func closeIfNeeded() {
        guard let cancelHandler = self.claimClose() else {
            return
        }

        Task {
            await cancelHandler()
        }
    }

    private func claimClose() -> (@Sendable () async -> Void)? {
        self.lock.lock()
        defer {
            self.lock.unlock()
        }

        guard self.shouldCloseOnDeinit, !self.didScheduleClose else {
            return nil
        }

        self.shouldCloseOnDeinit = false
        self.didScheduleClose = true
        return self.cancelHandler
    }
}

/// Event type used by OpenSSH streamlocal channels.
public typealias SSHStreamLocalChannelEvent = SSHTCPIPChannelEvent
/// Event sequence used by OpenSSH streamlocal channels.
public typealias SSHStreamLocalChannelEventSequence = SSHTCPIPChannelEventSequence

/// Complete data collected from a `direct-tcpip` channel.
public struct SSHDirectTCPIPChannelOutput: Equatable, Sendable {
    /// Collected channel data.
    public let data: [UInt8]
    /// Whether channel EOF was observed before close.
    public let didReceiveEOF: Bool

    init(transcript: SSHTCPIPChannelTranscript) {
        self.data = transcript.data
        self.didReceiveEOF = transcript.didReceiveEOF
    }
}

/// Complete data collected from a direct OpenSSH streamlocal channel.
public struct SSHDirectStreamLocalChannelOutput: Equatable, Sendable {
    /// Collected channel data.
    public let data: [UInt8]
    /// Whether channel EOF was observed before close.
    public let didReceiveEOF: Bool

    init(transcript: SSHTCPIPChannelTranscript) {
        self.data = transcript.data
        self.didReceiveEOF = transcript.didReceiveEOF
    }
}

/// Complete data collected from an accepted remote streamlocal channel.
public struct SSHForwardedStreamLocalChannelOutput: Equatable, Sendable {
    /// Collected channel data.
    public let data: [UInt8]
    /// Whether channel EOF was observed before close.
    public let didReceiveEOF: Bool

    init(transcript: SSHTCPIPChannelTranscript) {
        self.data = transcript.data
        self.didReceiveEOF = transcript.didReceiveEOF
    }
}

actor SSHConnectionLifetime {
    private var isActive = true
    private var closeOperation: (@Sendable () async -> Void)?
    private var abortOperation: (@Sendable () async -> Void)?
    private var closeWaiters: [CheckedContinuation<Void, Never>] = []

    init(
        closeOperation: (@Sendable () async -> Void)? = nil,
        abortOperation: (@Sendable () async -> Void)? = nil
    ) {
        self.closeOperation = closeOperation
        self.abortOperation = abortOperation
    }

    func requireActive() throws {
        guard self.isActive else {
            throw SSHClientError.connectionScopeEnded
        }
    }

    func close() async {
        await self.close(usingAbortOperation: false)
    }

    func abort() async {
        await self.close(usingAbortOperation: true)
    }

    private func close(usingAbortOperation: Bool) async {
        guard self.isActive else {
            return
        }

        self.isActive = false
        let selectedOperation: (@Sendable () async -> Void)?
        if usingAbortOperation {
            selectedOperation = self.abortOperation ?? self.closeOperation
        } else {
            selectedOperation = self.closeOperation
        }
        self.closeOperation = nil
        self.abortOperation = nil
        let closeWaiters = self.closeWaiters
        self.closeWaiters.removeAll(keepingCapacity: false)

        for continuation in closeWaiters {
            continuation.resume()
        }

        await selectedOperation?()
    }

    func waitUntilClosed() async {
        guard self.isActive else {
            return
        }

        await withCheckedContinuation { continuation in
            if self.isActive {
                self.closeWaiters.append(continuation)
            } else {
                continuation.resume()
            }
        }
    }

    func active() -> Bool {
        self.isActive
    }
}
