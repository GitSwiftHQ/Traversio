// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package struct SSHVersionExchange: Equatable, Sendable {
    package let clientIdentification: SSHIdentification
    package let remoteIdentification: SSHIdentification
    package let preIdentificationLines: [String]
}

enum SSHActorWaiterResume {
    case ready
    case cancelled
}

struct SSHActorWaiterQueue {
    typealias WaiterID = UInt64

    private var orderedWaiterIDs: [WaiterID] = []
    private var waiters: [WaiterID: CheckedContinuation<SSHActorWaiterResume, Never>] = [:]

    var count: Int {
        self.waiters.count
    }

    mutating func install(
        waiterID: WaiterID,
        continuation: CheckedContinuation<SSHActorWaiterResume, Never>
    ) {
        self.orderedWaiterIDs.append(waiterID)
        self.waiters[waiterID] = continuation
    }

    mutating func remove(
        waiterID: WaiterID
    ) -> CheckedContinuation<SSHActorWaiterResume, Never>? {
        guard let continuation = self.waiters.removeValue(forKey: waiterID) else {
            return nil
        }

        if let index = self.orderedWaiterIDs.firstIndex(of: waiterID) {
            self.orderedWaiterIDs.remove(at: index)
        }
        return continuation
    }

    mutating func popNext() -> CheckedContinuation<SSHActorWaiterResume, Never>? {
        while !self.orderedWaiterIDs.isEmpty {
            let waiterID = self.orderedWaiterIDs.removeFirst()
            if let continuation = self.waiters.removeValue(forKey: waiterID) {
                return continuation
            }
        }

        return nil
    }

    mutating func popAll() -> [CheckedContinuation<SSHActorWaiterResume, Never>] {
        let waiterIDs = self.orderedWaiterIDs
        self.orderedWaiterIDs.removeAll(keepingCapacity: false)

        var continuations: [CheckedContinuation<SSHActorWaiterResume, Never>] = []
        continuations.reserveCapacity(waiterIDs.count)
        for waiterID in waiterIDs {
            if let continuation = self.waiters.removeValue(forKey: waiterID) {
                continuations.append(continuation)
            }
        }

        return continuations
    }
}

struct SSHSessionReceiveWindowState: Sendable {
    let initialWindowSize: UInt32
    private(set) var remainingWindowSize: UInt32
    private var pendingWindowAdjustment: UInt32 = 0
    private let replenishThreshold: UInt32

    init(initialWindowSize: UInt32, replenishThreshold: UInt32) {
        self.initialWindowSize = initialWindowSize
        self.remainingWindowSize = initialWindowSize
        self.replenishThreshold = max(1, replenishThreshold)
    }

    mutating func consume(
        byteCount: Int,
        localChannelID: UInt32,
        remoteChannelID: UInt32
    ) throws -> SSHChannelWindowAdjustMessage? {
        let receivedByteCount = UInt32(byteCount)
        guard receivedByteCount <= self.remainingWindowSize else {
            throw SSHConnectionError.channelReceiveWindowExceeded(
                channelID: localChannelID,
                received: receivedByteCount,
                remaining: self.remainingWindowSize
            )
        }

        self.remainingWindowSize -= receivedByteCount
        self.pendingWindowAdjustment += receivedByteCount

        guard self.pendingWindowAdjustment >= self.replenishThreshold ||
                self.remainingWindowSize == 0 else {
            return nil
        }

        let bytesToAdd = self.pendingWindowAdjustment
        self.pendingWindowAdjustment = 0
        self.remainingWindowSize += bytesToAdd
        return SSHChannelWindowAdjustMessage(
            recipientChannel: remoteChannelID,
            bytesToAdd: bytesToAdd
        )
    }

    mutating func adjust(
        byteCount: UInt32,
        localChannelID: UInt32,
        remoteChannelID: UInt32
    ) throws -> SSHChannelWindowAdjustMessage? {
        guard byteCount > 0 else {
            return nil
        }

        let (updatedWindowSize, overflow) = self.remainingWindowSize.addingReportingOverflow(
            byteCount
        )
        guard !overflow else {
            throw SSHConnectionError.channelReceiveWindowOverflow(
                channelID: localChannelID,
                current: self.remainingWindowSize,
                adjustment: byteCount
            )
        }

        self.remainingWindowSize = updatedWindowSize
        return SSHChannelWindowAdjustMessage(
            recipientChannel: remoteChannelID,
            bytesToAdd: byteCount
        )
    }
}

struct SSHSessionRemoteWindowState: Sendable {
    let initialWindowSize: UInt32
    private(set) var remainingWindowSize: UInt32
    let maximumPacketSize: UInt32

    init(initialWindowSize: UInt32, maximumPacketSize: UInt32) {
        self.initialWindowSize = initialWindowSize
        self.remainingWindowSize = initialWindowSize
        self.maximumPacketSize = maximumPacketSize
    }

    mutating func reserveSendChunk(remainingByteCount: Int) -> Int {
        guard self.remainingWindowSize > 0, remainingByteCount > 0 else {
            return 0
        }

        let chunkSize = min(
            remainingByteCount,
            Int(self.remainingWindowSize),
            Int(self.maximumPacketSize)
        )
        self.remainingWindowSize -= UInt32(chunkSize)
        return chunkSize
    }

    mutating func applyWindowAdjust(
        _ bytesToAdd: UInt32,
        localChannelID: UInt32
    ) throws {
        let (newWindowSize, overflow) = self.remainingWindowSize.addingReportingOverflow(bytesToAdd)
        guard !overflow else {
            throw SSHConnectionError.channelSendWindowOverflow(
                channelID: localChannelID,
                current: self.remainingWindowSize,
                adjustment: bytesToAdd
            )
        }

        self.remainingWindowSize = newWindowSize
    }
}

enum SSHSessionOutputBufferingMode: String, Equatable, Sendable {
    case undecided
    case transcript
    case standardOutputChunks
    case events
}

struct SSHSessionOutputState: Sendable {
    var bufferingMode: SSHSessionOutputBufferingMode = .undecided
    var standardOutput: [UInt8] = []
    var unreadStandardOutput: [UInt8] = []
    var standardError: [UInt8] = []
    var pendingEvents: [SSHSessionEvent] = []
    var exitStatus: UInt32?
    var exitSignal: SSHSessionExitSignal?
    var didReceiveEOF = false
    var didSendEOF = false
    var didReceiveClose = false
    var didSendClose = false
    var observationGeneration: UInt64 = 0

    mutating func activateBufferingMode(
        _ requestedMode: SSHSessionOutputBufferingMode,
        channelID: UInt32
    ) throws {
        guard requestedMode != .undecided else {
            return
        }
        if self.bufferingMode == requestedMode {
            return
        }
        guard self.bufferingMode == .undecided else {
            throw SSHConnectionError.incompatibleSessionOutputConsumer(
                channelID: channelID,
                activeConsumer: self.bufferingMode,
                requestedConsumer: requestedMode
            )
        }

        self.bufferingMode = requestedMode
        switch requestedMode {
        case .undecided:
            return
        case .transcript:
            self.unreadStandardOutput.removeAll(keepingCapacity: false)
            self.pendingEvents.removeAll(keepingCapacity: false)
        case .standardOutputChunks:
            self.standardOutput.removeAll(keepingCapacity: false)
            self.standardError.removeAll(keepingCapacity: false)
            self.pendingEvents.removeAll(keepingCapacity: false)
        case .events:
            self.standardOutput.removeAll(keepingCapacity: false)
            self.unreadStandardOutput.removeAll(keepingCapacity: false)
            self.standardError.removeAll(keepingCapacity: false)
        }
    }

    mutating func appendStandardOutput(_ bytes: [UInt8]) {
        switch self.bufferingMode {
        case .undecided:
            self.standardOutput.append(contentsOf: bytes)
            self.unreadStandardOutput.append(contentsOf: bytes)
            self.pendingEvents.append(.standardOutput(bytes))
        case .transcript:
            self.standardOutput.append(contentsOf: bytes)
        case .standardOutputChunks:
            self.unreadStandardOutput.append(contentsOf: bytes)
        case .events:
            self.pendingEvents.append(.standardOutput(bytes))
        }
        self.observationGeneration &+= 1
    }

    mutating func appendStandardError(_ bytes: [UInt8]) {
        switch self.bufferingMode {
        case .undecided:
            self.standardError.append(contentsOf: bytes)
            self.pendingEvents.append(.standardError(bytes))
        case .transcript:
            self.standardError.append(contentsOf: bytes)
        case .standardOutputChunks:
            break
        case .events:
            self.pendingEvents.append(.standardError(bytes))
        }
        self.observationGeneration &+= 1
    }

    mutating func recordExitStatus(_ exitStatus: UInt32) {
        self.exitStatus = exitStatus
        switch self.bufferingMode {
        case .undecided, .events:
            self.pendingEvents.append(.exitStatus(exitStatus))
        case .transcript, .standardOutputChunks:
            break
        }
        self.observationGeneration &+= 1
    }

    mutating func recordExitSignal(_ exitSignal: SSHSessionExitSignal) {
        self.exitSignal = exitSignal
        switch self.bufferingMode {
        case .undecided, .events:
            self.pendingEvents.append(.exitSignal(exitSignal))
        case .transcript, .standardOutputChunks:
            break
        }
        self.observationGeneration &+= 1
    }

    mutating func recordEndOfFile() {
        self.didReceiveEOF = true
        switch self.bufferingMode {
        case .undecided, .events:
            self.pendingEvents.append(.endOfFile)
        case .transcript, .standardOutputChunks:
            break
        }
        self.observationGeneration &+= 1
    }

    mutating func recordClose() {
        self.didReceiveClose = true
        self.observationGeneration &+= 1
    }
}

struct SSHManagedSessionState: Sendable {
    let channel: SSHChannel
    var receiveWindowState: SSHSessionReceiveWindowState
    var remoteWindowState: SSHSessionRemoteWindowState
    var outputState = SSHSessionOutputState()
    var isWriting = false

    var transcript: SSHSessionTranscript {
        SSHSessionTranscript(
            channel: self.channel,
            standardOutput: self.outputState.standardOutput,
            standardError: self.outputState.standardError,
            exitStatus: self.outputState.exitStatus,
            exitSignal: self.outputState.exitSignal,
            didReceiveEOF: self.outputState.didReceiveEOF
        )
    }

    var isComplete: Bool {
        self.outputState.didReceiveClose && self.outputState.didSendClose
    }
}

enum SSHSessionMessageAction {
    case none
    case sendChannelSuccess(SSHChannelSuccessMessage)
    case sendChannelFailure(SSHChannelFailureMessage)
    case sendWindowAdjust(SSHChannelWindowAdjustMessage)
    case sendClose
    case complete
}

struct SSHAcceptedForwardedTCPIPChannel: Sendable {
    let openRequest: SSHForwardedTCPIPChannelOpenRequest
    let handle: SSHTCPIPChannelHandle
}

struct SSHAcceptedForwardedStreamLocalChannel: Sendable {
    let openRequest: SSHForwardedStreamLocalChannelOpenRequest
    let handle: SSHTCPIPChannelHandle
}

enum SSHPendingChannelOpenResponse: Sendable {
    case confirmation(SSHChannelOpenConfirmationMessage)
    case failure(SSHChannelOpenFailureMessage)
}

enum SSHPendingChannelRequestReply: Sendable {
    case windowAdjust(SSHChannelWindowAdjustMessage)
    case success(SSHChannelSuccessMessage)
    case failure(SSHChannelFailureMessage)
}

enum SSHInboundWaitOutcome<Result> {
    case value(Result)
    case continueWaiting
}

typealias SSHTransportRekeyHandler = @Sendable (
    SSHKeyExchangeInitMessage,
    isolated SSHTransportProtocolClient
) async throws -> Void
typealias SSHTransportLocalRekeyHandler = @Sendable (
    isolated SSHTransportProtocolClient
) async throws -> Void

struct SSHTransportProtocolClientConfiguration: Sendable {
    let keyExchangePreferences: SSHClientKeyExchangePreferences
    let automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy
    let keepalivePolicy: SSHTransportKeepalivePolicy
    let responseTimeoutNanoseconds: UInt64?

    init(
        keyExchangePreferences: SSHClientKeyExchangePreferences = .default,
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy = .currentProfileDefault,
        keepalivePolicy: SSHTransportKeepalivePolicy = .disabled,
        responseTimeoutNanoseconds: UInt64? = nil
    ) {
        self.keyExchangePreferences = keyExchangePreferences
        self.automaticRekeyPolicy = automaticRekeyPolicy
        self.keepalivePolicy = keepalivePolicy
        self.responseTimeoutNanoseconds = responseTimeoutNanoseconds
    }

    init(
        preferredServerHostKeyAlgorithms: [String]? = nil,
        compressionPreference: SSHCompressionPreference = .disabled,
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy = .currentProfileDefault,
        keepalivePolicy: SSHTransportKeepalivePolicy = .disabled,
        responseTimeoutNanoseconds: UInt64? = nil
    ) {
        self.init(
            keyExchangePreferences: Self.makeKeyExchangePreferences(
                preferredServerHostKeyAlgorithms: preferredServerHostKeyAlgorithms,
                compressionPreference: compressionPreference
            ),
            automaticRekeyPolicy: automaticRekeyPolicy,
            keepalivePolicy: keepalivePolicy,
            responseTimeoutNanoseconds: responseTimeoutNanoseconds
        )
    }

    private static func makeKeyExchangePreferences(
        preferredServerHostKeyAlgorithms: [String]?,
        compressionPreference: SSHCompressionPreference
    ) -> SSHClientKeyExchangePreferences {
        let preferences = SSHClientKeyExchangePreferences.default.withCompressionAlgorithms(
            clientToServer: compressionPreference.keyExchangeCompressionAlgorithms,
            serverToClient: compressionPreference.keyExchangeCompressionAlgorithms
        )
        guard let preferredServerHostKeyAlgorithms, !preferredServerHostKeyAlgorithms.isEmpty else {
            return preferences
        }

        return preferences.withServerHostKeyAlgorithms(preferredServerHostKeyAlgorithms)
    }
}

package actor SSHTransportProtocolClient {
    static let defaultClientIdentification = SSHIdentification(
        uncheckedRawValue: TraversioRelease.sshIdentificationRawValue,
        protocolVersion: "2.0",
        softwareVersion: TraversioRelease.sshSoftwareVersion
    )
    static let maximumRecordedDebugMessages = 16
    static let maximumRecentlyCompletedManagedSessionChannelIDs = 256
    static let defaultForwardingFallbackKeepaliveIntervalNanoseconds: UInt64 = 15_000_000_000

    let transport: any SSHByteStreamTransport
    let clientIdentification: SSHIdentification
    let maximumReadSize: Int
    let packetSerializer: SSHBinaryPacketSerializer
    let messageSerializer: SSHTransportMessageSerializer
    let messageParser: SSHTransportMessageParser
    let userAuthenticationMessageSerializer: SSHUserAuthenticationMessageSerializer
    let userAuthenticationMessageParser: SSHUserAuthenticationMessageParser
    let connectionMessageSerializer: SSHConnectionMessageSerializer
    let connectionMessageParser: SSHConnectionMessageParser
    let sessionRequestCoder: SSHSessionRequestCoder
    let tcpipForwardingRequestCoder: SSHTCPIPForwardingRequestCoder
    let keyExchangePreferences: SSHClientKeyExchangePreferences
    let algorithmNegotiator: SSHKeyExchangeAlgorithmNegotiator
    let automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy
    let keepalivePolicy: SSHTransportKeepalivePolicy
    nonisolated let responseTimeoutNanoseconds: UInt64?

    var identificationParser = SSHIdentificationParser(role: .client)
    var binaryPacketParser = SSHBinaryPacketParser()
    var versionExchange: SSHVersionExchange?
    var keyExchangeInitNegotiation: SSHKeyExchangeInitNegotiation?
    var outboundEncryptedPacketSerializer: SSHOutboundEncryptedPacketSerializer?
    var inboundEncryptedPacketParser: SSHInboundEncryptedPacketParser?
    var acceptedServices: Set<String> = []
    var authenticatedServiceName: String?
    var sessionIdentifier: [UInt8]?
    var didReceiveServerExtensionInfo = false
    var serverExtensions: [String: [UInt8]] = [:]
    var transportRekeyHandler: SSHTransportRekeyHandler?
    var localTransportRekeyHandler: SSHTransportLocalRekeyHandler?
    var lastDisconnectMessage: SSHDisconnectMessage?
    var recordedDebugMessages: [SSHDebugMessage] = []
    var nextLocalChannelID: UInt32 = 0
    var managedSessionStates: [UInt32: SSHManagedSessionState] = [:]
    var recentlyCompletedManagedSessionChannelIDs: Set<UInt32> = []
    var recentlyCompletedManagedSessionChannelIDOrder: [UInt32] = []
    var activeRemoteTCPIPForwards: Set<SSHTCPIPForwardingRequest> = []
    var remoteTCPIPForwardCancellationRequestsInFlight: Set<SSHTCPIPForwardingRequest> = []
    var pendingForwardedTCPIPChannels:
        [SSHTCPIPForwardingRequest: [SSHAcceptedForwardedTCPIPChannel]] = [:]
    var activeRemoteStreamLocalForwards: Set<SSHStreamLocalForwardingRequest> = []
    var remoteStreamLocalForwardCancellationRequestsInFlight: Set<SSHStreamLocalForwardingRequest> = []
    var pendingForwardedStreamLocalChannels:
        [SSHStreamLocalForwardingRequest: [SSHAcceptedForwardedStreamLocalChannel]] = [:]
    var pendingManagedSessionLocalChannelIDs: Set<UInt32> = []
    var pendingChannelOpenResponses: [UInt32: SSHPendingChannelOpenResponse] = [:]
    var pendingChannelRequestReplies: [UInt32: [SSHPendingChannelRequestReply]] = [:]
    var pendingPreManagedSessionMessages: [UInt32: [SSHConnectionMessage]] = [:]
    var pendingGlobalRequestReplies: [SSHConnectionMessage] = []
    var activeGlobalRequestReplyWaiterCount = 0
    var deferredConnectionMessagesDuringTransportRekey: [SSHConnectionMessage] = []
    var pendingConnectionMessagesAfterTransportRekey: [SSHConnectionMessage] = []
    var outboundPacketSequenceNumber: UInt32 = 0
    var inboundPacketSequenceNumber: UInt32 = 0
    var outboundEncryptedPacketCountSinceLastKeyExchange: UInt64 = 0
    var inboundEncryptedPacketCountSinceLastKeyExchange: UInt64 = 0
    var lastProtectedTransportActivityNanoseconds: UInt64?
    var latestLatency: SSHConnectionLatency?
    var completedRemoteRekeyCount: UInt64 = 0
    var completedLocalRekeyCount: UInt64 = 0
    var strictKeyExchangeWasNegotiated = false
    var nextActorWaiterID: UInt64 = 0
    var isReceivingInboundPacket = false
    var inboundPacketReceiveTurnWaiters = SSHActorWaiterQueue()
    var isSendingOutboundPacket = false
    var outboundPacketSendWaiters = SSHActorWaiterQueue()
    var activeConnectionMessageWaiterCount = 0
    var connectionMessageWaiterProgressWaiters = SSHActorWaiterQueue()
    var isTransportRekeyInProgress = false
    var transportRekeyWaiters = SSHActorWaiterQueue()
    var pendingIdleRekeyTrigger: SSHTransportAutomaticRekeyTrigger?
    var pendingBackgroundTransportFailure: (any Error & Sendable)?
    var idleRekeyTaskHandle: SSHCancellationHandle?
    var idleRekeyTaskGeneration: UInt64 = 0
    var keepaliveTaskHandle: SSHCancellationHandle?
    var keepaliveInFlightTaskHandle: SSHCancellationHandle?
    var keepaliveTaskGeneration: UInt64 = 0
    var networkTransitionProbeInFlight = false
    var isOutboundGlobalRequestInFlight = false
    var outboundGlobalRequestWaiters = SSHActorWaiterQueue()
    var backgroundFailureHandler: (@Sendable (any Error & Sendable) async -> Void)?

    init(
        transport: any SSHByteStreamTransport,
        maximumReadSize: Int = 4096,
        packetSerializer: SSHBinaryPacketSerializer = SSHBinaryPacketSerializer(),
        messageSerializer: SSHTransportMessageSerializer = SSHTransportMessageSerializer(),
        messageParser: SSHTransportMessageParser = SSHTransportMessageParser(),
        userAuthenticationMessageSerializer: SSHUserAuthenticationMessageSerializer =
            SSHUserAuthenticationMessageSerializer(),
        userAuthenticationMessageParser: SSHUserAuthenticationMessageParser =
            SSHUserAuthenticationMessageParser(),
        connectionMessageSerializer: SSHConnectionMessageSerializer =
            SSHConnectionMessageSerializer(),
        connectionMessageParser: SSHConnectionMessageParser =
            SSHConnectionMessageParser(),
        sessionRequestCoder: SSHSessionRequestCoder = SSHSessionRequestCoder(),
        tcpipForwardingRequestCoder: SSHTCPIPForwardingRequestCoder = SSHTCPIPForwardingRequestCoder(),
        keyExchangePreferences: SSHClientKeyExchangePreferences = .default,
        algorithmNegotiator: SSHKeyExchangeAlgorithmNegotiator = SSHKeyExchangeAlgorithmNegotiator(),
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy = .currentProfileDefault,
        keepalivePolicy: SSHTransportKeepalivePolicy = .disabled,
        responseTimeoutNanoseconds: UInt64? = nil
    ) {
        self.init(
            transport: transport,
            clientIdentification: Self.defaultClientIdentification,
            maximumReadSize: maximumReadSize,
            packetSerializer: packetSerializer,
            messageSerializer: messageSerializer,
            messageParser: messageParser,
            userAuthenticationMessageSerializer: userAuthenticationMessageSerializer,
            userAuthenticationMessageParser: userAuthenticationMessageParser,
            connectionMessageSerializer: connectionMessageSerializer,
            connectionMessageParser: connectionMessageParser,
            sessionRequestCoder: sessionRequestCoder,
            tcpipForwardingRequestCoder: tcpipForwardingRequestCoder,
            keyExchangePreferences: keyExchangePreferences,
            algorithmNegotiator: algorithmNegotiator,
            automaticRekeyPolicy: automaticRekeyPolicy,
            keepalivePolicy: keepalivePolicy,
            responseTimeoutNanoseconds: responseTimeoutNanoseconds
        )
    }

    package init(transport: any SSHByteStreamTransport) {
        self.init(
            transport: transport,
            transportConfiguration: SSHTransportProtocolClientConfiguration()
        )
    }

    package init(
        transport: any SSHByteStreamTransport,
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy
    ) {
        self.init(
            transport: transport,
            transportConfiguration: SSHTransportProtocolClientConfiguration(
                automaticRekeyPolicy: automaticRekeyPolicy
            )
        )
    }

    package init(
        transport: any SSHByteStreamTransport,
        preferredServerHostKeyAlgorithms: [String]? = nil,
        compressionPreference: SSHCompressionPreference,
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy = .currentProfileDefault,
        keepalivePolicy: SSHTransportKeepalivePolicy = .disabled,
        responseTimeoutNanoseconds: UInt64? = nil
    ) {
        self.init(
            transport: transport,
            transportConfiguration: SSHTransportProtocolClientConfiguration(
                preferredServerHostKeyAlgorithms: preferredServerHostKeyAlgorithms,
                compressionPreference: compressionPreference,
                automaticRekeyPolicy: automaticRekeyPolicy,
                keepalivePolicy: keepalivePolicy,
                responseTimeoutNanoseconds: responseTimeoutNanoseconds
            )
        )
    }

    package init(
        transport: any SSHByteStreamTransport,
        preferredServerHostKeyAlgorithms: [String]
    ) {
        self.init(
            transport: transport,
            transportConfiguration: SSHTransportProtocolClientConfiguration(
                preferredServerHostKeyAlgorithms: preferredServerHostKeyAlgorithms
            )
        )
    }

    package init(
        transport: any SSHByteStreamTransport,
        preferredServerHostKeyAlgorithms: [String],
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy
    ) {
        self.init(
            transport: transport,
            transportConfiguration: SSHTransportProtocolClientConfiguration(
                preferredServerHostKeyAlgorithms: preferredServerHostKeyAlgorithms,
                automaticRekeyPolicy: automaticRekeyPolicy
            )
        )
    }

    init(
        transport: any SSHByteStreamTransport,
        transportConfiguration: SSHTransportProtocolClientConfiguration
    ) {
        self.init(
            transport: transport,
            maximumReadSize: 4096,
            keyExchangePreferences: transportConfiguration.keyExchangePreferences,
            automaticRekeyPolicy: transportConfiguration.automaticRekeyPolicy,
            keepalivePolicy: transportConfiguration.keepalivePolicy,
            responseTimeoutNanoseconds: transportConfiguration.responseTimeoutNanoseconds
        )
    }

    init(
        transport: any SSHByteStreamTransport,
        clientIdentification: SSHIdentification,
        maximumReadSize: Int = 4096,
        packetSerializer: SSHBinaryPacketSerializer = SSHBinaryPacketSerializer(),
        messageSerializer: SSHTransportMessageSerializer = SSHTransportMessageSerializer(),
        messageParser: SSHTransportMessageParser = SSHTransportMessageParser(),
        userAuthenticationMessageSerializer: SSHUserAuthenticationMessageSerializer =
            SSHUserAuthenticationMessageSerializer(),
        userAuthenticationMessageParser: SSHUserAuthenticationMessageParser =
            SSHUserAuthenticationMessageParser(),
        connectionMessageSerializer: SSHConnectionMessageSerializer =
            SSHConnectionMessageSerializer(),
        connectionMessageParser: SSHConnectionMessageParser =
            SSHConnectionMessageParser(),
        sessionRequestCoder: SSHSessionRequestCoder = SSHSessionRequestCoder(),
        tcpipForwardingRequestCoder: SSHTCPIPForwardingRequestCoder = SSHTCPIPForwardingRequestCoder(),
        keyExchangePreferences: SSHClientKeyExchangePreferences = .default,
        algorithmNegotiator: SSHKeyExchangeAlgorithmNegotiator = SSHKeyExchangeAlgorithmNegotiator(),
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy = .currentProfileDefault,
        keepalivePolicy: SSHTransportKeepalivePolicy = .disabled,
        responseTimeoutNanoseconds: UInt64? = nil
    ) {
        self.transport = transport
        self.clientIdentification = clientIdentification
        self.maximumReadSize = maximumReadSize
        self.packetSerializer = packetSerializer
        self.messageSerializer = messageSerializer
        self.messageParser = messageParser
        self.userAuthenticationMessageSerializer = userAuthenticationMessageSerializer
        self.userAuthenticationMessageParser = userAuthenticationMessageParser
        self.connectionMessageSerializer = connectionMessageSerializer
        self.connectionMessageParser = connectionMessageParser
        self.sessionRequestCoder = sessionRequestCoder
        self.tcpipForwardingRequestCoder = tcpipForwardingRequestCoder
        self.keyExchangePreferences = keyExchangePreferences
        self.algorithmNegotiator = algorithmNegotiator
        self.automaticRekeyPolicy = automaticRekeyPolicy
        self.keepalivePolicy = keepalivePolicy
        self.responseTimeoutNanoseconds = responseTimeoutNanoseconds
    }
}
