// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

actor HostKeyValidationRequestRecorder {
    private var request: SSHHostKeyValidationRequest?

    func record(_ request: SSHHostKeyValidationRequest) {
        self.request = request
    }

    func recordedRequest() -> SSHHostKeyValidationRequest? {
        self.request
    }
}

actor HostKeyChangeRequestRecorder {
    private var request: SSHHostKeyChangeRequest?

    func record(_ request: SSHHostKeyChangeRequest) {
        self.request = request
    }

    func recordedRequest() -> SSHHostKeyChangeRequest? {
        self.request
    }
}

enum CustomHostKeyPolicyError: Error, Equatable, SSHCallbackFailureDiagnosticProviding {
    case rejected

    var sshCallbackFailureDiagnosticCode: String {
        "host-key-rejected"
    }

    var sshCallbackFailureDiagnosticSummary: String? {
        "The host-key trust decision was rejected by application policy."
    }
}

enum CustomKeyboardInteractiveCallbackError: Error, Equatable {
    case rejected
}

enum CustomPasswordChangeCallbackError: Error, Equatable {
    case rejected
}

enum CustomPublicKeySignatureCallbackError: Error, Equatable {
    case rejected
}

actor PasswordChangeChallengeRecorder {
    private var challenge: SSHPasswordChangeChallenge?

    func record(_ challenge: SSHPasswordChangeChallenge) {
        self.challenge = challenge
    }

    func recordedChallenge() -> SSHPasswordChangeChallenge? {
        self.challenge
    }
}

actor TrustOnFirstUseStore {
    private var hostKeys: [String: SSHTrustedHostKey] = [:]
    private var saveCount = 0
    private var lastStoreRequest: SSHHostKeyStoreRequest?

    func lookup(host: String, port: UInt16) -> SSHTrustedHostKey? {
        self.hostKeys[Self.storageKey(host: host, port: port)]
    }

    func store(host: String, port: UInt16, trustedHostKey: SSHTrustedHostKey) {
        self.hostKeys[Self.storageKey(host: host, port: port)] = trustedHostKey
        self.saveCount += 1
    }

    func store(_ request: SSHHostKeyStoreRequest) throws {
        let currentStoredHostKey = self.lookup(
            host: request.endpointHost,
            port: request.endpointPort
        )

        guard request.matchesExpectedStoredHostKey(currentStoredHostKey) else {
            throw SSHHostKeyPolicyError.concurrentStoredHostKeyUpdate(
                endpointHost: request.endpointHost,
                endpointPort: request.endpointPort,
                expectedStoredHostKey: request.expectedStoredHostKey,
                actualStoredHostKey: currentStoredHostKey
            )
        }

        self.lastStoreRequest = request
        self.hostKeys[Self.storageKey(host: request.endpointHost, port: request.endpointPort)] =
            request.trustedHostKey
        self.saveCount += 1
    }

    func saveCountObserved() -> Int {
        self.saveCount
    }

    func recordedStoreRequest() -> SSHHostKeyStoreRequest? {
        self.lastStoreRequest
    }

    private static func storageKey(host: String, port: UInt16) -> String {
        "\(host):\(port)"
    }
}

extension TrustOnFirstUseStore: SSHHostKeyTrustStore {
    func lookupHostKey(
        endpointHost: String,
        endpointPort: UInt16
    ) async throws -> SSHTrustedHostKey? {
        self.lookup(host: endpointHost, port: endpointPort)
    }

    func storeHostKey(_ request: SSHHostKeyStoreRequest) async throws {
        try self.store(request)
    }
}

actor ReplacingTrustOnFirstUseStore: SSHHostKeyTrustStore {
    private let backingStore = TrustOnFirstUseStore()
    private let requestRecorder = HostKeyChangeRequestRecorder()

    func lookupHostKey(
        endpointHost: String,
        endpointPort: UInt16
    ) async throws -> SSHTrustedHostKey? {
        await self.backingStore.lookup(host: endpointHost, port: endpointPort)
    }

    func storeHostKey(_ request: SSHHostKeyStoreRequest) async throws {
        try await self.backingStore.store(request)
    }

    func decisionForChangedHostKey(
        _ request: SSHHostKeyChangeRequest
    ) async throws -> SSHHostKeyChangeDecision {
        await self.requestRecorder.record(request)
        return .replaceStoredHostKey
    }

    func seed(
        host: String,
        port: UInt16,
        trustedHostKey: SSHTrustedHostKey
    ) async {
        await self.backingStore.store(
            host: host,
            port: port,
            trustedHostKey: trustedHostKey
        )
    }

    func storedHostKey(host: String, port: UInt16) async -> SSHTrustedHostKey? {
        await self.backingStore.lookup(host: host, port: port)
    }

    func saveCountObserved() async -> Int {
        await self.backingStore.saveCountObserved()
    }

    func recordedRequest() async -> SSHHostKeyChangeRequest? {
        await self.requestRecorder.recordedRequest()
    }

    func recordedStoreRequest() async -> SSHHostKeyStoreRequest? {
        await self.backingStore.recordedStoreRequest()
    }
}

actor RacingTrustOnFirstUseStore: SSHHostKeyTrustStore {
    private let backingStore = TrustOnFirstUseStore()
    private var pendingStoreRequest: SSHHostKeyStoreRequest?
    private var pendingStoreRequestContinuation: CheckedContinuation<SSHHostKeyStoreRequest, Never>?
    private var resumeStoreContinuation: CheckedContinuation<Void, Never>?
    private var shouldSuspendNextReplacementWrite = true

    func lookupHostKey(
        endpointHost: String,
        endpointPort: UInt16
    ) async throws -> SSHTrustedHostKey? {
        await self.backingStore.lookup(host: endpointHost, port: endpointPort)
    }

    func storeHostKey(_ request: SSHHostKeyStoreRequest) async throws {
        if request.expectedStoredHostKey != nil,
            self.shouldSuspendNextReplacementWrite
        {
            self.shouldSuspendNextReplacementWrite = false

            if let continuation = self.pendingStoreRequestContinuation {
                self.pendingStoreRequestContinuation = nil
                continuation.resume(returning: request)
            } else {
                self.pendingStoreRequest = request
            }

            await withCheckedContinuation { continuation in
                self.resumeStoreContinuation = continuation
            }
        }

        try await self.backingStore.store(request)
    }

    func decisionForChangedHostKey(
        _ request: SSHHostKeyChangeRequest
    ) async throws -> SSHHostKeyChangeDecision {
        .replaceStoredHostKey
    }

    func seed(
        host: String,
        port: UInt16,
        trustedHostKey: SSHTrustedHostKey
    ) async {
        await self.backingStore.store(
            host: host,
            port: port,
            trustedHostKey: trustedHostKey
        )
    }

    func forceConcurrentStoreUpdate(
        host: String,
        port: UInt16,
        trustedHostKey: SSHTrustedHostKey
    ) async {
        await self.backingStore.store(
            host: host,
            port: port,
            trustedHostKey: trustedHostKey
        )
    }

    func storedHostKey(host: String, port: UInt16) async -> SSHTrustedHostKey? {
        await self.backingStore.lookup(host: host, port: port)
    }

    func waitForSuspendedReplacementStoreRequest() async -> SSHHostKeyStoreRequest {
        if let pendingStoreRequest = self.pendingStoreRequest {
            self.pendingStoreRequest = nil
            return pendingStoreRequest
        }

        return await withCheckedContinuation { continuation in
            self.pendingStoreRequestContinuation = continuation
        }
    }

    func resumeSuspendedReplacementStore() {
        self.resumeStoreContinuation?.resume()
        self.resumeStoreContinuation = nil
    }
}

final class SSHClientLogEventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [SSHClientLogEvent] = []

    func record(_ event: SSHClientLogEvent) {
        self.lock.lock()
        defer { self.lock.unlock() }
        self.events.append(event)
    }

    func snapshot() -> [SSHClientLogEvent] {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.events
    }
}

actor SSHProxyJumpFactoryRecorder {
    private var endpoints: [SSHSocketEndpoint] = []
    private var upstreamHosts: [String] = []
    private var closeCount = 0

    func record(endpoint: SSHSocketEndpoint, upstreamConnection: SSHConnection) {
        self.endpoints.append(endpoint)
        self.upstreamHosts.append(upstreamConnection.metadata.endpointHost)
    }

    func recordClose() {
        self.closeCount += 1
    }

    func recordedEndpoints() -> [SSHSocketEndpoint] {
        self.endpoints
    }

    func recordedUpstreamHosts() -> [String] {
        self.upstreamHosts
    }

    func recordedCloseCount() -> Int {
        self.closeCount
    }
}

actor SSHProxyJumpTransportQueue {
    private var transports: [any SSHByteStreamTransport]

    init(_ transports: [any SSHByteStreamTransport]) {
        self.transports = transports
    }

    func popNext() -> (any SSHByteStreamTransport) {
        self.transports.removeFirst()
    }
}

actor SSHRouteTeardownOrderRecorder {
    private var events: [String] = []

    func record(_ event: String) {
        self.events.append(event)
    }

    func recordedEvents() -> [String] {
        self.events
    }
}

private struct HostKeyTrustTimedOut: Error, Sendable {
}

actor CloseStallingConnectionFixtureTransport: SSHByteStreamTransport {
    private let base: ConnectionFixtureMockSSHByteStreamTransport
    private var shouldBlockNextSend = false
    private var blockedSendContinuations: [CheckedContinuation<Void, Never>] = []
    private var closeCount = 0

    init(base: ConnectionFixtureMockSSHByteStreamTransport) {
        self.base = base
    }

    func armBlockNextSend() {
        self.shouldBlockNextSend = true
    }

    func send(_ bytes: [UInt8], endOfStream: Bool) async throws {
        if self.shouldBlockNextSend {
            self.shouldBlockNextSend = false
            await withCheckedContinuation { continuation in
                self.blockedSendContinuations.append(continuation)
            }
            throw CancellationError()
        }

        try await self.base.send(bytes, endOfStream: endOfStream)
    }

    func receive(atLeast minimum: Int, atMost maximum: Int) async throws -> SSHByteStreamChunk {
        try await self.base.receive(atLeast: minimum, atMost: maximum)
    }

    func close() async {
        self.closeCount += 1

        let blockedSendContinuations = self.blockedSendContinuations
        self.blockedSendContinuations.removeAll(keepingCapacity: false)
        for continuation in blockedSendContinuations {
            continuation.resume()
        }

        await self.base.close()
    }

    func closeCountObserved() -> Int {
        self.closeCount
    }
}

actor EmptyReceiveDelayTransport: SSHByteStreamTransport {
    private let base: ConnectionFixtureMockSSHByteStreamTransport
    private let emptyReceiveDelayNanoseconds: UInt64

    init(
        base: ConnectionFixtureMockSSHByteStreamTransport,
        emptyReceiveDelayNanoseconds: UInt64
    ) {
        self.base = base
        self.emptyReceiveDelayNanoseconds = emptyReceiveDelayNanoseconds
    }

    func send(_ bytes: [UInt8], endOfStream: Bool) async throws {
        try await self.base.send(bytes, endOfStream: endOfStream)
    }

    func receive(atLeast minimum: Int, atMost maximum: Int) async throws -> SSHByteStreamChunk {
        if await self.base.remainingReceiveChunkCount() == 0 {
            try await Task.sleep(nanoseconds: self.emptyReceiveDelayNanoseconds)
        }

        return try await self.base.receive(atLeast: minimum, atMost: maximum)
    }
}

private func makeKnownHostsLine(
    hosts: String,
    algorithm: String,
    trustedHostKey: SSHTrustedHostKey
) -> String {
    "\(hosts) \(algorithm) \(Data(trustedHostKey.rawRepresentation).base64EncodedString())"
}

private func connectionFailure(from error: any Error) -> SSHConnectionFailure? {
    guard case let .connectionFailed(failure)? = error as? SSHClientError else {
        return nil
    }

    return failure
}

private func makeAuthenticatedClientFixtureTransport(
    emptyReceiveBehavior: EmptyReceiveBehavior = .endOfStream
) throws
    -> ConnectionFixtureMockSSHByteStreamTransport {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    return ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ],
        emptyReceiveBehavior: emptyReceiveBehavior
    )
}

private func operationFailure(from error: any Error) -> SSHOperationFailure? {
    guard case let .operationFailed(failure)? = error as? SSHClientError else {
        return nil
    }

    return failure
}

private func makeOpenShellFixtureTransport(
    remoteChannelID: UInt32 = 73
) throws -> ConnectionFixtureMockSSHByteStreamTransport {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: remoteChannelID,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    return ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            ptySuccessPayload,
            shellSuccessPayload,
        ]
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeSFTPChannelDataPayload(_ message: SSHSFTPMessage) throws -> [UInt8] {
    let packet = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(message)
    )
    return try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: packet
            )
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeExtendedReplyMessage(
    requestID: UInt32,
    attributes: SSHSFTPFileSystemAttributes
) -> SSHSFTPMessage {
    var writer = SSHWireWriter()
    writer.write(uint64: attributes.blockSize)
    writer.write(uint64: attributes.fundamentalBlockSize)
    writer.write(uint64: attributes.totalBlocks)
    writer.write(uint64: attributes.freeBlocks)
    writer.write(uint64: attributes.availableBlocks)
    writer.write(uint64: attributes.totalFileNodes)
    writer.write(uint64: attributes.freeFileNodes)
    writer.write(uint64: attributes.availableFileNodes)
    writer.write(uint64: attributes.fileSystemID)
    writer.write(uint64: attributes.flags.rawValue)
    writer.write(uint64: attributes.maximumFilenameLength)
    return .extendedReply(
        SSHSFTPExtendedReplyMessage(
            requestID: requestID,
            data: writer.bytes
        )
    )
}

private func extractSentSFTPMessages(
    from transport: ConnectionFixtureMockSSHByteStreamTransport,
    recipientChannel: UInt32? = nil
) async throws -> [SSHSFTPMessage] {
    let sentPayloads = await transport.sentPayloads()
    let decryptionContext = try makeConnectionFixtureClientToServerDecryptionContext(
        sentPayloads: sentPayloads
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: decryptionContext.algorithms,
        keyMaterial: decryptionContext.keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(4).joined()))

    var messages: [SSHSFTPMessage] = []
    while let packet = try parser.nextPacket() {
        guard packet.payload.first == SSHConnectionMessageID.channelData.rawValue else {
            continue
        }
        let connectionMessage = try SSHConnectionMessageParser().parse(packet.payload)
        guard case let .channelData(channelData) = connectionMessage else {
            continue
        }
        if let recipientChannel, channelData.recipientChannel != recipientChannel {
            continue
        }

        var packetParser = SSHSFTPPacketParser()
        packetParser.append(bytes: channelData.data)
        while let payload = try packetParser.nextPayload() {
            messages.append(try SSHSFTPMessageParser().parse(payload))
        }
    }

    return messages
}

private func sentEncryptedPayloadIDsAfterConnectionSetup(
    from transport: ConnectionFixtureMockSSHByteStreamTransport
) async throws -> [UInt8] {
    let sentPayloads = await transport.sentPayloads()
    let decryptionContext = try makeConnectionFixtureClientToServerDecryptionContext(
        sentPayloads: sentPayloads
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: decryptionContext.algorithms,
        keyMaterial: decryptionContext.keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(4).joined()))

    var messageIDs: [UInt8] = []
    while let packet = try parser.nextPacket() {
        if let messageID = packet.payload.first {
            messageIDs.append(messageID)
        }
    }
    return messageIDs
}

@Test
func sshClientConfigurationUsesCurrentProfileAutomaticRekeyByDefault() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    #expect(configuration.automaticRekeyPolicy == .currentProfileDefault)
}

@Test
func sshClientConfigurationStoresCustomAutomaticRekeyPolicy() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        automaticRekeyPolicy: .init(
            outboundPacketThreshold: nil,
            inboundPacketThreshold: 42,
            idleTimeInterval: 30
        )
    )

    #expect(
        configuration.automaticRekeyPolicy
            == SSHAutomaticRekeyPolicy(
                outboundPacketThreshold: nil,
                inboundPacketThreshold: 42,
                idleTimeInterval: 30
            )
    )
}

@Test
func sshClientConfigurationStoresCompressionPreference() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        compressionPreference: .delayedZlib
    )

    #expect(configuration.compressionPreference == .delayedZlib)
}

@Test
func sshClientConfigurationStoresPlainZlibCompressionPreference() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        compressionPreference: .zlib
    )

    #expect(configuration.compressionPreference == .zlib)
}

@Test
func sshCompressionPreferenceAdvertisesExpectedCompressionAlgorithms() {
    #expect(SSHCompressionPreference.disabled.keyExchangeCompressionAlgorithms == ["none"])
    #expect(SSHCompressionPreference.zlib.keyExchangeCompressionAlgorithms == ["zlib", "none"])
    #expect(
        SSHCompressionPreference.delayedZlib.keyExchangeCompressionAlgorithms
            == ["zlib@openssh.com", "none"]
    )
}

@Test
func sshTimeoutPolicyCurrentProfileDefaultBoundsConnectionSetupOnly() {
    let policy = SSHTimeoutPolicy()
    let internalPolicy = SSHInternalTimeoutPolicy(policy)

    #expect(SSHTimeoutPolicy.defaultConnectionSetupTimeInterval == 30)
    #expect(SSHTimeoutPolicy.currentProfileDefault == policy)
    #expect(policy.connectionSetupTimeInterval == 30)
    #expect(policy.responseTimeInterval == nil)
    #expect(internalPolicy.connectionSetupTimeoutNanoseconds == 30_000_000_000)
    #expect(internalPolicy.responseTimeoutNanoseconds == nil)
    #expect(SSHTimeoutPolicy.disabled.connectionSetupTimeInterval == nil)
    #expect(SSHTimeoutPolicy.disabled.responseTimeInterval == nil)
}

@Test
func sshClientConfigurationDefaultsToCurrentTimeoutProfile() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    #expect(configuration.timeoutPolicy == .currentProfileDefault)
}

@Test
func sshAuthenticationMethodDiscoveryConfigurationDefaultsToCurrentTimeoutProfile() {
    let configuration = SSHAuthenticationMethodDiscoveryConfiguration(
        host: "example.com",
        username: "root",
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    #expect(configuration.timeoutPolicy == .currentProfileDefault)
}

@Test
func sshClientConfigurationStoresTimeoutPolicy() {
    let timeoutPolicy = SSHTimeoutPolicy(
        connectionSetupTimeInterval: 15,
        responseTimeInterval: 2.5
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        timeoutPolicy: timeoutPolicy
    )

    #expect(configuration.timeoutPolicy == timeoutPolicy)
}

@Test
func sshClientConfigurationStoresKeepalivePolicy() {
    let keepalivePolicy = SSHKeepalivePolicy(interval: 30)
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        keepalivePolicy: keepalivePolicy
    )

    #expect(configuration.keepalivePolicy == keepalivePolicy)
}

@Test
func sshClientConfigurationStoresLegacyAlgorithmOptions() {
    let legacyAlgorithmOptions = SSHLegacyAlgorithmOptions.sshRSA
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        legacyAlgorithmOptions: legacyAlgorithmOptions
    )

    #expect(configuration.legacyAlgorithmOptions == legacyAlgorithmOptions)
}

@Test
func sshProxyJumpHostStoresLegacyAlgorithmOptions() {
    let legacyAlgorithmOptions = SSHLegacyAlgorithmOptions.sshRSA
    let jumpHost = SSHProxyJumpHost(
        host: "bastion.example.com",
        username: "jumper",
        authentication: .password("jump"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        legacyAlgorithmOptions: legacyAlgorithmOptions
    )

    #expect(jumpHost.legacyAlgorithmOptions == legacyAlgorithmOptions)
}

@Test
func sshProxyJumpHostStoresKeepalivePolicy() {
    let keepalivePolicy = SSHKeepalivePolicy(interval: 20)
    let jumpHost = SSHProxyJumpHost(
        host: "bastion.example.com",
        username: "jumper",
        authentication: .password("jump"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        keepalivePolicy: keepalivePolicy
    )

    #expect(jumpHost.keepalivePolicy == keepalivePolicy)
}

@Test
func sshProxyJumpHostDefaultsToCurrentTimeoutProfile() {
    let jumpHost = SSHProxyJumpHost(
        host: "bastion.example.com",
        username: "jumper",
        authentication: .password("jump"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    #expect(jumpHost.timeoutPolicy == .currentProfileDefault)
}

@Test
func sshClientConfigurationDefaultsToNoProxyJumpHosts() {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    #expect(configuration.proxyJumpHosts.isEmpty)
}

@Test
func sshClientConfigurationStoresProxyJumpHosts() {
    let jumpHost = SSHProxyJumpHost(
        host: "bastion.example.com",
        username: "jumper",
        authentication: .password("jump"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )
    let configuration = SSHClientConfiguration(
        host: "db.internal",
        username: "root",
        authentication: .password("target"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        proxyJumpHosts: [jumpHost]
    )

    #expect(configuration.proxyJumpHosts == [jumpHost])
}

@Test
func sshClientConnectsWithConfiguredKeepalivePolicy() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let keepaliveFailurePayload = try SSHConnectionMessageSerializer().serialize(
        .requestFailure(SSHGlobalRequestFailureMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            keepaliveFailurePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        keepalivePolicy: SSHKeepalivePolicy(interval: backgroundKeepaliveTestInterval)
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        logHandler: .disabled,
        transportHandleFactory: { _ in
            SSHClientTransportHandle(transport: transport)
        }
    )
    let baselineSentCount = await transport.sentPayloads().count

    #expect(
        await waitForSentPayloadCount(
            on: transport,
            minimumCount: baselineSentCount + 1,
            maxAttempts: backgroundKeepaliveObservationAttempts,
            sleepNanoseconds: backgroundKeepaliveObservationSleepNanoseconds
        )
    )

    let sentPayloads = await transport.sentPayloads()
    let decryptionContext = try makeConnectionFixtureClientToServerDecryptionContext(
        sentPayloads: sentPayloads
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: decryptionContext.algorithms,
        keyMaterial: decryptionContext.keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(4).joined()))

    var sawKeepalive = false
    while let packet = try parser.nextPacket() {
        guard packet.payload.first == SSHConnectionMessageID.globalRequest.rawValue else {
            continue
        }

        let request = try #require({
            let message = try SSHConnectionMessageParser().parse(packet.payload)
            if case let .globalRequest(value) = message {
                return value
            }
            return nil
        }())
        if request.requestName == "keepalive@openssh.com" {
            sawKeepalive = true
            #expect(request.wantReply)
        }
    }

    #expect(sawKeepalive)
    await connection.close()
}

@Test
func sshClientClosesConnectionLifetimeAfterBackgroundKeepaliveFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        keepalivePolicy: SSHKeepalivePolicy(interval: backgroundKeepaliveTestInterval)
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        logHandler: .disabled,
        transportHandleFactory: { _ in
            SSHClientTransportHandle(transport: transport)
        }
    )
    let baselineSentCount = await transport.sentPayloads().count

    #expect(
        await waitForSentPayloadCount(
            on: transport,
            minimumCount: baselineSentCount + 1,
            maxAttempts: backgroundKeepaliveObservationAttempts,
            sleepNanoseconds: backgroundKeepaliveObservationSleepNanoseconds
        )
    )
    #expect(
        await waitUntil(
            maxAttempts: backgroundKeepaliveObservationAttempts,
            sleepNanoseconds: backgroundKeepaliveObservationSleepNanoseconds
        ) {
            await transport.closeCountObserved() == 1
        }
    )
    let sentPayloads = await transport.sentPayloads()
    let decryptionContext = try makeConnectionFixtureClientToServerDecryptionContext(
        sentPayloads: sentPayloads
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: decryptionContext.algorithms,
        keyMaterial: decryptionContext.keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(4).joined()))

    var sawDisconnect = false
    while let packet = try parser.nextPacket() {
        if packet.payload.first == SSHTransportMessageID.disconnect.rawValue {
            sawDisconnect = true
        }
    }
    #expect(!sawDisconnect)

    do {
        _ = try await connection.execute("true")
        Issue.record("Expected background keepalive failure to end the connection lifetime.")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }

    await connection.close()
}

@Test
func sshClientWithConnectionFinishesAfterGracefulCloseTimeoutWhenDisconnectStalls() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let baseTransport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ],
        emptyReceiveBehavior: .waitForAppendedChunks
    )
    let transport = CloseStallingConnectionFixtureTransport(base: baseTransport)
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    try await withOptionalTimeout(
        nanoseconds: 5_000_000_000,
        timeoutError: SSHTimeoutError.connectionSetup(durationNanoseconds: 5_000_000_000)
    ) {
        try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { _ in
            await transport.armBlockNextSend()
        }
    }

    #expect(await transport.closeCountObserved() == 1)
}

@Test
func sshClientConnectsThroughExplicitProxyJumpHosts() async throws {
    let jumpServiceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let jumpAuthSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let secondJumpServiceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let secondJumpAuthSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let finalServiceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let finalAuthSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let finalOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 42,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let finalChannelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let finalStdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("proxy-jump-ok\n".utf8)
            )
        )
    )
    let finalExitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 0, exitStatus: 0)
    )
    let finalEOFPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let finalClosePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )

    let firstHopTransport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            jumpServiceAcceptPayload,
            jumpAuthSuccessPayload,
        ]
    )
    let secondHopTransport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            secondJumpServiceAcceptPayload,
            secondJumpAuthSuccessPayload,
        ]
    )
    let finalTransport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            finalServiceAcceptPayload,
            finalAuthSuccessPayload,
            finalOpenConfirmationPayload,
            finalChannelSuccessPayload,
            finalStdoutPayload,
            finalExitStatusPayload,
            finalEOFPayload,
            finalClosePayload,
        ]
    )
    let recorder = SSHProxyJumpFactoryRecorder()
    let jumpHosts = [
        SSHProxyJumpHost(
            host: "jump-1.example.com",
            username: "jump1",
            authentication: .password("jump-1"),
            hostKeyPolicy: .acceptAnyVerifiedHostKey
        ),
        SSHProxyJumpHost(
            host: "jump-2.example.com",
            username: "jump2",
            authentication: .password("jump-2"),
            hostKeyPolicy: .acceptAnyVerifiedHostKey
        ),
    ]
    let configuration = SSHClientConfiguration(
        host: "db.internal",
        username: "root",
        authentication: .password("target"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        proxyJumpHosts: jumpHosts
    )
    let jumpTransports = SSHProxyJumpTransportQueue([secondHopTransport, finalTransport])

    let finalConnection = try await SSHClient.connect(
        configuration: configuration,
        logHandler: .disabled,
        transportHandleFactory: { endpoint in
            #expect(endpoint.host == "jump-1.example.com")
            return SSHClientTransportHandle(transport: firstHopTransport)
        },
        jumpTransportFactory: { upstreamConnection, endpoint in
            await recorder.record(endpoint: endpoint, upstreamConnection: upstreamConnection)
            let transport = await jumpTransports.popNext()
            return SSHClientTransportHandle(
                transport: transport,
                closeOperation: {
                    await recorder.recordClose()
                }
            )
        }
    )

    let execResult = try await finalConnection.execute("echo proxy-jump-ok")
    #expect(execResult.standardOutput == Array("proxy-jump-ok\n".utf8))
    #expect(execResult.exitStatus == 0)
    await finalConnection.close()

    #expect(
        await recorder.recordedEndpoints()
            == [
                SSHSocketEndpoint(host: "jump-2.example.com", port: 22),
                SSHSocketEndpoint(host: "db.internal", port: 22),
            ]
    )
    #expect(await recorder.recordedUpstreamHosts() == ["jump-1.example.com", "jump-2.example.com"])
    #expect(await recorder.recordedCloseCount() == 2)
}

@Test
func sshClientProxyJumpFirstHopRouteSetupTimeoutUsesHopPolicy() async throws {
    let configuration = SSHClientConfiguration(
        host: "db.internal",
        username: "root",
        authentication: .password("target"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        proxyJumpHosts: [
            SSHProxyJumpHost(
                host: "jump-1.example.com",
                username: "jump1",
                authentication: .password("jump-1"),
                hostKeyPolicy: .acceptAnyVerifiedHostKey,
                timeoutPolicy: SSHTimeoutPolicy(connectionSetupTimeInterval: 0.05)
            )
        ]
    )
    let timeoutRecorder = RouteSetupTimeoutRecorder()

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            logHandler: .disabled,
            transportHandleFactory: { _ in
                try await suspendUntilRouteSetupTimeoutCancellation(recording: timeoutRecorder)
                return SSHClientTransportHandle(
                    transport: try makeAuthenticatedClientFixtureTransport()
                )
            },
            jumpTransportFactory: { _, _ in
                Issue.record("Final ProxyJump route should not open after first-hop timeout")
                return SSHClientTransportHandle(
                    transport: try makeAuthenticatedClientFixtureTransport()
                )
            }
        )
        Issue.record("Expected first ProxyJump hop route setup to time out")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.code == .timeout)
        #expect(failure.stage == .identification)
        #expect(failure.diagnostics.endpointHost == "jump-1.example.com")
    }

    #expect(await timeoutRecorder.cancellationCountObserved() == 1)
    #expect(await timeoutRecorder.completionCountObserved() == 0)
}

@Test
func sshClientProxyJumpFinalRouteSetupTimeoutUsesTargetPolicyAndClosesHops() async throws {
    let firstHopTransport = try makeAuthenticatedClientFixtureTransport()
    let configuration = SSHClientConfiguration(
        host: "db.internal",
        username: "root",
        authentication: .password("target"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        timeoutPolicy: SSHTimeoutPolicy(connectionSetupTimeInterval: 0.05),
        proxyJumpHosts: [
            SSHProxyJumpHost(
                host: "jump-1.example.com",
                username: "jump1",
                authentication: .password("jump-1"),
                hostKeyPolicy: .acceptAnyVerifiedHostKey
            )
        ]
    )
    let timeoutRecorder = RouteSetupTimeoutRecorder()

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            logHandler: .disabled,
            transportHandleFactory: { _ in
                SSHClientTransportHandle(transport: firstHopTransport)
            },
            jumpTransportFactory: { _, endpoint in
                #expect(endpoint == SSHSocketEndpoint(host: "db.internal", port: 22))
                try await suspendUntilRouteSetupTimeoutCancellation(recording: timeoutRecorder)
                return SSHClientTransportHandle(
                    transport: try makeAuthenticatedClientFixtureTransport()
                )
            }
        )
        Issue.record("Expected final ProxyJump route setup to time out")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.code == .timeout)
        #expect(failure.stage == .identification)
        #expect(failure.diagnostics.endpointHost == "db.internal")
    }

    #expect(await timeoutRecorder.cancellationCountObserved() == 1)
    #expect(await timeoutRecorder.completionCountObserved() == 0)
    #expect(await firstHopTransport.closeCountObserved() == 1)
}

@Test
func sshClientDirectHostKeyTrustTimeoutClosesTransport() async throws {
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: []
    )
    let timeoutRecorder = RouteSetupTimeoutRecorder()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("target"),
        hostKeyPolicy: .callback { _ in
            try await suspendUntilRouteSetupTimeoutCancellation(recording: timeoutRecorder)
            return .callback
        },
        timeoutPolicy: SSHTimeoutPolicy(connectionSetupTimeInterval: 0.05)
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            logHandler: .disabled,
            transportHandleFactory: { endpoint in
                #expect(endpoint == SSHSocketEndpoint(host: "example.com", port: 22))
                return SSHClientTransportHandle(transport: transport)
            }
        )
        Issue.record("Expected direct host-key trust wait to time out")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.code == .timeout)
        #expect(failure.diagnostics.endpointHost == "example.com")
    }

    #expect(await timeoutRecorder.cancellationCountObserved() == 1)
    #expect(await timeoutRecorder.completionCountObserved() == 0)
    #expect(await transport.closeCountObserved() == 1)
    #expect(await transport.sentPayloads().count == 3)
    #expect(await transport.sentPayloadEndOfStreamFlags().contains(true) == false)
}

@Test
func sshClientConnectionProxyHostKeyTrustTimeoutClosesProxyRootTransport() async throws {
    let targetTransport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: []
    )
    let proxyTransport = ScriptedProxyHandshakeTransport(
        proxyResponsesBySend: [
            Array("HTTP/1.1 200 Connection Established\r\n\r\n".utf8),
        ],
        sshTransport: targetTransport
    )
    let timeoutRecorder = RouteSetupTimeoutRecorder()
    let configuration = SSHClientConfiguration(
        host: "ssh.internal",
        username: "root",
        authentication: .password("target"),
        hostKeyPolicy: .callback { _ in
            try await suspendUntilRouteSetupTimeoutCancellation(recording: timeoutRecorder)
            return .callback
        },
        timeoutPolicy: SSHTimeoutPolicy(connectionSetupTimeInterval: 0.05),
        connectionProxy: .httpConnect(
            SSHHTTPConnectConnectionProxy(host: "proxy.example.com", port: 3128)
        )
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            logHandler: .disabled,
            transportFactory: { endpoint in
                #expect(endpoint == SSHSocketEndpoint(host: "proxy.example.com", port: 3128))
                return proxyTransport
            }
        )
        Issue.record("Expected proxied host-key trust wait to time out")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.code == .timeout)
        #expect(failure.diagnostics.endpointHost == "ssh.internal")
    }

    #expect(await timeoutRecorder.cancellationCountObserved() == 1)
    #expect(await timeoutRecorder.completionCountObserved() == 0)
    #expect(await proxyTransport.closeCountObserved() == 1)
    #expect(await targetTransport.closeCountObserved() == 1)
    #expect(await targetTransport.sentPayloads().count == 3)
    #expect(await targetTransport.sentPayloadEndOfStreamFlags().contains(true) == false)
}

@Test
func sshClientProxyJumpFinalHostKeyTrustTimeoutClosesFinalEdgeBeforeRootHop()
    async throws {
    let firstHopTransport = try makeAuthenticatedClientFixtureTransport()
    let finalTransport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: []
    )
    let timeoutRecorder = RouteSetupTimeoutRecorder()
    let teardownRecorder = SSHRouteTeardownOrderRecorder()
    let configuration = SSHClientConfiguration(
        host: "db.internal",
        username: "root",
        authentication: .password("target"),
        hostKeyPolicy: .callback { _ in
            try await suspendUntilRouteSetupTimeoutCancellation(recording: timeoutRecorder)
            return .callback
        },
        timeoutPolicy: SSHTimeoutPolicy(connectionSetupTimeInterval: 0.05),
        proxyJumpHosts: [
            SSHProxyJumpHost(
                host: "jump-1.example.com",
                username: "jump1",
                authentication: .password("jump-1"),
                hostKeyPolicy: .acceptAnyVerifiedHostKey
            )
        ]
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            logHandler: .disabled,
            transportHandleFactory: { _ in
                SSHClientTransportHandle(
                    transport: firstHopTransport,
                    closeOperation: {
                        await teardownRecorder.record("root-hop")
                    }
                )
            },
            jumpTransportFactory: { _, endpoint in
                #expect(endpoint == SSHSocketEndpoint(host: "db.internal", port: 22))
                return SSHClientTransportHandle(
                    transport: finalTransport,
                    closeOperation: {
                        await teardownRecorder.record("final-edge")
                    }
                )
            }
        )
        Issue.record("Expected final ProxyJump host-key trust wait to time out")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.code == .timeout)
        #expect(failure.diagnostics.endpointHost == "db.internal")
    }

    #expect(await timeoutRecorder.cancellationCountObserved() == 1)
    #expect(await timeoutRecorder.completionCountObserved() == 0)
    #expect(await finalTransport.closeCountObserved() == 1)
    #expect(await firstHopTransport.closeCountObserved() == 1)
    #expect(await finalTransport.sentPayloads().count == 3)
    #expect(await finalTransport.sentPayloadEndOfStreamFlags().contains(true) == false)
    #expect(await firstHopTransport.sentPayloadEndOfStreamFlags().contains(true) == false)
    #expect(
        !(try await sentEncryptedPayloadIDsAfterConnectionSetup(
            from: firstHopTransport
        ).contains(SSHTransportMessageID.disconnect.rawValue))
    )
    #expect(await teardownRecorder.recordedEvents() == ["final-edge", "root-hop"])
}

@Test
func sshClientTwoHopProxyJumpFinalHostKeyTrustTimeoutClosesRouteChildFirst()
    async throws {
    let firstHopTransport = try makeAuthenticatedClientFixtureTransport()
    let secondHopTransport = try makeAuthenticatedClientFixtureTransport()
    let finalTransport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: []
    )
    let timeoutRecorder = RouteSetupTimeoutRecorder()
    let teardownRecorder = SSHRouteTeardownOrderRecorder()
    let configuration = SSHClientConfiguration(
        host: "db.internal",
        username: "root",
        authentication: .password("target"),
        hostKeyPolicy: .callback { _ in
            try await suspendUntilRouteSetupTimeoutCancellation(recording: timeoutRecorder)
            return .callback
        },
        timeoutPolicy: SSHTimeoutPolicy(connectionSetupTimeInterval: 0.05),
        proxyJumpHosts: [
            SSHProxyJumpHost(
                host: "jump-1.example.com",
                username: "jump1",
                authentication: .password("jump-1"),
                hostKeyPolicy: .acceptAnyVerifiedHostKey
            ),
            SSHProxyJumpHost(
                host: "jump-2.example.com",
                username: "jump2",
                authentication: .password("jump-2"),
                hostKeyPolicy: .acceptAnyVerifiedHostKey
            ),
        ]
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            logHandler: .disabled,
            transportHandleFactory: { endpoint in
                #expect(endpoint == SSHSocketEndpoint(host: "jump-1.example.com", port: 22))
                return SSHClientTransportHandle(
                    transport: firstHopTransport,
                    closeOperation: {
                        await teardownRecorder.record("first-hop")
                    }
                )
            },
            jumpTransportFactory: { _, endpoint in
                switch endpoint {
                case SSHSocketEndpoint(host: "jump-2.example.com", port: 22):
                    return SSHClientTransportHandle(
                        transport: secondHopTransport,
                        closeOperation: {
                            await teardownRecorder.record("second-hop")
                        }
                    )
                case SSHSocketEndpoint(host: "db.internal", port: 22):
                    return SSHClientTransportHandle(
                        transport: finalTransport,
                        closeOperation: {
                            await teardownRecorder.record("final-edge")
                        }
                    )
                default:
                    Issue.record("Unexpected ProxyJump route endpoint \(endpoint)")
                    return SSHClientTransportHandle(
                        transport: ConnectionFixtureMockSSHByteStreamTransport(
                            serverPayloadsAfterNewKeys: []
                        )
                    )
                }
            }
        )
        Issue.record("Expected two-hop ProxyJump host-key trust wait to time out")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.code == .timeout)
        #expect(failure.diagnostics.endpointHost == "db.internal")
    }

    #expect(await timeoutRecorder.cancellationCountObserved() == 1)
    #expect(await timeoutRecorder.completionCountObserved() == 0)
    #expect(await finalTransport.closeCountObserved() == 1)
    #expect(await secondHopTransport.closeCountObserved() == 1)
    #expect(await firstHopTransport.closeCountObserved() == 1)
    #expect(await finalTransport.sentPayloads().count == 3)
    #expect(await finalTransport.sentPayloadEndOfStreamFlags().contains(true) == false)
    #expect(await secondHopTransport.sentPayloadEndOfStreamFlags().contains(true) == false)
    #expect(await firstHopTransport.sentPayloadEndOfStreamFlags().contains(true) == false)
    #expect(
        !(try await sentEncryptedPayloadIDsAfterConnectionSetup(
            from: secondHopTransport
        ).contains(SSHTransportMessageID.disconnect.rawValue))
    )
    #expect(
        !(try await sentEncryptedPayloadIDsAfterConnectionSetup(
            from: firstHopTransport
        ).contains(SSHTransportMessageID.disconnect.rawValue))
    )
    #expect(
        await teardownRecorder.recordedEvents()
            == ["final-edge", "second-hop", "first-hop"]
    )
}

@Test
func sshClientProxyJumpFinalHostKeyCallbackFailureClosesFinalEdgeBeforeRootHop()
    async throws {
    let firstHopTransport = try makeAuthenticatedClientFixtureTransport()
    let finalTransport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: []
    )
    let teardownRecorder = SSHRouteTeardownOrderRecorder()
    let configuration = SSHClientConfiguration(
        host: "db.internal",
        username: "root",
        authentication: .password("target"),
        hostKeyPolicy: .callback { _ in
            throw HostKeyTrustTimedOut()
        },
        proxyJumpHosts: [
            SSHProxyJumpHost(
                host: "jump-1.example.com",
                username: "jump1",
                authentication: .password("jump-1"),
                hostKeyPolicy: .acceptAnyVerifiedHostKey
            )
        ]
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            logHandler: .disabled,
            transportHandleFactory: { _ in
                SSHClientTransportHandle(
                    transport: firstHopTransport,
                    closeOperation: {
                        await teardownRecorder.record("root-hop")
                    }
                )
            },
            jumpTransportFactory: { _, endpoint in
                #expect(endpoint == SSHSocketEndpoint(host: "db.internal", port: 22))
                return SSHClientTransportHandle(
                    transport: finalTransport,
                    closeOperation: {
                        await teardownRecorder.record("final-edge")
                    }
                )
            }
        )
        Issue.record("Expected final host-key callback failure")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.code == .callbackFailed)
        #expect(failure.stage == .hostKeyTrust)
        #expect(failure.diagnostics.endpointHost == "db.internal")
    }

    #expect(await finalTransport.closeCountObserved() == 1)
    #expect(await firstHopTransport.closeCountObserved() == 1)
    #expect(await finalTransport.sentPayloads().count == 3)
    #expect(await firstHopTransport.sentPayloadEndOfStreamFlags().contains(true) == false)
    #expect(
        !(try await sentEncryptedPayloadIDsAfterConnectionSetup(
            from: firstHopTransport
        ).contains(SSHTransportMessageID.disconnect.rawValue))
    )
    #expect(await teardownRecorder.recordedEvents() == ["final-edge", "root-hop"])
}

@Test
func sshClientProxyJumpBackgroundKeepaliveFailureClosesDependentHop() async throws {
    let firstHopTransport = try makeAuthenticatedClientFixtureTransport(
        emptyReceiveBehavior: .waitForAppendedChunks
    )
    let finalTransport = try makeAuthenticatedClientFixtureTransport()
    let configuration = SSHClientConfiguration(
        host: "db.internal",
        username: "root",
        authentication: .password("target"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        keepalivePolicy: SSHKeepalivePolicy(interval: backgroundKeepaliveTestInterval),
        proxyJumpHosts: [
            SSHProxyJumpHost(
                host: "jump-1.example.com",
                username: "jump1",
                authentication: .password("jump-1"),
                hostKeyPolicy: .acceptAnyVerifiedHostKey
            )
        ]
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        logHandler: .disabled,
        transportHandleFactory: { endpoint in
            #expect(endpoint == SSHSocketEndpoint(host: "jump-1.example.com", port: 22))
            return SSHClientTransportHandle(transport: firstHopTransport)
        },
        jumpTransportFactory: { upstreamConnection, endpoint in
            #expect(upstreamConnection.metadata.endpointHost == "jump-1.example.com")
            #expect(endpoint == SSHSocketEndpoint(host: "db.internal", port: 22))
            return SSHClientTransportHandle(transport: finalTransport)
        }
    )
    let baselineSentCount = await finalTransport.sentPayloads().count

    #expect(
        await waitForSentPayloadCount(
            on: finalTransport,
            minimumCount: baselineSentCount + 1,
            maxAttempts: backgroundKeepaliveObservationAttempts,
            sleepNanoseconds: backgroundKeepaliveObservationSleepNanoseconds
        )
    )
    #expect(
        await waitUntil(
            maxAttempts: backgroundKeepaliveObservationAttempts,
            sleepNanoseconds: backgroundKeepaliveObservationSleepNanoseconds
        ) {
            let finalClosed = await finalTransport.closeCountObserved() == 1
            let firstHopClosed = await firstHopTransport.closeCountObserved() == 1
            return finalClosed && firstHopClosed
        }
    )
    let sentPayloadCountAtBackgroundFailure = await finalTransport.sentPayloads().count

    do {
        _ = try await connection.execute("true")
        Issue.record("Expected ProxyJump final connection to fail after background failure.")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }

    #expect(await finalTransport.sentPayloads().count == sentPayloadCountAtBackgroundFailure)
    #expect(await finalTransport.closeCountObserved() == 1)
    #expect(await firstHopTransport.closeCountObserved() == 1)

    await connection.close()
    #expect(await finalTransport.closeCountObserved() == 1)
    #expect(await firstHopTransport.closeCountObserved() == 1)
}

@Test
func sshClientExecutesCommandAndExpiresConnectionScope() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 42,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let stdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("Linux traversio-test\n".utf8)
            )
        )
    )
    let stderrPayload = try SSHConnectionMessageSerializer().serialize(
        .channelExtendedData(
            SSHChannelExtendedDataMessage(
                recipientChannel: 0,
                dataTypeCode: SSHChannelExtendedDataMessage.standardErrorDataTypeCode,
                data: Array("warning\n".utf8)
            )
        )
    )
    let exitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 0, exitStatus: 0)
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            stdoutPayload,
            stderrPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    var escapedConnection: SSHConnection?
    let result: SSHExecResult = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { endpoint, handler in
            #expect(endpoint.host == "example.com")
            #expect(endpoint.port == 22)
            return try await handler(transport)
        }
    ) { connection in
        escapedConnection = connection
        #expect(connection.metadata.endpointHost == "example.com")
        #expect(connection.metadata.endpointPort == 22)
        #expect(connection.metadata.username == "root")
        #expect(connection.metadata.clientIdentification == TraversioRelease.sshIdentificationRawValue)
        #expect(connection.metadata.remoteIdentification == "SSH-2.0-OpenSSH_9.9 test")
        #expect(connection.metadata.hostKeyAlgorithm == "ssh-ed25519")
        #expect(connection.metadata.hostKeyTrustMethod == .acceptAnyVerifiedHostKey)
        #expect(!connection.metadata.hostKeyFingerprintSHA256.isEmpty)
        let result = try await connection.execute("uname -a")
        let latency = try #require(await connection.latency)
        #expect(latency.source == .channelRequest)
        #expect(latency.roundTripTimeMilliseconds >= 0)
        return result
    }

    #expect(result.standardOutput == Array("Linux traversio-test\n".utf8))
    #expect(result.standardError == Array("warning\n".utf8))
    #expect(result.exitStatus == 0)
    #expect(result.didReceiveEOF)

    let connection = try #require(escapedConnection)
    do {
        _ = try await connection.execute("true")
        Issue.record("Expected connection scope to expire after withConnection returned")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
}

@Test
func sshClientExecuteSendsEnvironmentRequestsThroughPublicWrapper() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 42,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let environmentSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let execSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let stdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("en_US.UTF-8\n".utf8)
            )
        )
    )
    let exitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 0, exitStatus: 0)
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            environmentSuccessPayload,
            execSuccessPayload,
            stdoutPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )
    let environmentVariable = SSHSessionEnvironmentVariable(
        name: "LANG",
        value: "en_US.UTF-8"
    )

    let result: SSHExecResult = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        try await connection.execute(
            "printenv LANG",
            environment: [environmentVariable]
        )
    }

    #expect(result.standardOutput == Array("en_US.UTF-8\n".utf8))
    #expect(result.exitStatus == 0)
    #expect(result.didReceiveEOF)

    let sentPayloads = await transport.sentPayloads()
    let decryptionContext = try makeConnectionFixtureClientToServerDecryptionContext(
        sentPayloads: sentPayloads
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: decryptionContext.algorithms,
        keyMaterial: decryptionContext.keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(4).joined()))

    var channelRequests: [SSHChannelRequestMessage] = []
    while let packet = try parser.nextPacket() {
        guard packet.payload.first == SSHConnectionMessageID.channelRequest.rawValue else {
            continue
        }

        let message = try SSHConnectionMessageParser().parse(packet.payload)
        if case let .channelRequest(value) = message {
            channelRequests.append(value)
        }
    }

    #expect(channelRequests.count == 2)
    #expect(
        try SSHSessionRequestCoder().parseEnvironmentRequest(from: channelRequests[0])
            == environmentVariable
    )
    #expect(
        try SSHSessionRequestCoder().parseExecCommand(from: channelRequests[1])
            == "printenv LANG"
    )
}

@Test
func sshClientExecuteSurfacesExitSignalWhenRemoteCommandTerminatesBySignal() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 42,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let exitSignal = SSHSessionExitSignal(
        signal: .kill,
        didCoreDump: false,
        errorMessage: "killed by policy",
        languageTag: "en-US"
    )
    let exitSignalPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitSignalRequest(
            recipientChannel: 0,
            exitSignal: exitSignal
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            exitSignalPayload,
            eofPayload,
            closePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let result: SSHExecResult = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        try await connection.execute("sleep 10")
    }

    #expect(result.exitStatus == nil)
    #expect(result.exitSignal == exitSignal)
    #expect(result.didReceiveEOF)
}

@Test
func sshClientSessionTranscriptCancellationBestEffortClosesExecChannel() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 84,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
        ],
        receiveDelayNanoseconds: 200_000_000
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        transportFactory: { _ in
            transport
        }
    )
    let session = try await connection.openExec("sleep 300")
    let baselineSentCount = await transport.sentPayloads().count

    let task = Task {
        try await session.collectOutputUntilClose()
    }

    try? await Task.sleep(nanoseconds: 50_000_000)
    task.cancel()

    do {
        _ = try await task.value
        Issue.record("Expected transcript collection cancellation")
    } catch {
        #expect(error is CancellationError)
    }

    #expect(
        await waitForSentPayloadCount(
            on: transport,
            minimumCount: baselineSentCount + 1
        )
    )

    await connection.close()
}

@Test
func sshClientSessionEventSequenceCancellationBestEffortClosesExecChannel() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 61,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
        ],
        receiveDelayNanoseconds: 200_000_000
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        transportFactory: { _ in
            transport
        }
    )
    let session = try await connection.openExec("sleep 300")
    let baselineSentCount = await transport.sentPayloads().count

    let task = Task {
        for try await _ in session.events {
        }
    }

    try? await Task.sleep(nanoseconds: 50_000_000)
    task.cancel()

    do {
        try await task.value
        Issue.record("Expected event-sequence cancellation")
    } catch {
        #expect(error is CancellationError)
    }

    #expect(
        await waitForSentPayloadCount(
            on: transport,
            minimumCount: baselineSentCount + 1
        )
    )

    let sentPayloads = await transport.sentPayloads()
    let decryptionContext = try makeConnectionFixtureClientToServerDecryptionContext(
        sentPayloads: sentPayloads
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: decryptionContext.algorithms,
        keyMaterial: decryptionContext.keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(4).joined()))

    var packets: [SSHBinaryPacket] = []
    while let packet = try parser.nextPacket() {
        packets.append(packet)
    }

    let closePacket = try #require(packets.last)
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 61)
            )
    )

    await connection.close()
}

@Test
func sshClientOpensExecSessionStreamsEventsAndExpiresWrapperScope() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 42,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let stdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("Linux traversio-test\n".utf8)
            )
        )
    )
    let stderrPayload = try SSHConnectionMessageSerializer().serialize(
        .channelExtendedData(
            SSHChannelExtendedDataMessage(
                recipientChannel: 0,
                dataTypeCode: SSHChannelExtendedDataMessage.standardErrorDataTypeCode,
                data: Array("warning\n".utf8)
            )
        )
    )
    let exitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 0, exitStatus: 0)
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            stdoutPayload,
            stderrPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    var escapedSession: SSHSession?
    let events: [SSHSessionEvent] = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let session = try await connection.openExec("uname -a")
        escapedSession = session

        var streamedEvents: [SSHSessionEvent] = []
        for try await event in session.events {
            streamedEvents.append(event)
        }
        return streamedEvents
    }

    #expect(
        events == [
            .standardOutput(Array("Linux traversio-test\n".utf8)),
            .standardError(Array("warning\n".utf8)),
            .exitStatus(0),
            .endOfFile,
        ]
    )

    let session = try #require(escapedSession)
    do {
        _ = try await session.nextEvent()
        Issue.record("Expected exec session wrapper scope to expire after withConnection returned")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
}

@Test
func sshClientOpenExecSessionStreamsRemoteExitSignalEvent() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 42,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let exitSignal = SSHSessionExitSignal(
        signal: .terminate,
        didCoreDump: true,
        errorMessage: "terminated for test",
        languageTag: "en-US"
    )
    let exitSignalPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitSignalRequest(
            recipientChannel: 0,
            exitSignal: exitSignal
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            exitSignalPayload,
            eofPayload,
            closePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let events: [SSHSessionEvent] = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let session = try await connection.openExec("sleep 10")

        var streamedEvents: [SSHSessionEvent] = []
        for try await event in session.events {
            streamedEvents.append(event)
        }
        return streamedEvents
    }

    #expect(
        events == [
            .exitSignal(exitSignal),
            .endOfFile,
        ]
    )
}

@Test
func sshClientConnectsAndExplicitCloseEndsConnectionLifetime() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        transportFactory: { endpoint in
            #expect(endpoint.host == "example.com")
            #expect(endpoint.port == 22)
            return transport
        }
    )

    #expect(connection.metadata.endpointHost == "example.com")
    #expect(connection.metadata.endpointPort == 22)
    #expect(connection.metadata.username == "root")
    #expect(connection.metadata.remoteIdentification == "SSH-2.0-OpenSSH_9.9 test")
    #expect(connection.metadata.hostKeyTrustMethod == .acceptAnyVerifiedHostKey)

    await connection.close()
    await connection.close()

    #expect(await transport.closeCountObserved() == 1)

    do {
        _ = try await connection.execute("true")
        Issue.record("Expected connection to expire after explicit close")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
}

@Test
func sshClientWrapsConnectionSetupTimeoutIntoPublicConnectionFailure() async throws {
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [],
        receiveDelayNanoseconds: 200_000_000
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        timeoutPolicy: SSHTimeoutPolicy(connectionSetupTimeInterval: 0.05)
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            transportFactory: { _ in transport }
        )
        Issue.record("Expected connection setup timeout to produce a public failure")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.code == .timeout)
        #expect(failure.message.contains("SSH connection setup"))
        #expect(
            failure.stage == .identification || failure.stage == .keyExchange
        )
        #expect(
            failure.diagnostics.remoteIdentification == nil
                || failure.diagnostics.remoteIdentification == "SSH-2.0-OpenSSH_9.9 test"
        )
    }
    #expect(await transport.closeCountObserved() == 1)
}

@Test
func sshClientConnectionSetupTimeoutCoversTransportHandleFactory() async throws {
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        timeoutPolicy: SSHTimeoutPolicy(connectionSetupTimeInterval: 0.05)
    )
    let timeoutRecorder = RouteSetupTimeoutRecorder()

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            logHandler: .disabled,
            transportHandleFactory: { _ in
                try await suspendUntilRouteSetupTimeoutCancellation(recording: timeoutRecorder)
                let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
                    .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
                )
                let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
                    .success(SSHUserAuthenticationSuccessMessage())
                )
                return SSHClientTransportHandle(
                    transport: try makeConnectionFixtureTransport(
                        serverPayloadsAfterNewKeys: [
                            serviceAcceptPayload,
                            authSuccessPayload,
                        ]
                    )
                )
            }
        )
        Issue.record("Expected transport route setup to be covered by the connection setup timeout")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.code == .timeout)
        #expect(failure.stage == .identification)
        #expect(failure.message.contains("SSH connection setup"))
    }

    #expect(await timeoutRecorder.cancellationCountObserved() == 1)
    #expect(await timeoutRecorder.completionCountObserved() == 0)
}

@Test
func sshClientWrapsExecChannelOpenTimeoutIntoPublicOperationFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let baseTransport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ]
    )
    let transport = EmptyReceiveDelayTransport(
        base: baseTransport,
        emptyReceiveDelayNanoseconds: 200_000_000
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        timeoutPolicy: SSHTimeoutPolicy(responseTimeInterval: 0.05)
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        transportFactory: { _ in transport }
    )

    do {
        _ = try await connection.openExec("true")
        Issue.record("Expected exec channel-open timeout to produce a public failure")
    } catch {
        let failure = try #require(operationFailure(from: error))
        #expect(failure.scope == .session)
        #expect(failure.code == .timeout)
        #expect(failure.message.contains("channel open response"))
    }

    await connection.close()
}

@Test
func sshClientWrapsShellRequestTimeoutIntoPublicOperationFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 71,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let baseTransport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
        ]
    )
    let transport = EmptyReceiveDelayTransport(
        base: baseTransport,
        emptyReceiveDelayNanoseconds: 200_000_000
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        timeoutPolicy: SSHTimeoutPolicy(responseTimeInterval: 0.05)
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        transportFactory: { _ in transport }
    )

    do {
        _ = try await connection.openShell()
        Issue.record("Expected PTY request timeout to produce a public failure")
    } catch {
        let failure = try #require(operationFailure(from: error))
        #expect(failure.scope == .session)
        #expect(failure.code == .timeout)
        #expect(failure.message.contains("pty-req channel request reply"))
    }

    await connection.close()
}

@Test
func sshClientAuthenticatesEd25519PublicKey() async throws {
    let privateKey = try SSHEd25519PrivateKey(rawRepresentation: Array(0x01...0x20))
    let unsignedRequest = try privateKey.makeRequest(algorithmName: "ssh-ed25519")
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let publicKeyOKPayload = SSHUserAuthenticationMessageSerializer().serializePublicKeyOK(
        SSHPublicKeyAuthenticationOKMessage(
            algorithmName: unsignedRequest.algorithmName,
            publicKey: unsignedRequest.publicKey
        )
    )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            publicKeyOKPayload,
            successPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .ed25519PrivateKey(rawRepresentation: Array(0x01...0x20)),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        connection.metadata
    }

    #expect(metadata.username == "root")
    #expect(metadata.remoteIdentification == "SSH-2.0-OpenSSH_9.9 test")
    #expect(metadata.hostKeyTrustMethod == .acceptAnyVerifiedHostKey)
}

@Test
func sshClientAuthenticatesPublicKeyWithSignatureProvider() async throws {
    let privateKey = try SSHEd25519PrivateKey(rawRepresentation: Array(0x01...0x20))
    let unsignedRequest = try privateKey.makeRequest(algorithmName: "ssh-ed25519")
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let publicKeyOKPayload = SSHUserAuthenticationMessageSerializer().serializePublicKeyOK(
        SSHPublicKeyAuthenticationOKMessage(
            algorithmName: unsignedRequest.algorithmName,
            publicKey: unsignedRequest.publicKey
        )
    )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            publicKeyOKPayload,
            successPayload,
        ]
    )
    let requestRecorder = PublicKeySigningRequestRecorder()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .publicKey(
            algorithmNames: ["ssh-ed25519"],
            publicKey: unsignedRequest.publicKey,
            signatureProvider: { request in
                await requestRecorder.record(request)
                return try privateKey.signUserAuthenticationRequest(
                    request.signatureData,
                    algorithmName: request.algorithmName
                )
            }
        ),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        connection.metadata
    }

    let signingRequests = await requestRecorder.recordedRequests()
    let signingRequest = try #require(signingRequests.first)
    #expect(metadata.username == "root")
    #expect(signingRequest.username == "root")
    #expect(signingRequest.serviceName == "ssh-connection")
    #expect(signingRequest.algorithmName == "ssh-ed25519")
    #expect(signingRequest.publicKey == unsignedRequest.publicKey)
}

@Test
func sshClientFiltersLegacySSHRSAFromCallbackPublicKeyAuthenticationWhenDisabled() async throws {
    let privateKey = try SSHEd25519PrivateKey(rawRepresentation: Array(0x01...0x20))
    let unsignedRequest = try privateKey.makeRequest(algorithmName: "ssh-ed25519")
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let publicKeyOKPayload = SSHUserAuthenticationMessageSerializer().serializePublicKeyOK(
        SSHPublicKeyAuthenticationOKMessage(
            algorithmName: unsignedRequest.algorithmName,
            publicKey: unsignedRequest.publicKey
        )
    )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            publicKeyOKPayload,
            successPayload,
        ]
    )
    let requestRecorder = PublicKeySigningRequestRecorder()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .publicKey(
            algorithmNames: ["ssh-rsa", "ssh-ed25519"],
            publicKey: unsignedRequest.publicKey,
            signatureProvider: { request in
                await requestRecorder.record(request)
                return try privateKey.signUserAuthenticationRequest(
                    request.signatureData,
                    algorithmName: request.algorithmName
                )
            }
        ),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        connection.metadata
    }

    let signingRequest = try #require(await requestRecorder.recordedRequests().first)
    #expect(metadata.username == "root")
    #expect(signingRequest.algorithmName == "ssh-ed25519")
}

@Test
func sshClientAllowsLegacySSHRSAForCallbackPublicKeyAuthenticationWhenEnabled() async throws {
    let privateKey = try SSHRSAPrivateKey.generate(bitCount: 1024)
    let unsignedRequest = try privateKey.makeRequest(algorithmName: "ssh-rsa")
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let publicKeyOKPayload = SSHUserAuthenticationMessageSerializer().serializePublicKeyOK(
        SSHPublicKeyAuthenticationOKMessage(
            algorithmName: unsignedRequest.algorithmName,
            publicKey: unsignedRequest.publicKey
        )
    )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            publicKeyOKPayload,
            successPayload,
        ]
    )
    let requestRecorder = PublicKeySigningRequestRecorder()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .publicKey(
            algorithmNames: ["ssh-rsa", "rsa-sha2-512"],
            publicKey: unsignedRequest.publicKey,
            signatureProvider: { request in
                await requestRecorder.record(request)
                return try privateKey.signUserAuthenticationRequest(
                    request.signatureData,
                    algorithmName: request.algorithmName
                )
            }
        ),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        legacyAlgorithmOptions: .sshRSA
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        connection.metadata
    }

    let signingRequest = try #require(await requestRecorder.recordedRequests().first)
    #expect(metadata.username == "root")
    #expect(signingRequest.algorithmName == "ssh-rsa")
}

@Test
func sshClientWrapsPublicKeySignatureCallbackFailureIntoPublicConnectionFailure() async throws {
    let privateKey = try SSHEd25519PrivateKey(rawRepresentation: Array(0x01...0x20))
    let unsignedRequest = try privateKey.makeRequest(algorithmName: "ssh-ed25519")
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let publicKeyOKPayload = SSHUserAuthenticationMessageSerializer().serializePublicKeyOK(
        SSHPublicKeyAuthenticationOKMessage(
            algorithmName: unsignedRequest.algorithmName,
            publicKey: unsignedRequest.publicKey
        )
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            publicKeyOKPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .publicKey(
            algorithmNames: ["ssh-ed25519"],
            publicKey: unsignedRequest.publicKey,
            signatureProvider: { _ in
                throw CustomPublicKeySignatureCallbackError.rejected
            }
        ),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        let _: SSHConnectionMetadata = try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            connection.metadata
        }
        Issue.record("Expected public-key signature callback failure")
    } catch let SSHClientError.connectionFailed(failure) {
        #expect(failure.stage == .authentication)
        #expect(failure.code == .callbackFailed)
        #expect(failure.message.contains("public-key signature callback failed"))
        #expect(failure.message.contains("CustomPublicKeySignatureCallbackError"))
        #expect(failure.diagnostics.callbackFailure?.source == .publicKeySignature)
        #expect(
            failure.diagnostics.callbackFailure?.errorType
                == String(reflecting: CustomPublicKeySignatureCallbackError.self)
        )
    }
}

@Test
func sshClientFallsBackToLegacySSHRSAAuthenticationWhenEnabled() async throws {
    let privateKey = try SSHRSAPrivateKey.generate(bitCount: 1024)
    let legacyUnsignedRequest = try privateKey.makeRequest(algorithmName: "ssh-rsa")
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let bannerPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .banner(
            SSHUserAuthenticationBannerMessage(
                message: "Authorized use only",
                languageTag: "en-US"
            )
        )
    )
    let failurePayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .failure(
            SSHUserAuthenticationFailureMessage(
                authenticationsThatCanContinue: ["publickey"],
                partialSuccess: false
            )
        )
    )
    let publicKeyOKPayload = SSHUserAuthenticationMessageSerializer().serializePublicKeyOK(
        SSHPublicKeyAuthenticationOKMessage(
            algorithmName: legacyUnsignedRequest.algorithmName,
            publicKey: legacyUnsignedRequest.publicKey
        )
    )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            bannerPayload,
            failurePayload,
            publicKeyOKPayload,
            successPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .rsaPrivateKey(
            pkcs1DERRepresentation: privateKey.pkcs1DERRepresentation
        ),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        legacyAlgorithmOptions: .sshRSA
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        connection.metadata
    }

    #expect(metadata.username == "root")
    #expect(
        metadata.authenticationBanners == [
            SSHAuthenticationBanner(
                message: "Authorized use only",
                languageTag: "en-US"
            )
        ]
    )

    let sentPayloads = await transport.sentPayloads()
    let decryptionContext = try makeConnectionFixtureClientToServerDecryptionContext(
        sentPayloads: sentPayloads
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: decryptionContext.algorithms,
        keyMaterial: decryptionContext.keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    let encryptedPayloads = Array(sentPayloads.dropFirst(4).joined())
    parser.append(bytes: encryptedPayloads)
    _ = try #require(try parser.nextPacket())
    let modernUnsignedPacket = try #require(try parser.nextPacket())
    let legacyUnsignedPacket = try #require(try parser.nextPacket())
    let legacySignedPacket = try #require(try parser.nextPacket())

    let modernParsedRequest = try sshClientPublicKeyRequest(from: modernUnsignedPacket.payload)
    let legacyParsedUnsignedRequest = try sshClientPublicKeyRequest(
        from: legacyUnsignedPacket.payload
    )
    let legacyParsedSignedRequest = try sshClientPublicKeyRequest(
        from: legacySignedPacket.payload
    )
    let modernRequest = try #require(modernParsedRequest)
    let legacyUnsignedRequestMessage = try #require(legacyParsedUnsignedRequest)
    let legacySignedRequest = try #require(legacyParsedSignedRequest)
    let legacySignatureBlob = try #require(legacySignedRequest.signature)
    var signatureReader = SSHWireReader(bytes: legacySignatureBlob)
    let signatureAlgorithm = try signatureReader.readUTF8String()
    _ = try signatureReader.readString()
    #expect(signatureReader.isAtEnd)

    #expect(modernRequest.algorithmName == "rsa-sha2-512")
    #expect(legacyUnsignedRequestMessage.algorithmName == "ssh-rsa")
    #expect(legacySignedRequest.algorithmName == "ssh-rsa")
    #expect(signatureAlgorithm == "ssh-rsa")
}

@Test
func sshClientAuthenticatesKeyboardInteractive() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let infoRequestPayload = SSHUserAuthenticationMessageSerializer()
        .serializeKeyboardInteractiveInfoRequest(
            SSHKeyboardInteractiveInformationRequestMessage(
                name: "Password Authentication",
                instruction: "Enter your password",
                languageTag: "en-US",
                prompts: [
                    SSHKeyboardInteractivePromptMessage(
                        prompt: "Password: ",
                        shouldEcho: false
                    )
                ]
            )
        )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            infoRequestPayload,
            successPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .keyboardInteractive(
            submethods: ["pam"],
            responseProvider: { challenge in
                #expect(challenge.username == "root")
                #expect(challenge.serviceName == "ssh-connection")
                #expect(challenge.name == "Password Authentication")
                #expect(challenge.instruction == "Enter your password")
                #expect(
                    challenge.prompts
                        == [
                            SSHKeyboardInteractivePrompt(
                                prompt: "Password: ",
                                shouldEcho: false
                            )
                        ]
                )
                return ["s3cr3t"]
            }
        ),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        connection.metadata
    }

    #expect(metadata.username == "root")
    #expect(metadata.remoteIdentification == "SSH-2.0-OpenSSH_9.9 test")
    #expect(metadata.hostKeyTrustMethod == .acceptAnyVerifiedHostKey)
}

private func sshClientPublicKeyRequest(
    from payload: [UInt8]
) throws -> SSHPublicKeyAuthenticationRequest? {
    let parsedMessage = try SSHUserAuthenticationMessageParser().parse(payload)
    guard case let .request(message) = parsedMessage,
          case let .publicKey(request) = message.method else {
        return nil
    }

    return request
}

@Test
func sshClientWrapsKeyboardInteractiveResponseCallbackFailureIntoPublicConnectionFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let infoRequestPayload = SSHUserAuthenticationMessageSerializer()
        .serializeKeyboardInteractiveInfoRequest(
            SSHKeyboardInteractiveInformationRequestMessage(
                name: "Password Authentication",
                instruction: "Enter your password",
                languageTag: "en-US",
                prompts: [
                    SSHKeyboardInteractivePromptMessage(
                        prompt: "Password: ",
                        shouldEcho: false
                    )
                ]
            )
        )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            infoRequestPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .keyboardInteractive(
            submethods: ["pam"],
            responseProvider: { _ in
                throw CustomKeyboardInteractiveCallbackError.rejected
            }
        ),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        let _: SSHConnectionMetadata = try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            connection.metadata
        }
        Issue.record(
            "Expected keyboard-interactive callback failure to become a public connection failure"
        )
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.stage == .authentication)
        #expect(failure.code == .callbackFailed)
        #expect(failure.message.contains("keyboard-interactive response callback failed"))
        #expect(failure.message.contains("CustomKeyboardInteractiveCallbackError"))
        let callbackFailure = try #require(failure.diagnostics.callbackFailure)
        #expect(callbackFailure.source == .keyboardInteractiveResponse)
        #expect(callbackFailure.errorType.contains("CustomKeyboardInteractiveCallbackError"))
        #expect(failure.diagnostics.remoteIdentification == "SSH-2.0-OpenSSH_9.9 test")
    }
}

@Test
func sshClientMatchesKnownHostsFileWithAdditionalLookupName() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ]
    )
    let temporaryDirectoryURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let knownHostsURL = temporaryDirectoryURL.appendingPathComponent("known_hosts")
    let trustedHostKey = try SSHTrustedHostKey(
        rawRepresentation: ConnectionFixtureMockSSHByteStreamTransport.fixtureHostKey()
    )

    try FileManager.default.createDirectory(
        at: temporaryDirectoryURL,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectoryURL)
    }

    try makeKnownHostsLine(
        hosts: "192.0.2.10",
        algorithm: trustedHostKey.algorithmName,
        trustedHostKey: trustedHostKey
    ).write(to: knownHostsURL, atomically: true, encoding: .utf8)

    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .knownHostsFile(
            knownHostsURL.path,
            additionalLookupNames: ["192.0.2.10"]
        )
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        connection.metadata
    }

    #expect(metadata.hostKeyAlgorithm == "ssh-ed25519")
    #expect(metadata.hostKeyTrustMethod == .exactMatch)
}

@Test
func sshClientMatchesKnownHostsFileWithCIDRAdditionalLookupName() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ]
    )
    let temporaryDirectoryURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let knownHostsURL = temporaryDirectoryURL.appendingPathComponent("known_hosts")
    let trustedHostKey = try SSHTrustedHostKey(
        rawRepresentation: ConnectionFixtureMockSSHByteStreamTransport.fixtureHostKey()
    )

    try FileManager.default.createDirectory(
        at: temporaryDirectoryURL,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectoryURL)
    }

    try makeKnownHostsLine(
        hosts: "192.0.2.0/24",
        algorithm: trustedHostKey.algorithmName,
        trustedHostKey: trustedHostKey
    ).write(to: knownHostsURL, atomically: true, encoding: .utf8)

    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .knownHostsFile(
            knownHostsURL.path,
            additionalLookupNames: ["192.0.2.10"]
        )
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        connection.metadata
    }

    #expect(metadata.hostKeyAlgorithm == "ssh-ed25519")
    #expect(metadata.hostKeyTrustMethod == .exactMatch)
}

@Test
func sshClientTrustOnFirstUseStoresVerifiedHostKeyAndReusesIt() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let store = TrustOnFirstUseStore()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .trustOnFirstUse(
            lookup: { host, port in
                await store.lookup(host: host, port: port)
            },
            store: { request in
                try await store.store(request)
            }
        )
    )

    let firstMetadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(
                ConnectionFixtureMockSSHByteStreamTransport(
                    serverPayloadsAfterNewKeys: [
                        serviceAcceptPayload,
                        authSuccessPayload,
                    ]
                )
            )
        }
    ) { connection in
        connection.metadata
    }

    let storedHostKey = try #require(await store.lookup(host: "example.com", port: 22))
    let recordedStoreRequest = try #require(await store.recordedStoreRequest())
    #expect(storedHostKey.algorithmName == "ssh-ed25519")
    #expect(recordedStoreRequest.expectedStoredHostKey == nil)
    #expect(recordedStoreRequest.trustedHostKey == storedHostKey)
    #expect(firstMetadata.hostKeyTrustMethod == .callback)
    #expect(await store.saveCountObserved() == 1)

    let secondMetadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(
                ConnectionFixtureMockSSHByteStreamTransport(
                    serverPayloadsAfterNewKeys: [
                        serviceAcceptPayload,
                        authSuccessPayload,
                    ]
                )
            )
        }
    ) { connection in
        connection.metadata
    }

    #expect(secondMetadata.hostKeyTrustMethod == .callback)
    #expect(await store.saveCountObserved() == 1)
}

@Test
func sshClientTrustOnFirstUseRejectsChangedStoredHostKey() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let store = TrustOnFirstUseStore()
    let mismatchedTrustedHostKey = try SSHTrustedHostKey(
        rawRepresentation: {
            var writer = SSHWireWriter()
            writer.write(utf8: "ssh-ed25519")
            writer.write(string: Array(0x41...0x60))
            return writer.bytes
        }()
    )
    await store.store(
        host: "example.com",
        port: 22,
        trustedHostKey: mismatchedTrustedHostKey
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .trustOnFirstUse(
            lookup: { host, port in
                await store.lookup(host: host, port: port)
            },
            store: { request in
                try await store.store(request)
            }
        )
    )
    let receivedHostKey = try SSHTrustedHostKey(
        rawRepresentation: ConnectionFixtureMockSSHByteStreamTransport.fixtureHostKey()
    )

    do {
        let _: SSHConnectionMetadata = try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(
                    ConnectionFixtureMockSSHByteStreamTransport(
                        serverPayloadsAfterNewKeys: [
                            serviceAcceptPayload,
                            authSuccessPayload,
                        ]
                    )
                )
            }
        ) { connection in
            connection.metadata
        }
        Issue.record("Expected trust-on-first-use mismatch to reject changed host key")
    } catch {
        #expect(
            error as? SSHHostKeyPolicyError
                == .storedHostKeyMismatch(
                    endpointHost: "example.com",
                    endpointPort: 22,
                    storedHostKey: mismatchedTrustedHostKey,
                    receivedHostKey: receivedHostKey
                )
        )
    }
}

@Test
func sshClientTrustOnFirstUseCanReplaceChangedStoredHostKeyWhenApproved() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let store = TrustOnFirstUseStore()
    let requestRecorder = HostKeyChangeRequestRecorder()
    let mismatchedTrustedHostKey = try SSHTrustedHostKey(
        rawRepresentation: {
            var writer = SSHWireWriter()
            writer.write(utf8: "ssh-ed25519")
            writer.write(string: Array(0x41...0x60))
            return writer.bytes
        }()
    )
    await store.store(
        host: "example.com",
        port: 22,
        trustedHostKey: mismatchedTrustedHostKey
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .trustOnFirstUse(
            lookup: { host, port in
                await store.lookup(host: host, port: port)
            },
            store: { request in
                try await store.store(request)
            },
            onStoredHostKeyMismatch: { request in
                await requestRecorder.record(request)
                return .replaceStoredHostKey
            }
        )
    )
    let receivedHostKey = try SSHTrustedHostKey(
        rawRepresentation: ConnectionFixtureMockSSHByteStreamTransport.fixtureHostKey()
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(
                ConnectionFixtureMockSSHByteStreamTransport(
                    serverPayloadsAfterNewKeys: [
                        serviceAcceptPayload,
                        authSuccessPayload,
                    ]
                )
            )
        }
    ) { connection in
        connection.metadata
    }

    let recordedRequest = try #require(await requestRecorder.recordedRequest())
    let recordedStoreRequest = try #require(await store.recordedStoreRequest())
    #expect(recordedRequest.endpointHost == "example.com")
    #expect(recordedRequest.endpointPort == 22)
    #expect(recordedRequest.remoteIdentification == "SSH-2.0-OpenSSH_9.9 test")
    #expect(recordedRequest.storedHostKey == mismatchedTrustedHostKey)
    #expect(recordedRequest.receivedHostKey == receivedHostKey)
    #expect(recordedStoreRequest.expectedStoredHostKey == mismatchedTrustedHostKey)
    #expect(recordedStoreRequest.trustedHostKey == receivedHostKey)
    #expect(metadata.hostKeyTrustMethod == .callback)
    #expect(await store.lookup(host: "example.com", port: 22) == receivedHostKey)
    #expect(await store.saveCountObserved() == 2)
}

@Test
func sshClientTrustOnFirstUseCanRejectChangedStoredHostKeyExplicitly() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let store = TrustOnFirstUseStore()
    let requestRecorder = HostKeyChangeRequestRecorder()
    let mismatchedTrustedHostKey = try SSHTrustedHostKey(
        rawRepresentation: {
            var writer = SSHWireWriter()
            writer.write(utf8: "ssh-ed25519")
            writer.write(string: Array(0x41...0x60))
            return writer.bytes
        }()
    )
    await store.store(
        host: "example.com",
        port: 22,
        trustedHostKey: mismatchedTrustedHostKey
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .trustOnFirstUse(
            lookup: { host, port in
                await store.lookup(host: host, port: port)
            },
            store: { request in
                try await store.store(request)
            },
            onStoredHostKeyMismatch: { request in
                await requestRecorder.record(request)
                return .reject
            }
        )
    )
    let receivedHostKey = try SSHTrustedHostKey(
        rawRepresentation: ConnectionFixtureMockSSHByteStreamTransport.fixtureHostKey()
    )

    do {
        let _: SSHConnectionMetadata = try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(
                    ConnectionFixtureMockSSHByteStreamTransport(
                        serverPayloadsAfterNewKeys: [
                            serviceAcceptPayload,
                            authSuccessPayload,
                        ]
                    )
                )
            }
        ) { connection in
            connection.metadata
        }
        Issue.record("Expected explicit changed host-key rejection to fail the connection")
    } catch {
        #expect(
            error as? SSHHostKeyPolicyError
                == .storedHostKeyMismatch(
                    endpointHost: "example.com",
                    endpointPort: 22,
                    storedHostKey: mismatchedTrustedHostKey,
                    receivedHostKey: receivedHostKey
                )
        )
    }

    let recordedRequest = try #require(await requestRecorder.recordedRequest())
    #expect(recordedRequest.storedHostKey == mismatchedTrustedHostKey)
    #expect(recordedRequest.receivedHostKey == receivedHostKey)
    #expect(await store.lookup(host: "example.com", port: 22) == mismatchedTrustedHostKey)
    #expect(await store.saveCountObserved() == 1)
}

@Test
func sshClientWrapsTrustOnFirstUseChangedKeyCallbackFailureIntoPublicConnectionFailure() async throws {
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: []
    )
    let store = TrustOnFirstUseStore()
    let mismatchedTrustedHostKey = try SSHTrustedHostKey(
        rawRepresentation: {
            var writer = SSHWireWriter()
            writer.write(utf8: "ssh-ed25519")
            writer.write(string: Array(0x41...0x60))
            return writer.bytes
        }()
    )
    await store.store(
        host: "example.com",
        port: 22,
        trustedHostKey: mismatchedTrustedHostKey
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .trustOnFirstUse(
            lookup: { host, port in
                await store.lookup(host: host, port: port)
            },
            store: { request in
                try await store.store(request)
            },
            onStoredHostKeyMismatch: { _ in
                throw CustomHostKeyPolicyError.rejected
            }
        )
    )

    do {
        let _: SSHConnectionMetadata = try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            connection.metadata
        }
        Issue.record("Expected custom changed host-key callback failure to become a public connection failure")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.stage == .hostKeyTrust)
        #expect(failure.code == .callbackFailed)
        #expect(failure.message.contains("custom host-key policy callback failed"))
        #expect(failure.message.contains("CustomHostKeyPolicyError"))
        let callbackFailure = try #require(failure.diagnostics.callbackFailure)
        #expect(callbackFailure.source == .hostKeyPolicy)
        #expect(callbackFailure.errorType.contains("CustomHostKeyPolicyError"))
        #expect(callbackFailure.diagnosticCode == "host-key-rejected")
        #expect(
            callbackFailure.diagnosticSummary
                == "The host-key trust decision was rejected by application policy."
        )
        #expect(failure.diagnosticReport.contains("callback-failure-diagnostic-code: host-key-rejected"))
        #expect(
            failure.diagnosticReport.contains(
                "callback-failure-diagnostic-summary: The host-key trust decision was rejected by application policy."
            )
        )
        #expect(failure.diagnostics.remoteIdentification == "SSH-2.0-OpenSSH_9.9 test")
        #expect(await store.lookup(host: "example.com", port: 22) == mismatchedTrustedHostKey)
        #expect(await store.saveCountObserved() == 1)
    }
}

@Test
func sshClientTrustOnFirstUseRejectsConcurrentStoredHostKeyUpdateDuringReplacement() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let store = RacingTrustOnFirstUseStore()
    let mismatchedTrustedHostKey = try SSHTrustedHostKey(
        rawRepresentation: {
            var writer = SSHWireWriter()
            writer.write(utf8: "ssh-ed25519")
            writer.write(string: Array(0x41...0x60))
            return writer.bytes
        }()
    )
    let concurrentlyStoredHostKey = try SSHTrustedHostKey(
        rawRepresentation: {
            var writer = SSHWireWriter()
            writer.write(utf8: "ssh-ed25519")
            writer.write(string: Array(0x61...0x80))
            return writer.bytes
        }()
    )
    await store.seed(
        host: "example.com",
        port: 22,
        trustedHostKey: mismatchedTrustedHostKey
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .trustOnFirstUse(using: store)
    )
    let receivedHostKey = try SSHTrustedHostKey(
        rawRepresentation: ConnectionFixtureMockSSHByteStreamTransport.fixtureHostKey()
    )

    let metadataTask = Task {
        try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(
                    ConnectionFixtureMockSSHByteStreamTransport(
                        serverPayloadsAfterNewKeys: [
                            serviceAcceptPayload,
                            authSuccessPayload,
                        ]
                    )
                )
            }
        ) { connection in
            connection.metadata
        }
    }

    let pendingStoreRequest = await store.waitForSuspendedReplacementStoreRequest()
    #expect(pendingStoreRequest.expectedStoredHostKey == mismatchedTrustedHostKey)
    #expect(pendingStoreRequest.trustedHostKey == receivedHostKey)

    await store.forceConcurrentStoreUpdate(
        host: "example.com",
        port: 22,
        trustedHostKey: concurrentlyStoredHostKey
    )
    await store.resumeSuspendedReplacementStore()

    do {
        let _: SSHConnectionMetadata = try await metadataTask.value
        Issue.record("Expected concurrent store update to reject changed host-key replacement")
    } catch {
        #expect(
            error as? SSHHostKeyPolicyError
                == .concurrentStoredHostKeyUpdate(
                    endpointHost: "example.com",
                    endpointPort: 22,
                    expectedStoredHostKey: mismatchedTrustedHostKey,
                    actualStoredHostKey: concurrentlyStoredHostKey
                )
        )
    }

    #expect(await store.storedHostKey(host: "example.com", port: 22) == concurrentlyStoredHostKey)
}

@Test
func sshClientTrustOnFirstUseUsingStoreProtocolStoresVerifiedHostKeyAndReusesIt() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let store = TrustOnFirstUseStore()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .trustOnFirstUse(using: store)
    )

    let firstMetadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(
                ConnectionFixtureMockSSHByteStreamTransport(
                    serverPayloadsAfterNewKeys: [
                        serviceAcceptPayload,
                        authSuccessPayload,
                    ]
                )
            )
        }
    ) { connection in
        connection.metadata
    }

    let storedHostKey = try #require(await store.lookup(host: "example.com", port: 22))
    let recordedStoreRequest = try #require(await store.recordedStoreRequest())
    #expect(storedHostKey.algorithmName == "ssh-ed25519")
    #expect(recordedStoreRequest.expectedStoredHostKey == nil)
    #expect(recordedStoreRequest.trustedHostKey == storedHostKey)
    #expect(firstMetadata.hostKeyTrustMethod == .callback)
    #expect(await store.saveCountObserved() == 1)

    let secondMetadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(
                ConnectionFixtureMockSSHByteStreamTransport(
                    serverPayloadsAfterNewKeys: [
                        serviceAcceptPayload,
                        authSuccessPayload,
                    ]
                )
            )
        }
    ) { connection in
        connection.metadata
    }

    #expect(secondMetadata.hostKeyTrustMethod == .callback)
    #expect(await store.saveCountObserved() == 1)
}

@Test
func sshClientTrustOnFirstUseUsingStoreProtocolRejectsChangedStoredHostKeyByDefault() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let store = TrustOnFirstUseStore()
    let mismatchedTrustedHostKey = try SSHTrustedHostKey(
        rawRepresentation: {
            var writer = SSHWireWriter()
            writer.write(utf8: "ssh-ed25519")
            writer.write(string: Array(0x41...0x60))
            return writer.bytes
        }()
    )
    await store.store(
        host: "example.com",
        port: 22,
        trustedHostKey: mismatchedTrustedHostKey
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .trustOnFirstUse(using: store)
    )
    let receivedHostKey = try SSHTrustedHostKey(
        rawRepresentation: ConnectionFixtureMockSSHByteStreamTransport.fixtureHostKey()
    )

    do {
        let _: SSHConnectionMetadata = try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(
                    ConnectionFixtureMockSSHByteStreamTransport(
                        serverPayloadsAfterNewKeys: [
                            serviceAcceptPayload,
                            authSuccessPayload,
                        ]
                    )
                )
            }
        ) { connection in
            connection.metadata
        }
        Issue.record("Expected protocol-backed trust-on-first-use mismatch to reject changed host key")
    } catch {
        #expect(
            error as? SSHHostKeyPolicyError
                == .storedHostKeyMismatch(
                    endpointHost: "example.com",
                    endpointPort: 22,
                    storedHostKey: mismatchedTrustedHostKey,
                    receivedHostKey: receivedHostKey
                )
        )
    }
}

@Test
func sshClientTrustOnFirstUseUsingStoreProtocolCanReplaceChangedStoredHostKey() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let store = ReplacingTrustOnFirstUseStore()
    let mismatchedTrustedHostKey = try SSHTrustedHostKey(
        rawRepresentation: {
            var writer = SSHWireWriter()
            writer.write(utf8: "ssh-ed25519")
            writer.write(string: Array(0x41...0x60))
            return writer.bytes
        }()
    )
    await store.seed(
        host: "example.com",
        port: 22,
        trustedHostKey: mismatchedTrustedHostKey
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .trustOnFirstUse(using: store)
    )
    let receivedHostKey = try SSHTrustedHostKey(
        rawRepresentation: ConnectionFixtureMockSSHByteStreamTransport.fixtureHostKey()
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(
                ConnectionFixtureMockSSHByteStreamTransport(
                    serverPayloadsAfterNewKeys: [
                        serviceAcceptPayload,
                        authSuccessPayload,
                    ]
                )
            )
        }
    ) { connection in
        connection.metadata
    }

    let recordedRequest = try #require(await store.recordedRequest())
    let recordedStoreRequest = try #require(await store.recordedStoreRequest())
    #expect(recordedRequest.endpointHost == "example.com")
    #expect(recordedRequest.endpointPort == 22)
    #expect(recordedRequest.remoteIdentification == "SSH-2.0-OpenSSH_9.9 test")
    #expect(recordedRequest.storedHostKey == mismatchedTrustedHostKey)
    #expect(recordedRequest.receivedHostKey == receivedHostKey)
    #expect(recordedStoreRequest.expectedStoredHostKey == mismatchedTrustedHostKey)
    #expect(recordedStoreRequest.trustedHostKey == receivedHostKey)
    #expect(metadata.hostKeyTrustMethod == .callback)
    #expect(await store.storedHostKey(host: "example.com", port: 22) == receivedHostKey)
    #expect(await store.saveCountObserved() == 2)
}

@Test
func sshClientEvaluatesCustomHostKeyPolicyCallback() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ]
    )
    let requestRecorder = HostKeyValidationRequestRecorder()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .callback { request in
            await requestRecorder.record(request)
            return .callback
        }
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        connection.metadata
    }

    let recordedRequest = try #require(await requestRecorder.recordedRequest())
    #expect(recordedRequest.endpointHost == "example.com")
    #expect(recordedRequest.endpointPort == 22)
    #expect(recordedRequest.remoteIdentification == "SSH-2.0-OpenSSH_9.9 test")
    #expect(recordedRequest.trustedHostKey.algorithmName == "ssh-ed25519")
    #expect(!recordedRequest.trustedHostKey.fingerprintSHA256.isEmpty)
    #expect(metadata.hostKeyTrustMethod == .callback)
}

@Test
func sshClientWrapsCustomHostKeyPolicyCallbackFailureIntoPublicConnectionFailure() async throws {
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: []
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .callback { _ in
            throw CustomHostKeyPolicyError.rejected
        }
    )

    do {
        let _: SSHConnectionMetadata = try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            connection.metadata
        }
        Issue.record("Expected custom host-key policy callback failure to become a public connection failure")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.stage == .hostKeyTrust)
        #expect(failure.code == .callbackFailed)
        #expect(failure.message.contains("custom host-key policy callback failed"))
        #expect(failure.message.contains("CustomHostKeyPolicyError"))
        let callbackFailure = try #require(failure.diagnostics.callbackFailure)
        #expect(callbackFailure.source == .hostKeyPolicy)
        #expect(callbackFailure.errorType.contains("CustomHostKeyPolicyError"))
        #expect(callbackFailure.diagnosticCode == "host-key-rejected")
        #expect(
            callbackFailure.diagnosticSummary
                == "The host-key trust decision was rejected by application policy."
        )
        #expect(failure.diagnosticReport.contains("callback-failure-diagnostic-code: host-key-rejected"))
        #expect(
            failure.diagnosticReport.contains(
                "callback-failure-diagnostic-summary: The host-key trust decision was rejected by application policy."
            )
        )
        #expect(failure.diagnostics.remoteIdentification == "SSH-2.0-OpenSSH_9.9 test")
    }
}

@Test
func sshClientMapsAuthenticationFailureIntoPublicError() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let bannerPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .banner(
            SSHUserAuthenticationBannerMessage(
                message: "Authorized use only",
                languageTag: "en-US"
            )
        )
    )
    let failurePayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .failure(
            SSHUserAuthenticationFailureMessage(
                authenticationsThatCanContinue: ["publickey"],
                partialSuccess: false
            )
        )
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            bannerPayload,
            failurePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("bad-password"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )
    let recorder = SSHClientLogRecorder()

    do {
        let _: String = try await SSHClient.withConnection(
            configuration: configuration,
            logHandler: recorder.logHandler(),
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { _ in
            "unexpected"
        }
        Issue.record("Expected authentication rejection error")
    } catch {
        #expect(
            error as? SSHClientError
                == .authenticationRejected(
                    methodName: "password",
                    availableMethods: ["publickey"],
                    partialSuccess: false,
                    banners: [
                        SSHAuthenticationBanner(
                            message: "Authorized use only",
                            languageTag: "en-US"
                        )
                    ]
                )
        )
    }
    #expect(await transport.closeCountObserved() == 1)
    let authRejectionLog = try #require(
        recorder.snapshot().events.first { event in
            event.category == .authentication
                && event.message == "SSH authentication was rejected by the server."
        }
    )
    #expect(authRejectionLog.metadata["bannerCount"] == "1")
}

@Test
func sshClientAttemptsConfiguredAuthenticationMethodsOnOneConnection() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let passwordBannerPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .banner(
            SSHUserAuthenticationBannerMessage(
                message: "Password rejected",
                languageTag: "en-US"
            )
        )
    )
    let passwordFailurePayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .failure(
            SSHUserAuthenticationFailureMessage(
                authenticationsThatCanContinue: ["keyboard-interactive"],
                partialSuccess: false
            )
        )
    )
    let infoRequestPayload = SSHUserAuthenticationMessageSerializer()
        .serializeKeyboardInteractiveInfoRequest(
            SSHKeyboardInteractiveInformationRequestMessage(
                name: "Password Authentication",
                instruction: "Enter your password",
                languageTag: "en-US",
                prompts: [
                    SSHKeyboardInteractivePromptMessage(
                        prompt: "Password: ",
                        shouldEcho: false
                    )
                ]
            )
        )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            passwordBannerPayload,
            passwordFailurePayload,
            infoRequestPayload,
            successPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authenticationMethods: [
            .password("bad-password"),
            .keyboardInteractive(
                submethods: [],
                responseProvider: { challenge in
                    #expect(challenge.username == "root")
                    #expect(challenge.prompts.count == 1)
                    return ["s3cr3t"]
                }
            ),
        ],
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        connection.metadata
    }

    #expect(
        metadata.authenticationBanners == [
            SSHAuthenticationBanner(
                message: "Password rejected",
                languageTag: "en-US"
            )
        ]
    )

    let sentPayloads = await transport.sentPayloads()
    let decryptionContext = try makeConnectionFixtureClientToServerDecryptionContext(
        sentPayloads: sentPayloads
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: decryptionContext.algorithms,
        keyMaterial: decryptionContext.keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(4).joined()))

    let serviceRequestPacket = try #require(try parser.nextPacket())
    let passwordRequestPacket = try #require(try parser.nextPacket())
    let keyboardInteractiveRequestPacket = try #require(try parser.nextPacket())
    let infoResponsePacket = try #require(try parser.nextPacket())

    #expect(
        try SSHTransportMessageParser().parse(serviceRequestPacket.payload)
            == .serviceRequest(
                SSHServiceRequestMessage(serviceName: "ssh-userauth")
            )
    )
    #expect(
        try SSHUserAuthenticationMessageParser().parse(passwordRequestPacket.payload)
            == .request(
                SSHUserAuthenticationRequestMessage(
                    username: "root",
                    serviceName: "ssh-connection",
                    method: .password(
                        SSHPasswordAuthenticationRequest(password: "bad-password")
                    )
                )
            )
    )

    let parsedKeyboardInteractiveRequest = try SSHUserAuthenticationMessageParser().parse(
        keyboardInteractiveRequestPacket.payload
    )
    let requestMessage = try #require({
        if case let .request(message) = parsedKeyboardInteractiveRequest {
            return message
        }
        return nil
    }())
    let keyboardInteractiveRequest = try #require({
        if case let .keyboardInteractive(request) = requestMessage.method {
            return request
        }
        return nil
    }())
    let infoResponse = try SSHUserAuthenticationMessageParser()
        .parseKeyboardInteractiveInfoResponse(infoResponsePacket.payload)

    #expect(requestMessage.username == "root")
    #expect(requestMessage.serviceName == "ssh-connection")
    #expect(keyboardInteractiveRequest.submethods == [])
    #expect(infoResponse.responses == ["s3cr3t"])
}

@Test
func sshClientAuthenticatesPasswordChangeResponseThroughPublicCallback() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let initialBannerPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .banner(
            SSHUserAuthenticationBannerMessage(
                message: "Password expired",
                languageTag: "en-US"
            )
        )
    )
    let changeRequestPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .passwordChangeRequest(
            SSHUserAuthenticationPasswordChangeRequestMessage(
                prompt: "Choose a new password",
                languageTag: "en-AU"
            )
        )
    )
    let finalBannerPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .banner(
            SSHUserAuthenticationBannerMessage(
                message: "Password updated",
                languageTag: "en-AU"
            )
        )
    )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            initialBannerPayload,
            changeRequestPayload,
            finalBannerPayload,
            successPayload,
        ]
    )
    let challengeRecorder = PasswordChangeChallengeRecorder()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .passwordWithChangeResponse(password: "expired") { challenge in
            await challengeRecorder.record(challenge)
            return "updated"
        },
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        connection.metadata
    }

    #expect(
        try #require(await challengeRecorder.recordedChallenge())
            == SSHPasswordChangeChallenge(
                username: "root",
                serviceName: "ssh-connection",
                prompt: "Choose a new password",
                languageTag: "en-AU",
                banners: [
                    SSHAuthenticationBanner(
                        message: "Password expired",
                        languageTag: "en-US"
                    )
                ]
            )
    )
    #expect(
        metadata.authenticationBanners == [
            SSHAuthenticationBanner(
                message: "Password expired",
                languageTag: "en-US"
            ),
            SSHAuthenticationBanner(
                message: "Password updated",
                languageTag: "en-AU"
            ),
        ]
    )

    let sentPayloads = await transport.sentPayloads()
    let decryptionContext = try makeConnectionFixtureClientToServerDecryptionContext(
        sentPayloads: sentPayloads
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: decryptionContext.algorithms,
        keyMaterial: decryptionContext.keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(4).joined()))

    let serviceRequestPacket = try #require(try parser.nextPacket())
    let initialPasswordPacket = try #require(try parser.nextPacket())
    let changedPasswordPacket = try #require(try parser.nextPacket())

    #expect(
        try SSHTransportMessageParser().parse(serviceRequestPacket.payload)
            == .serviceRequest(
                SSHServiceRequestMessage(serviceName: "ssh-userauth")
            )
    )
    #expect(
        try SSHUserAuthenticationMessageParser().parse(initialPasswordPacket.payload)
            == .request(
                SSHUserAuthenticationRequestMessage(
                    username: "root",
                    serviceName: "ssh-connection",
                    method: .password(SSHPasswordAuthenticationRequest(password: "expired"))
                )
            )
    )
    #expect(
        try SSHUserAuthenticationMessageParser().parse(changedPasswordPacket.payload)
            == .request(
                SSHUserAuthenticationRequestMessage(
                    username: "root",
                    serviceName: "ssh-connection",
                    method: .password(
                        SSHPasswordAuthenticationRequest(
                            oldPassword: "expired",
                            newPassword: "updated"
                        )
                    )
                )
            )
    )
}

@Test
func sshClientWrapsPasswordChangeResponseCallbackFailureIntoPublicConnectionFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let changeRequestPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .passwordChangeRequest(
            SSHUserAuthenticationPasswordChangeRequestMessage(
                prompt: "Choose a new password",
                languageTag: "en-AU"
            )
        )
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            changeRequestPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .passwordWithChangeResponse(password: "expired") { _ in
            throw CustomPasswordChangeCallbackError.rejected
        },
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            transportFactory: { _ in transport }
        )
        Issue.record("Expected password-change callback failure")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.stage == .authentication)
        #expect(failure.code == .callbackFailed)
        #expect(failure.message.contains("password-change response callback failed"))
        #expect(failure.message.contains("CustomPasswordChangeCallbackError"))
        let callbackFailure = try #require(failure.diagnostics.callbackFailure)
        #expect(callbackFailure.source == .passwordChangeResponse)
        #expect(callbackFailure.errorType.contains("CustomPasswordChangeCallbackError"))
    }
    #expect(await transport.closeCountObserved() == 1)
}

@Test
func sshClientWrapsInvalidAuthenticationMaterialIntoPublicConnectionFailure() async throws {
    let transport = try makeConnectionFixtureTransport(serverPayloadsAfterNewKeys: [])
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .ed25519PrivateKey(rawRepresentation: [0x01, 0x02, 0x03]),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            transportFactory: { _ in transport }
        )
        Issue.record("Expected invalid private-key bytes to be wrapped as a public connection failure")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.stage == .configuration)
        #expect(failure.code == .invalidAuthenticationMaterial)
        #expect(failure.message == "The Ed25519 private key must be 32 bytes, but received 3.")
        #expect(failure.diagnostics.endpointHost == "example.com")
        #expect(failure.diagnostics.username == "root")
        #expect(failure.diagnostics.remoteIdentification == "SSH-2.0-OpenSSH_9.9 test")
        #expect(failure.diagnostics.negotiatedAlgorithms?.keyExchangeAlgorithm == "curve25519-sha256")
        #expect(failure.diagnostics.remoteDisconnect == nil)
    }
}

@Test
func sshClientCapturesRemoteDisconnectAndDebugMessagesDuringAuthenticationFailure() async throws {
    let debugPayload = try SSHTransportMessageSerializer().serialize(
        .debug(
            SSHDebugMessage(
                alwaysDisplay: false,
                message: "auth service disabled",
                languageTag: "en-US"
            )
        )
    )
    let disconnectPayload = try SSHTransportMessageSerializer().serialize(
        .disconnect(
            SSHDisconnectMessage(
                reasonCode: .serviceNotAvailable,
                description: "ssh-userauth disabled",
                languageTag: "en-US"
            )
        )
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            debugPayload,
            disconnectPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            transportFactory: { _ in transport }
        )
        Issue.record("Expected remote disconnect during authentication to produce a public connection failure")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.stage == .authentication)
        #expect(failure.code == .remoteDisconnect)
        #expect(
            failure.message
                == "The server disconnected during connection setup with reason code 7: ssh-userauth disabled"
        )
        let remoteDisconnect = try #require(failure.diagnostics.remoteDisconnect)
        #expect(remoteDisconnect.reasonCode == 7)
        #expect(remoteDisconnect.description == "ssh-userauth disabled")
        #expect(remoteDisconnect.languageTag == "en-US")
        #expect(
            failure.diagnostics.remoteDebugMessages
                == [
                    SSHRemoteDebugMessage(
                        alwaysDisplay: false,
                        message: "auth service disabled",
                        languageTag: "en-US"
                    )
                ]
        )
        #expect(failure.diagnostics.serverSignatureAlgorithms == nil)
    }
}

@Test
func connectionFailureDiagnosticsExposeStrictKeyExchangeWhenNegotiated() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-ctr",
        encryptionAlgorithmServerToClient: "aes128-ctr",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-256",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let snapshot = SSHTransportProtocolDiagnosticsSnapshot(
        phase: .keyExchange,
        clientIdentification: "SSH-2.0-Traversio_Test",
        remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
        preIdentificationLines: [],
        keepaliveIntervalNanoseconds: 10_000_000_000,
        keepaliveReplyTimeoutNanoseconds: 10_000_000_000,
        responseTimeoutNanoseconds: nil,
        negotiatedAlgorithms: SSHTransportProtocolNegotiatedAlgorithmsSnapshot(
            algorithms: negotiatedAlgorithms,
            usesStrictKeyExchange: true
        ),
        didReceiveServerExtensionInfo: true,
        serverExtensionNames: ["delay-compression", "server-sig-algs"],
        serverSignatureAlgorithms: nil,
        remoteDisconnect: nil,
        remoteDebugMessages: []
    )

    let diagnostics = SSHConnectionFailureDiagnostics(
        endpoint: SSHSocketEndpoint(host: "example.com", port: 22),
        username: "root",
        snapshot: snapshot
    )
    let publicAlgorithms = try #require(diagnostics.negotiatedAlgorithms)

    #expect(publicAlgorithms.keyExchangeAlgorithm == "curve25519-sha256")
    #expect(publicAlgorithms.usesStrictKeyExchange == true)
    #expect(diagnostics.didReceiveServerExtensionInfo == true)
    #expect(diagnostics.serverExtensionNames == ["delay-compression", "server-sig-algs"])
    #expect(diagnostics.callbackFailure == nil)
}

@Test
func connectionFailureDiagnosticsExposeEffectiveIntegrityForAEADTransports() throws {
    let diagnostics = SSHConnectionFailureDiagnostics(
        endpoint: SSHSocketEndpoint(host: "example.com", port: 22),
        username: "root",
        snapshot: makeNegotiatedDiagnosticsSnapshot(
            encryptionAlgorithmClientToServer: "aes128-gcm@openssh.com",
            encryptionAlgorithmServerToClient: "chacha20-poly1305@openssh.com",
            macAlgorithmClientToServer: "hmac-sha2-256-etm@openssh.com",
            macAlgorithmServerToClient: "hmac-sha2-512-etm@openssh.com"
        )
    )
    let algorithms = try #require(diagnostics.negotiatedAlgorithms)

    #expect(algorithms.macAlgorithmClientToServer == "hmac-sha2-256-etm@openssh.com")
    #expect(algorithms.macAlgorithmServerToClient == "hmac-sha2-512-etm@openssh.com")
    #expect(algorithms.effectiveIntegrityAlgorithmClientToServer == "implicit")
    #expect(algorithms.effectiveIntegrityAlgorithmServerToClient == "implicit")
}

@Test
func operationFailureDiagnosticsExposeEffectiveIntegrityForAEADTransports() throws {
    let diagnostics = SSHOperationFailureDiagnostics(
        metadata: SSHConnectionMetadata(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: [],
            hostKeyAlgorithm: "ssh-ed25519",
            hostKeyFingerprintSHA256: "fingerprint",
            hostKeyTrustMethod: .acceptAnyVerifiedHostKey
        ),
        snapshot: makeNegotiatedDiagnosticsSnapshot(
            encryptionAlgorithmClientToServer: "aes128-gcm@openssh.com",
            encryptionAlgorithmServerToClient: "aes128-ctr",
            macAlgorithmClientToServer: "hmac-sha2-256-etm@openssh.com",
            macAlgorithmServerToClient: "hmac-sha2-256"
        ),
        localChannelID: 17,
        remoteChannelID: 42,
        requestType: "exec",
        sftpStatus: nil
    )
    let algorithms = try #require(diagnostics.negotiatedAlgorithms)

    #expect(algorithms.effectiveIntegrityAlgorithmClientToServer == "implicit")
    #expect(algorithms.effectiveIntegrityAlgorithmServerToClient == "hmac-sha2-256")
    #expect(diagnostics.localChannelID == 17)
    #expect(diagnostics.remoteChannelID == 42)
    #expect(diagnostics.requestType == "exec")
}

@Test
func sshSessionWrapsRemoteDisconnectIntoPublicOperationFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 42,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let debugPayload = try SSHTransportMessageSerializer().serialize(
        .debug(
            SSHDebugMessage(
                alwaysDisplay: false,
                message: "closing idle exec session",
                languageTag: "en-US"
            )
        )
    )
    let disconnectPayload = try SSHTransportMessageSerializer().serialize(
        .disconnect(
            SSHDisconnectMessage(
                reasonCode: .serviceNotAvailable,
                description: "exec subsystem disabled",
                languageTag: "en-US"
            )
        )
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            debugPayload,
            disconnectPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        _ = try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            let session = try await connection.openExec("uname -a")
            return try await session.nextEvent()
        }
        Issue.record("Expected post-auth remote disconnect to produce a public operation failure")
    } catch {
        let failure = try #require(operationFailure(from: error))
        #expect(failure.scope == .session)
        #expect(failure.code == .remoteDisconnect)
        #expect(failure.message == "The server disconnected during a session operation with reason code 7: exec subsystem disabled")
        #expect(failure.diagnostics.localChannelID == 0)
        #expect(failure.diagnostics.remoteChannelID == 42)
        let remoteDisconnect = try #require(failure.diagnostics.remoteDisconnect)
        #expect(remoteDisconnect.reasonCode == 7)
        #expect(remoteDisconnect.description == "exec subsystem disabled")
        #expect(
            failure.diagnostics.remoteDebugMessages
                == [
                    SSHRemoteDebugMessage(
                        alwaysDisplay: false,
                        message: "closing idle exec session",
                        languageTag: "en-US"
                    )
                ]
        )
    }
}

@Test
func sshClientWrapsDirectTCPIPChannelOpenFailureIntoPublicOperationFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openFailurePayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenFailure(
            SSHChannelOpenFailureMessage(
                recipientChannel: 0,
                reasonCode: .connectFailed,
                description: "connection refused",
                languageTag: "en-US"
            )
        )
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openFailurePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        _ = try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            try await connection.openDirectTCPIPChannel(
                targetHost: "db.internal",
                targetPort: 5432
            )
        }
        Issue.record("Expected direct-tcpip open failure to produce a public operation failure")
    } catch {
        let failure = try #require(operationFailure(from: error))
        #expect(failure.scope == .directTCPIPChannel)
        #expect(failure.code == .channelOpenFailed)
        #expect(failure.diagnostics.localChannelID == 0)
        #expect(failure.diagnostics.remoteChannelID == nil)
        #expect(failure.message.contains("connect-failed"))
        #expect(failure.message.contains("connection refused"))
    }
}

@Test
func sshClientWrapsDirectStreamLocalChannelOpenFailureIntoPublicOperationFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openFailurePayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenFailure(
            SSHChannelOpenFailureMessage(
                recipientChannel: 0,
                reasonCode: .connectFailed,
                description: "socket path missing",
                languageTag: "en-US"
            )
        )
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openFailurePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        _ = try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            try await connection.openDirectStreamLocalChannel(
                socketPath: "/run/missing.sock"
            )
        }
        Issue.record("Expected direct-streamlocal open failure to produce a public operation failure")
    } catch {
        let failure = try #require(operationFailure(from: error))
        #expect(failure.scope == .directStreamLocalChannel)
        #expect(failure.code == .channelOpenFailed)
        #expect(failure.diagnostics.localChannelID == 0)
        #expect(failure.diagnostics.remoteChannelID == nil)
        #expect(failure.message.contains("connect-failed"))
        #expect(failure.message.contains("socket path missing"))
    }
}

@Test
func sshClientWrapsSFTPStatusIntoPublicOperationFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 82,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .version(
                SSHSFTPVersionMessage(
                    version: 3,
                    extensions: []
                )
            )
        )
    )
    let versionPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: versionPacket
            )
        )
    )
    let statusPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .status(
                SSHSFTPStatusMessage(
                    requestID: 0,
                    statusCode: .noSuchFile,
                    errorMessage: "missing file",
                    languageTag: "en-US"
                )
            )
        )
    )
    let statusPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: statusPacket
            )
        )
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            versionPayload,
            statusPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        _ = try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            let sftp = try await connection.openSFTP()
            try await sftp.removeFile("/tmp/missing")
        }
        Issue.record("Expected SFTP status failure to produce a public operation failure")
    } catch {
        let failure = try #require(operationFailure(from: error))
        #expect(failure.scope == .sftp)
        #expect(failure.code == .requestFailed)
        #expect(failure.diagnostics.localChannelID == 0)
        #expect(failure.diagnostics.remoteChannelID == 82)
        let status = try #require(failure.diagnostics.sftpStatus)
        #expect(status.code == 2)
        #expect(status.statusCode == .noSuchFile)
        #expect(status.standardName == "SSH_FX_NO_SUCH_FILE")
        #expect(status.message == "missing file")
        #expect(status.languageTag == "en-US")
        #expect(failure.message == "The SFTP server returned status 2: missing file")
    }
}

@Test
func sshClientWrapsSFTPResponseTimeoutIntoPublicOperationFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 82,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .version(
                SSHSFTPVersionMessage(
                    version: 3,
                    extensions: []
                )
            )
        )
    )
    let versionPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: versionPacket
            )
        )
    )
    let baseTransport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            versionPayload,
        ]
    )
    let transport = EmptyReceiveDelayTransport(
        base: baseTransport,
        emptyReceiveDelayNanoseconds: 200_000_000
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        timeoutPolicy: SSHTimeoutPolicy(responseTimeInterval: 0.05)
    )

    do {
        _ = try await SSHClient.withConnection(
            configuration: configuration,
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            let sftp = try await connection.openSFTP()
            _ = try await sftp.stat("/tmp/test")
        }
        Issue.record("Expected SFTP response timeout to produce a public operation failure")
    } catch {
        let failure = try #require(operationFailure(from: error))
        #expect(failure.scope == .sftp)
        #expect(failure.code == .timeout)
        #expect(failure.diagnostics.localChannelID == 0)
        #expect(failure.diagnostics.remoteChannelID == 82)
        #expect(failure.message.contains("SFTP response"))
    }
}

@Test
func sshClientWrapsHostKeyTrustMismatchIntoPublicConnectionFailure() async throws {
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: []
    )
    let mismatchedTrustedHostKey = try SSHTrustedHostKey(
        rawRepresentation: {
            var writer = SSHWireWriter()
            writer.write(utf8: "ssh-ed25519")
            writer.write(string: Array(0x41...0x60))
            return writer.bytes
        }()
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .requireMatch(mismatchedTrustedHostKey)
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            transportFactory: { _ in transport }
        )
        Issue.record("Expected mismatched host key to produce a public connection failure")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.stage == .hostKeyTrust)
        #expect(failure.code == .hostKeyTrustFailed)
        #expect(failure.message.contains("Expected trusted host key ssh-ed25519"))
        #expect(failure.message.contains("but received ssh-ed25519"))
        #expect(failure.diagnostics.remoteIdentification == "SSH-2.0-OpenSSH_9.9 test")
        #expect(failure.diagnostics.negotiatedAlgorithms?.serverHostKeyAlgorithm == "ssh-ed25519")
    }
}

@Test
func sshClientWrapsInvalidHostCertificateTrustFailureIntoPublicConnectionFailure() throws {
    let endpoint = SSHSocketEndpoint(host: "db.example.com", port: 22)
    let failure = try #require(
        SSHClient.wrapConnectionFailure(
            SSHHostKeyTrustError.invalidHostCertificate(
                receivedAlgorithmName: "ssh-ed25519-cert-v01@openssh.com",
                reason: .principalMismatch(
                    expectedHost: "db.example.com",
                    principals: ["host1", "host2"]
                ),
                context: SSHHostKeyValidationContext(
                    remoteEndpoint: endpoint,
                    remoteIdentification: try SSHIdentification(
                        rawValue: "SSH-2.0-OpenSSH_9.9"
                    ),
                    verificationDate: Date(timeIntervalSince1970: 1_100_000_000)
                )
            ),
            endpoint: endpoint,
            username: "root",
            snapshot: makeNegotiatedDiagnosticsSnapshot(
                encryptionAlgorithmClientToServer: "aes128-ctr",
                encryptionAlgorithmServerToClient: "aes128-ctr",
                macAlgorithmClientToServer: "hmac-sha2-256",
                macAlgorithmServerToClient: "hmac-sha2-256"
            )
        )
    )

    #expect(failure.stage == .hostKeyTrust)
    #expect(failure.code == .hostKeyTrustFailed)
    #expect(
        failure.message
            == "The server host certificate ssh-ed25519-cert-v01@openssh.com does not permit host db.example.com. Presented principals: host1, host2."
    )
    #expect(failure.diagnostics.endpointHost == "db.example.com")
    #expect(
        failure.diagnostics.negotiatedAlgorithms?.serverHostKeyAlgorithm
            == "ssh-ed25519"
    )
}

@Test
func sshClientWrapsUntrustedHostCertificateAuthorityIntoPublicConnectionFailure() throws {
    let endpoint = SSHSocketEndpoint(host: "db.example.com", port: 22)
    let certificateAuthority = try SSHTrustedHostKey(
        rawRepresentation: {
            var writer = SSHWireWriter()
            writer.write(utf8: "ssh-ed25519")
            writer.write(string: Array(0x41...0x60))
            return writer.bytes
        }()
    )
    let failure = try #require(
        SSHClient.wrapConnectionFailure(
            SSHHostKeyTrustError.hostCertificateAuthorityNotTrusted(
                receivedAlgorithmName: "ssh-ed25519-cert-v01@openssh.com",
                certificateAuthorityAlgorithmName: certificateAuthority.algorithmName,
                certificateAuthorityFingerprintSHA256: certificateAuthority.fingerprintSHA256,
                trustedCertificateAuthorities: [],
                context: SSHHostKeyValidationContext(
                    remoteEndpoint: endpoint,
                    remoteIdentification: try SSHIdentification(
                        rawValue: "SSH-2.0-OpenSSH_9.9"
                    ),
                    verificationDate: Date(timeIntervalSince1970: 1_100_000_000)
                )
            ),
            endpoint: endpoint,
            username: "root",
            snapshot: makeNegotiatedDiagnosticsSnapshot(
                encryptionAlgorithmClientToServer: "aes128-ctr",
                encryptionAlgorithmServerToClient: "aes128-ctr",
                macAlgorithmClientToServer: "hmac-sha2-256",
                macAlgorithmServerToClient: "hmac-sha2-256"
            )
        )
    )

    #expect(failure.stage == .hostKeyTrust)
    #expect(failure.code == .hostKeyTrustFailed)
    #expect(
        failure.message
            == "The server host certificate ssh-ed25519-cert-v01@openssh.com was signed by untrusted certificate authority ssh-ed25519 \(certificateAuthority.fingerprintSHA256). Trusted certificate-authority candidate count: 0."
    )
}

@Test
func sshClientWrapsKnownHostsMissIntoPublicConnectionFailure() async throws {
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: []
    )
    let temporaryDirectoryURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let knownHostsURL = temporaryDirectoryURL.appendingPathComponent("known_hosts")
    let trustedHostKey = try SSHTrustedHostKey(
        rawRepresentation: ConnectionFixtureMockSSHByteStreamTransport.fixtureHostKey()
    )

    try FileManager.default.createDirectory(
        at: temporaryDirectoryURL,
        withIntermediateDirectories: true
    )
    defer {
        try? FileManager.default.removeItem(at: temporaryDirectoryURL)
    }

    try makeKnownHostsLine(
        hosts: "other.example.com",
        algorithm: trustedHostKey.algorithmName,
        trustedHostKey: trustedHostKey
    ).write(to: knownHostsURL, atomically: true, encoding: .utf8)

    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .knownHostsFile(knownHostsURL.path)
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            transportFactory: { _ in transport }
        )
        Issue.record("Expected unmatched known_hosts policy to produce a public connection failure")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.stage == .configuration)
        #expect(failure.code == .noMatchingKnownHost)
        #expect(failure.message == "No known_hosts entry matched example.com:22.")
        #expect(failure.diagnostics.remoteIdentification == nil)
        #expect(failure.diagnostics.negotiatedAlgorithms == nil)
    }
}

@Test
func sshClientWrapsPOSIXTransportFactoryFailureAndLogsStableConnectionMetadata() async throws {
    let recorder = SSHClientLogEventRecorder()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            logHandler: .sink(minimumLevel: .debug) { event in
                recorder.record(event)
            },
            transportFactory: { _ in
                throw POSIXError(.ECONNREFUSED)
            }
        )
        Issue.record("Expected POSIX transport failure to produce a public connection failure")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.stage == .transport)
        #expect(failure.code == .transportError)
    }

    let events = recorder.snapshot()
    #expect(events.count == 2)
    #expect(events[0].category == .connection)
    #expect(events[0].message == "Starting SSH connection setup.")
    #expect(events[0].metadata["authenticationMethod"] == "password")
    #expect(events[1].category == .connection)
    #expect(events[1].metadata["stage"] == "transport")
    #expect(events[1].metadata["code"] == "transportError")
    #expect(events[1].metadata["callbackFailureSource"] == nil)
    #expect(events[1].metadata["callbackFailureErrorType"] == nil)
}

@Test
func sshClientLogsStructuredCallbackFailureMetadata() async throws {
    let recorder = SSHClientLogEventRecorder()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .callback { _ in
            throw CustomHostKeyPolicyError.rejected
        }
    )

    do {
        _ = try await SSHClient.connect(
            configuration: configuration,
            logHandler: .sink(minimumLevel: .debug) { event in
                recorder.record(event)
            },
            transportFactory: { _ in
                ConnectionFixtureMockSSHByteStreamTransport(
                    serverPayloadsAfterNewKeys: []
                )
            }
        )
        Issue.record("Expected callback failure to produce a public connection failure")
    } catch {
        let failure = try #require(connectionFailure(from: error))
        #expect(failure.code == .callbackFailed)
        let callbackFailure = try #require(failure.diagnostics.callbackFailure)
        #expect(callbackFailure.source == .hostKeyPolicy)
    }

    let events = recorder.snapshot()
    let failureEvent = try #require(
        events.last(where: { $0.metadata["code"] == "callbackFailed" })
    )
    #expect(failureEvent.category == .connection)
    #expect(failureEvent.metadata["stage"] == "hostKeyTrust")
    #expect(failureEvent.metadata["callbackFailureSource"] == "hostKeyPolicy")
    #expect(
        failureEvent.metadata["callbackFailureErrorType"]?.contains("CustomHostKeyPolicyError")
            == true
    )
    #expect(failureEvent.metadata["callbackFailureDiagnosticCode"] == "host-key-rejected")
    #expect(
        failureEvent.metadata["callbackFailureDiagnosticSummary"]
            == "The host-key trust decision was rejected by application policy."
    )
}

@Test
func sshClientLogsProxyJumpLifecycleMetadata() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let firstHopTransport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ]
    )
    let finalTransport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
        ]
    )
    let recorder = SSHClientLogEventRecorder()
    let configuration = SSHClientConfiguration(
        host: "db.internal",
        username: "root",
        authentication: .password("target"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey,
        proxyJumpHosts: [
            SSHProxyJumpHost(
                host: "jump-1.example.com",
                username: "jump1",
                authentication: .password("jump-1"),
                hostKeyPolicy: .acceptAnyVerifiedHostKey
            )
        ]
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        logHandler: .sink(minimumLevel: .debug) { event in
            recorder.record(event)
        },
        transportHandleFactory: { endpoint in
            #expect(endpoint.host == "jump-1.example.com")
            return SSHClientTransportHandle(transport: firstHopTransport)
        },
        jumpTransportFactory: { _, endpoint in
            #expect(endpoint.host == "db.internal")
            return SSHClientTransportHandle(transport: finalTransport)
        }
    )
    await connection.close()

    let events = recorder.snapshot()
    let setupEvent = try #require(
        events.first(where: { $0.message == "Starting SSH connection setup through ProxyJump." })
    )
    #expect(setupEvent.metadata["endpointHost"] == "db.internal")
    #expect(setupEvent.metadata["proxyJumpConnectionCount"] == "2")
    #expect(setupEvent.metadata["username"] == "root")

    let hopStartEvent = try #require(
        events.first(where: { $0.message == "Starting SSH ProxyJump hop." })
    )
    #expect(hopStartEvent.metadata["endpointHost"] == "jump-1.example.com")
    #expect(hopStartEvent.metadata["proxyJumpConnectionIndex"] == "1")
    #expect(hopStartEvent.metadata["connectionRole"] == "proxy-jump-hop")
    #expect(hopStartEvent.metadata["username"] == "jump1")

    let channelOpenEvent = try #require(
        events.first(where: { $0.message == "Opening SSH ProxyJump direct-tcpip channel." })
    )
    #expect(channelOpenEvent.metadata["upstreamEndpointHost"] == "jump-1.example.com")
    #expect(channelOpenEvent.metadata["targetEndpointHost"] == "db.internal")
    #expect(channelOpenEvent.metadata["proxyJumpConnectionIndex"] == "2")

    let targetStartEvent = try #require(
        events.first(where: { $0.message == "Starting SSH ProxyJump final target connection." })
    )
    #expect(targetStartEvent.metadata["endpointHost"] == "db.internal")
    #expect(targetStartEvent.metadata["proxyJumpConnectionIndex"] == "2")
    #expect(targetStartEvent.metadata["connectionRole"] == "proxy-jump-target")
}

@Test
func sshClientWrapsRemotePortForwardingRequestFailureAndLogsStableOperationMetadata() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let requestFailurePayload = try SSHConnectionMessageSerializer().serialize(
        .requestFailure(SSHGlobalRequestFailureMessage())
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            requestFailurePayload,
        ]
    )
    let recorder = SSHClientLogEventRecorder()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        _ = try await SSHClient.withConnection(
            configuration: configuration,
            logHandler: .sink(minimumLevel: .debug) { event in
                recorder.record(event)
            },
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            try await connection.withRemotePortForwarding(
                localPort: 8080,
                remoteHost: "127.0.0.1",
                remotePort: 0
            ) { forward in
                forward
            }
        }
        Issue.record("Expected remote port forwarding request failure to produce a public operation failure")
    } catch {
        let failure = try #require(operationFailure(from: error))
        #expect(failure.scope == .remotePortForward)
        #expect(failure.code == .requestFailed)
        #expect(failure.diagnostics.requestType == "tcpip-forward")
    }

    let events = recorder.snapshot()
    let failureEvent = try #require(
        events.last(where: { $0.metadata["scope"] == "remotePortForward" })
    )
    #expect(failureEvent.category == .forwarding)
    #expect(failureEvent.metadata["scope"] == "remotePortForward")
    #expect(failureEvent.metadata["code"] == "requestFailed")
    #expect(failureEvent.metadata["requestType"] == "tcpip-forward")
}

@Test
func sshClientLogsStableOperationMetadataForSessionTranscriptFailure() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 42,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let debugPayload = try SSHTransportMessageSerializer().serialize(
        .debug(
            SSHDebugMessage(
                alwaysDisplay: false,
                message: "closing transcript collection",
                languageTag: "en-US"
            )
        )
    )
    let disconnectPayload = try SSHTransportMessageSerializer().serialize(
        .disconnect(
            SSHDisconnectMessage(
                reasonCode: .serviceNotAvailable,
                description: "exec transcript disabled",
                languageTag: "en-US"
            )
        )
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            debugPayload,
            disconnectPayload,
        ]
    )
    let recorder = SSHClientLogEventRecorder()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        _ = try await SSHClient.withConnection(
            configuration: configuration,
            logHandler: .sink(minimumLevel: .debug) { event in
                recorder.record(event)
            },
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            let session = try await connection.openExec("uname -a")
            return try await session.collectOutputUntilClose()
        }
        Issue.record("Expected transcript collection failure to produce a public operation failure")
    } catch {
        let failure = try #require(operationFailure(from: error))
        #expect(failure.scope == .session)
        #expect(failure.code == .remoteDisconnect)
        #expect(failure.diagnostics.localChannelID == 0)
        #expect(failure.diagnostics.remoteChannelID == 42)
    }

    let events = recorder.snapshot()
    let failureEvent = try #require(
        events.last(where: { $0.metadata["scope"] == "session" })
    )
    #expect(failureEvent.category == .session)
    #expect(failureEvent.metadata["scope"] == "session")
    #expect(failureEvent.metadata["code"] == "remoteDisconnect")
    #expect(failureEvent.metadata["localChannelID"] == "0")
    #expect(failureEvent.metadata["remoteChannelID"] == "42")
    #expect(failureEvent.metadata["remoteDisconnectReasonCode"] == "7")
    #expect(failureEvent.metadata["requestType"] == nil)
}

@Test
func sshClientPreservesSignalRequestTypeForTransportFailureDiagnostics() async throws {
    let transport = try makeOpenShellFixtureTransport()
    let recorder = SSHClientLogEventRecorder()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        _ = try await SSHClient.withConnection(
            configuration: configuration,
            logHandler: .sink(minimumLevel: .debug) { event in
                recorder.record(event)
            },
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            let session = try await connection.openShell()
            await transport.enqueueSendFailure(.EPIPE)
            try await session.sendSignal(.terminate)
        }
        Issue.record("Expected signal send failure to produce a public operation failure")
    } catch {
        let failure = try #require(operationFailure(from: error))
        #expect(failure.scope == .session)
        #expect(failure.code == .transportError)
        #expect(failure.diagnostics.requestType == "signal")
        #expect(failure.diagnostics.localChannelID == 0)
        #expect(failure.diagnostics.remoteChannelID == 73)
    }

    let events = recorder.snapshot()
    let failureEvent = events.last(where: { event in
        event.metadata["scope"] == "session"
            && event.metadata["requestType"] == "signal"
    })
    let signalFailureEvent = try #require(failureEvent)
    #expect(signalFailureEvent.category == .session)
    #expect(signalFailureEvent.metadata["code"] == "transportError")
    #expect(signalFailureEvent.metadata["localChannelID"] == "0")
    #expect(signalFailureEvent.metadata["remoteChannelID"] == "73")
}

@Test
func sshClientPreservesWindowChangeRequestTypeForTransportFailureDiagnostics() async throws {
    let transport = try makeOpenShellFixtureTransport()
    let recorder = SSHClientLogEventRecorder()
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    do {
        _ = try await SSHClient.withConnection(
            configuration: configuration,
            logHandler: .sink(minimumLevel: .debug) { event in
                recorder.record(event)
            },
            transportRunner: { _, handler in
                try await handler(transport)
            }
        ) { connection in
            let session = try await connection.openShell()
            await transport.enqueueSendFailure(.EPIPE)
            try await session.resizePseudoTerminal(
                characterWidth: 120,
                characterHeight: 40,
                pixelWidth: 1440,
                pixelHeight: 900
            )
        }
        Issue.record("Expected window-change send failure to produce a public operation failure")
    } catch {
        let failure = try #require(operationFailure(from: error))
        #expect(failure.scope == .session)
        #expect(failure.code == .transportError)
        #expect(failure.diagnostics.requestType == "window-change")
        #expect(failure.diagnostics.localChannelID == 0)
        #expect(failure.diagnostics.remoteChannelID == 73)
    }

    let events = recorder.snapshot()
    let failureEvent = events.last(where: { event in
        event.metadata["scope"] == "session"
            && event.metadata["requestType"] == "window-change"
    })
    let windowChangeFailureEvent = try #require(failureEvent)
    #expect(windowChangeFailureEvent.category == .session)
    #expect(windowChangeFailureEvent.metadata["code"] == "transportError")
    #expect(windowChangeFailureEvent.metadata["localChannelID"] == "0")
    #expect(windowChangeFailureEvent.metadata["remoteChannelID"] == "73")
}

@Test
func sshClientOpensSFTPAndExpiresNestedWrapperScope() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 82,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .version(
                SSHSFTPVersionMessage(
                    version: 3,
                    extensions: [
                        SSHSFTPExtension(
                            name: "posix-rename@openssh.com",
                            data: Array("1".utf8)
                        )
                    ]
                )
            )
        )
    )
    let versionPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: versionPacket
            )
        )
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            versionPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    var escapedSFTPClient: SFTPClient?
    let versionExchange: SSHSFTPVersionExchange = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let sftpClient = try await connection.openSFTP()
        escapedSFTPClient = sftpClient
        return try await sftpClient.currentVersionExchange()
    }

    #expect(versionExchange.clientVersion == 3)
    #expect(versionExchange.serverVersion == 3)
    #expect(versionExchange.supportsExtension(named: "posix-rename@openssh.com", minimumVersion: 1))

    let sftpClient = try #require(escapedSFTPClient)
    do {
        _ = try await sftpClient.currentVersionExchange()
        Issue.record("Expected SFTP wrapper scope to expire after withConnection returned")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
}

@Test
func sshClientOpensPublicSFTPFileHandleAndRunsHandleScopedOperations() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 82,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPayload = try makeSFTPChannelDataPayload(
        .version(
            SSHSFTPVersionMessage(
                version: 3,
                extensions: [
                    SSHSFTPExtension(
                        name: "fstatvfs@openssh.com",
                        data: Array("2".utf8)
                    ),
                    SSHSFTPExtension(
                        name: "fsync@openssh.com",
                        data: Array("1".utf8)
                    ),
                ]
            )
        )
    )
    let fileHandle = SSHSFTPHandle(bytes: [0xaa, 0xbb, 0xcc, 0xdd])
    let fileAttributes = SSHSFTPFileAttributes(
        flags: SSHSFTPFileAttributes.permissionsFlag,
        size: nil,
        userID: nil,
        groupID: nil,
        permissions: 0o100600,
        accessTime: nil,
        modificationTime: nil,
        extensions: []
    )
    let updatedAttributes = SSHSFTPFileAttributes(
        flags: SSHSFTPFileAttributes.permissionsFlag,
        size: nil,
        userID: nil,
        groupID: nil,
        permissions: 0o100640,
        accessTime: nil,
        modificationTime: nil,
        extensions: []
    )
    let fileSystemAttributes = SSHSFTPFileSystemAttributes(
        blockSize: 4_096,
        fundamentalBlockSize: 4_096,
        totalBlocks: 100_000,
        freeBlocks: 50_000,
        availableBlocks: 48_000,
        totalFileNodes: 10_000,
        freeFileNodes: 9_000,
        availableFileNodes: 8_900,
        fileSystemID: 42,
        flags: [.readOnly],
        maximumFilenameLength: 255
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            versionPayload,
            try makeSFTPChannelDataPayload(
                .handle(
                    SSHSFTPHandleMessage(
                        requestID: 0,
                        handle: fileHandle
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .attributes(
                    SSHSFTPAttributesMessage(
                        requestID: 1,
                        attributes: fileAttributes
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 2,
                        statusCode: .ok,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                makeExtendedReplyMessage(
                    requestID: 3,
                    attributes: fileSystemAttributes
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 4,
                        statusCode: .ok,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 5,
                        statusCode: .ok,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 6,
                        statusCode: .ok,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let result = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let sftp = try await connection.openSFTP()
        let handle = try await sftp.openFile(
            "/tmp/example.txt",
            flags: [.write, .create]
        )
        let stat = try await handle.stat()
        try await handle.setAttributes(updatedAttributes)
        let filesystem = try await handle.fileSystemAttributes()
        try await handle.write(Array("tail".utf8), at: 5)
        try await handle.synchronize()
        try await handle.close()
        return (stat, filesystem)
    }

    #expect(result.0 == fileAttributes)
    #expect(result.1 == fileSystemAttributes)

    let sentMessages = try await extractSentSFTPMessages(from: transport)
    let expectedMessages: [SSHSFTPMessage] = [
        .initialize(SSHSFTPInitializeMessage(version: 3)),
        .openFile(
            SSHSFTPOpenFileMessage(
                requestID: 0,
                path: "/tmp/example.txt",
                pflags: [.write, .create],
                attributes: .empty
            )
        ),
        .fstat(
            SSHSFTPFStatMessage(
                requestID: 1,
                handle: fileHandle
            )
        ),
        .fsetAttributes(
            SSHSFTPFSetAttributesMessage(
                requestID: 2,
                handle: fileHandle,
                attributes: updatedAttributes
            )
        ),
        .fstatVFS(
            SSHSFTPFStatVFSMessage(
                requestID: 3,
                handle: fileHandle
            )
        ),
        .writeFile(
            SSHSFTPWriteFileMessage(
                requestID: 4,
                handle: fileHandle,
                offset: 5,
                data: Array("tail".utf8)
            )
        ),
        .fsync(
            SSHSFTPFSyncMessage(
                requestID: 5,
                handle: fileHandle
            )
        ),
        .close(
            SSHSFTPCloseMessage(
                requestID: 6,
                handle: fileHandle
            )
        ),
    ]
    #expect(
        sentMessages == expectedMessages
    )
}

@Test
func sshClientPublicSFTPFileHandleTracksCursorForSequentialReads() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 91,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPayload = try makeSFTPChannelDataPayload(
        .version(
            SSHSFTPVersionMessage(
                version: 3,
                extensions: []
            )
        )
    )
    let fileHandle = SSHSFTPHandle(bytes: [0x50, 0x51, 0x52, 0x53])
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            versionPayload,
            try makeSFTPChannelDataPayload(
                .handle(
                    SSHSFTPHandleMessage(
                        requestID: 0,
                        handle: fileHandle
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .data(
                    SSHSFTPDataMessage(
                        requestID: 1,
                        data: Array("abcd".utf8)
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .data(
                    SSHSFTPDataMessage(
                        requestID: 2,
                        data: Array("ef".utf8)
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 3,
                        statusCode: .endOfFile,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .data(
                    SSHSFTPDataMessage(
                        requestID: 4,
                        data: Array("ab".utf8)
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 5,
                        statusCode: .ok,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let result = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let sftp = try await connection.openSFTP()
        let handle = try await sftp.openFile("/tmp/example.txt")
        #expect(try await handle.tell() == 0)

        let first = try await handle.read(length: 4)
        #expect(try await handle.tell() == 4)

        let second = try await handle.read(length: 4)
        #expect(try await handle.tell() == 6)

        let eof = try await handle.read(length: 4)
        #expect(eof == nil)
        #expect(try await handle.tell() == 6)

        try await handle.rewind()
        #expect(try await handle.tell() == 0)

        let reread = try await handle.read(length: 2)
        #expect(try await handle.tell() == 2)

        try await handle.close()
        return (first, second, reread)
    }

    #expect(result.0 == Array("abcd".utf8))
    #expect(result.1 == Array("ef".utf8))
    #expect(result.2 == Array("ab".utf8))

    let sentMessages = try await extractSentSFTPMessages(from: transport)
    let expectedMessages: [SSHSFTPMessage] = [
        .initialize(SSHSFTPInitializeMessage(version: 3)),
        .openFile(
            SSHSFTPOpenFileMessage(
                requestID: 0,
                path: "/tmp/example.txt",
                pflags: [.read],
                attributes: .empty
            )
        ),
        .readFile(
            SSHSFTPReadFileMessage(
                requestID: 1,
                handle: fileHandle,
                offset: 0,
                length: 4
            )
        ),
        .readFile(
            SSHSFTPReadFileMessage(
                requestID: 2,
                handle: fileHandle,
                offset: 4,
                length: 4
            )
        ),
        .readFile(
            SSHSFTPReadFileMessage(
                requestID: 3,
                handle: fileHandle,
                offset: 6,
                length: 4
            )
        ),
        .readFile(
            SSHSFTPReadFileMessage(
                requestID: 4,
                handle: fileHandle,
                offset: 0,
                length: 2
            )
        ),
        .close(
            SSHSFTPCloseMessage(
                requestID: 5,
                handle: fileHandle
            )
        ),
    ]
    #expect(sentMessages == expectedMessages)
}

@Test
func sshClientPublicSFTPFileHandleReleasesCursorAfterOffsetOverflow() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 93,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPayload = try makeSFTPChannelDataPayload(
        .version(
            SSHSFTPVersionMessage(
                version: 3,
                extensions: []
            )
        )
    )
    let fileHandle = SSHSFTPHandle(bytes: [0x58, 0x59, 0x5a, 0x5b])
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            versionPayload,
            try makeSFTPChannelDataPayload(
                .handle(
                    SSHSFTPHandleMessage(
                        requestID: 0,
                        handle: fileHandle
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .data(
                    SSHSFTPDataMessage(
                        requestID: 1,
                        data: Array("x".utf8)
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .data(
                    SSHSFTPDataMessage(
                        requestID: 2,
                        data: Array("y".utf8)
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 3,
                        statusCode: .ok,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let recoveredRead = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let sftp = try await connection.openSFTP()
        let handle = try await sftp.openFile("/tmp/example.txt")
        try await handle.seek(to: UInt64.max)

        do {
            _ = try await handle.read(length: 1)
            Issue.record("Expected cursor offset overflow")
        } catch SSHSFTPFileHandleError.cursorOffsetOverflow(
            current: UInt64.max,
            byteCount: 1
        ) {
        } catch {
            Issue.record("Expected cursor offset overflow, got \(String(reflecting: error))")
        }

        try await handle.seek(to: 0)
        let recoveredRead = try await handle.read(length: 1)
        try await handle.close()
        return recoveredRead
    }

    #expect(recoveredRead == Array("y".utf8))

    let sentMessages = try await extractSentSFTPMessages(from: transport)
    let expectedMessages: [SSHSFTPMessage] = [
        .initialize(SSHSFTPInitializeMessage(version: 3)),
        .openFile(
            SSHSFTPOpenFileMessage(
                requestID: 0,
                path: "/tmp/example.txt",
                pflags: [.read],
                attributes: .empty
            )
        ),
        .readFile(
            SSHSFTPReadFileMessage(
                requestID: 1,
                handle: fileHandle,
                offset: UInt64.max,
                length: 1
            )
        ),
        .readFile(
            SSHSFTPReadFileMessage(
                requestID: 2,
                handle: fileHandle,
                offset: 0,
                length: 1
            )
        ),
        .close(
            SSHSFTPCloseMessage(
                requestID: 3,
                handle: fileHandle
            )
        ),
    ]
    #expect(sentMessages == expectedMessages)
}

@Test
func sshClientPublicSFTPFileHandleTracksCursorForSequentialWrites() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 92,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPayload = try makeSFTPChannelDataPayload(
        .version(
            SSHSFTPVersionMessage(
                version: 3,
                extensions: []
            )
        )
    )
    let fileHandle = SSHSFTPHandle(bytes: [0x54, 0x55, 0x56, 0x57])
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            versionPayload,
            try makeSFTPChannelDataPayload(
                .handle(
                    SSHSFTPHandleMessage(
                        requestID: 0,
                        handle: fileHandle
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 1,
                        statusCode: .ok,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 2,
                        statusCode: .ok,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 3,
                        statusCode: .ok,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let sftp = try await connection.openSFTP()
        let handle = try await sftp.openFile(
            "/tmp/example.txt",
            flags: [.write, .create]
        )
        #expect(try await handle.tell() == 0)

        try await handle.seek(to: 5)
        #expect(try await handle.tell() == 5)

        try await handle.write(Array("ab".utf8))
        #expect(try await handle.tell() == 7)

        try await handle.write(Array("cde".utf8))
        #expect(try await handle.tell() == 10)

        try await handle.close()
    }

    let sentMessages = try await extractSentSFTPMessages(from: transport)
    let expectedMessages: [SSHSFTPMessage] = [
        .initialize(SSHSFTPInitializeMessage(version: 3)),
        .openFile(
            SSHSFTPOpenFileMessage(
                requestID: 0,
                path: "/tmp/example.txt",
                pflags: [.write, .create],
                attributes: .empty
            )
        ),
        .writeFile(
            SSHSFTPWriteFileMessage(
                requestID: 1,
                handle: fileHandle,
                offset: 5,
                data: Array("ab".utf8)
            )
        ),
        .writeFile(
            SSHSFTPWriteFileMessage(
                requestID: 2,
                handle: fileHandle,
                offset: 7,
                data: Array("cde".utf8)
            )
        ),
        .close(
            SSHSFTPCloseMessage(
                requestID: 3,
                handle: fileHandle
            )
        ),
    ]
    #expect(sentMessages == expectedMessages)
}

@Test
func sshClientPublicSFTPFileHandleReadsWholeFile() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x10, 0x20, 0x30, 0x40])
    let progressRecorder = SFTPTransferProgressRecorder()
    let fixture = try await makeConcurrentSFTPFixture(
        senderChannel: 83
    )
    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let connection = SSHConnection(
        metadata: SSHConnectionMetadata(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: [],
            hostKeyAlgorithm: "ssh-ed25519",
            hostKeyFingerprintSHA256: "fingerprint",
            hostKeyTrustMethod: .acceptAnyVerifiedHostKey
        ),
        client: fixture.client,
        lifetime: SSHConnectionLifetime(),
        logHandler: .disabled
    )

    let dataTask = Task {
        let sftp = try await connection.openSFTP()
        let handle = try await sftp.openFile("/tmp/example.txt")
        let fileData = try await handle.readAll(
            chunkSize: 4,
            maxConcurrentReads: 2,
            progress: { value in
                await progressRecorder.record(value)
            }
        )
        try await handle.close()
        return fileData
    }
    defer { dataTask.cancel() }

    let openMessages = try await waitForSentSFTPMessages(
        minimumCount: 2,
        from: fixture
    )
    let openMessage = try #require(openMessages.last)
    let openRequest: SSHSFTPOpenFileMessage
    switch openMessage {
    case let .openFile(message):
        openRequest = message
    default:
        Issue.record("Expected second SFTP message to be openFile, got \(openMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let sentMessages = try await waitForSentSFTPMessages(
        minimumCount: 4,
        from: fixture
    )
    let readRequests = sentMessages.compactMap { message -> SSHSFTPReadFileMessage? in
        guard case let .readFile(readMessage) = message else {
            return nil
        }
        return readMessage
    }
    #expect(readRequests.count == 2)
    #expect(readRequests.map(\.offset) == [0, 4])
    #expect(readRequests.map(\.length) == [4, 4])

    let firstReadRequest = try #require(readRequests.first(where: { $0.offset == 0 }))
    let secondReadRequest = try #require(readRequests.first(where: { $0.offset == 4 }))

    try await fixture.server.appendSFTPMessages(
        [
            .data(
                SSHSFTPDataMessage(
                    requestID: secondReadRequest.requestID,
                    data: Array("ef".utf8)
                )
            ),
            .data(
                SSHSFTPDataMessage(
                    requestID: firstReadRequest.requestID,
                    data: Array("abcd".utf8)
                )
            ),
        ]
    )

    let sentMessagesAfterEOFRead = try await waitForSentSFTPMessages(
        minimumCount: 6,
        from: fixture
    )
    let eofReadMessage = try #require(sentMessagesAfterEOFRead.last)
    let eofReadRequest: SSHSFTPReadFileMessage
    switch eofReadMessage {
    case let .readFile(message):
        eofReadRequest = message
    default:
        Issue.record("Expected trailing SFTP message to be readFile, got \(eofReadMessage)")
        return
    }

    #expect(eofReadRequest.offset == 6)
    #expect(eofReadRequest.length == 4)

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: eofReadRequest.requestID,
                    statusCode: .endOfFile,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    let sentMessagesAfterClose = try await waitForSentSFTPMessages(
        minimumCount: 7,
        from: fixture
    )
    let closeMessage = try #require(sentMessagesAfterClose.last)
    let closeRequest: SSHSFTPCloseMessage
    switch closeMessage {
    case let .close(message):
        closeRequest = message
    default:
        Issue.record("Expected trailing SFTP message to be close, got \(closeMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: closeRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    let data = try await dataTask.value

    #expect(data == Array("abcdef".utf8))
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .read, bytesTransferred: 4),
                .init(operation: .read, bytesTransferred: 6),
            ]
    )

    let allSentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
    let expectedMessages: [SSHSFTPMessage] = [
        .openFile(
            SSHSFTPOpenFileMessage(
                requestID: 0,
                path: "/tmp/example.txt",
                pflags: [.read],
                attributes: .empty
            )
        ),
        .readFile(
            SSHSFTPReadFileMessage(
                requestID: 1,
                handle: fileHandle,
                offset: 0,
                length: 4
            )
        ),
        .readFile(
            SSHSFTPReadFileMessage(
                requestID: 2,
                handle: fileHandle,
                offset: 4,
                length: 4
            )
        ),
        .readFile(
            SSHSFTPReadFileMessage(
                requestID: 3,
                handle: fileHandle,
                offset: 8,
                length: 4
            )
        ),
        .readFile(
            SSHSFTPReadFileMessage(
                requestID: 4,
                handle: fileHandle,
                offset: 6,
                length: 4
            )
        ),
        .close(
            SSHSFTPCloseMessage(
                requestID: 5,
                handle: fileHandle
            )
        ),
    ]
    #expect(allSentMessages == expectedMessages)
}

@Test
func sshClientPublicSFTPFileHandleStreamsReadChunks() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 84,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPayload = try makeSFTPChannelDataPayload(
        .version(
            SSHSFTPVersionMessage(
                version: 3,
                extensions: []
            )
        )
    )
    let fileHandle = SSHSFTPHandle(bytes: [0x11, 0x22, 0x33, 0x44])
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            versionPayload,
            try makeSFTPChannelDataPayload(
                .handle(
                    SSHSFTPHandleMessage(
                        requestID: 0,
                        handle: fileHandle
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .data(
                    SSHSFTPDataMessage(
                        requestID: 1,
                        data: Array("abcd".utf8)
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .data(
                    SSHSFTPDataMessage(
                        requestID: 2,
                        data: Array("ef".utf8)
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 3,
                        statusCode: .endOfFile,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 4,
                        statusCode: .ok,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let chunks = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let sftp = try await connection.openSFTP()
        let handle = try await sftp.openFile("/tmp/example.txt")
        var receivedChunks: [SSHSFTPFileChunk] = []
        for try await chunk in handle.readChunks(chunkSize: 4) {
            receivedChunks.append(chunk)
        }
        try await handle.close()
        return receivedChunks
    }

    #expect(
        chunks == [
            SSHSFTPFileChunk(offset: 0, bytes: Array("abcd".utf8)),
            SSHSFTPFileChunk(offset: 4, bytes: Array("ef".utf8)),
        ]
    )

    let sentMessages = try await extractSentSFTPMessages(from: transport)
    let expectedMessages: [SSHSFTPMessage] = [
        .initialize(SSHSFTPInitializeMessage(version: 3)),
        .openFile(
            SSHSFTPOpenFileMessage(
                requestID: 0,
                path: "/tmp/example.txt",
                pflags: [.read],
                attributes: .empty
            )
        ),
        .readFile(
            SSHSFTPReadFileMessage(
                requestID: 1,
                handle: fileHandle,
                offset: 0,
                length: 4
            )
        ),
        .readFile(
            SSHSFTPReadFileMessage(
                requestID: 2,
                handle: fileHandle,
                offset: 4,
                length: 4
            )
        ),
        .readFile(
            SSHSFTPReadFileMessage(
                requestID: 3,
                handle: fileHandle,
                offset: 6,
                length: 4
            )
        ),
        .close(
            SSHSFTPCloseMessage(
                requestID: 4,
                handle: fileHandle
            )
        ),
    ]
    #expect(sentMessages == expectedMessages)
}

@Test
func sshClientPublicSFTPFileHandleWritesAsyncChunkStream() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 85,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPayload = try makeSFTPChannelDataPayload(
        .version(
            SSHSFTPVersionMessage(
                version: 3,
                extensions: []
            )
        )
    )
    let fileHandle = SSHSFTPHandle(bytes: [0xaa, 0xbb, 0xcc, 0xdd])
    let progressRecorder = SFTPTransferProgressRecorder()
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            versionPayload,
            try makeSFTPChannelDataPayload(
                .handle(
                    SSHSFTPHandleMessage(
                        requestID: 0,
                        handle: fileHandle
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 1,
                        statusCode: .ok,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 2,
                        statusCode: .ok,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
            try makeSFTPChannelDataPayload(
                .status(
                    SSHSFTPStatusMessage(
                        requestID: 3,
                        statusCode: .ok,
                        errorMessage: "",
                        languageTag: ""
                    )
                )
            ),
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let sftp = try await connection.openSFTP()
        let handle = try await sftp.openFile(
            "/tmp/example.txt",
            flags: [.write, .create, .truncate]
        )
        let stream = AsyncStream<[UInt8]> { continuation in
            continuation.yield(Array("ab".utf8))
            continuation.yield([])
            continuation.yield(Array("cdef".utf8))
            continuation.finish()
        }
        try await handle.write(
            contentsOf: stream,
            startingAt: 5,
            progress: { value in
                await progressRecorder.record(value)
            }
        )
        try await handle.close()
    }

    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .write, bytesTransferred: 2),
                .init(operation: .write, bytesTransferred: 6),
            ]
    )

    let sentMessages = try await extractSentSFTPMessages(from: transport)
    let expectedMessages: [SSHSFTPMessage] = [
        .initialize(SSHSFTPInitializeMessage(version: 3)),
        .openFile(
            SSHSFTPOpenFileMessage(
                requestID: 0,
                path: "/tmp/example.txt",
                pflags: [.write, .create, .truncate],
                attributes: .empty
            )
        ),
        .writeFile(
            SSHSFTPWriteFileMessage(
                requestID: 1,
                handle: fileHandle,
                offset: 5,
                data: Array("ab".utf8)
            )
        ),
        .writeFile(
            SSHSFTPWriteFileMessage(
                requestID: 2,
                handle: fileHandle,
                offset: 7,
                data: Array("cdef".utf8)
            )
        ),
        .close(
            SSHSFTPCloseMessage(
                requestID: 3,
                handle: fileHandle
            )
        ),
    ]
    #expect(sentMessages == expectedMessages)
}

@Test
func sshConnectionWritesWholeFileWithBoundedConcurrentSFTPRequests() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x21, 0x43, 0x65, 0x87])
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let connection = SSHConnection(
        metadata: SSHConnectionMetadata(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: [],
            hostKeyAlgorithm: "ssh-ed25519",
            hostKeyFingerprintSHA256: "fingerprint",
            hostKeyTrustMethod: .acceptAnyVerifiedHostKey
        ),
        client: fixture.client,
        lifetime: SSHConnectionLifetime(),
        logHandler: .disabled
    )
    let sftp = try await connection.openSFTP()

    let writeTask = Task {
        try await sftp.writeFile(
            "/root/output.txt",
            data: Array("abcdefghij".utf8),
            chunkSize: 4,
            maxConcurrentWrites: 2,
            progress: { value in
                await progressRecorder.record(value)
            }
        )
    }
    defer { writeTask.cancel() }

    let openFileMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    let openFileMessage = try #require(openFileMessages.first)
    let openFileRequest: SSHSFTPOpenFileMessage
    switch openFileMessage {
    case let .openFile(message):
        openFileRequest = message
    default:
        Issue.record("Expected first SFTP message to be openFile, got \(openFileMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openFileRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let sentMessages = try await waitForSentSFTPMessages(
        minimumCount: 3,
        from: fixture
    )
    #expect(sentMessages.count == 3)

    let writeRequests = sentMessages.compactMap { message -> SSHSFTPWriteFileMessage? in
        guard case let .writeFile(writeMessage) = message else {
            return nil
        }
        return writeMessage
    }
    #expect(writeRequests.count == 2)
    #expect(writeRequests.map(\.offset) == [0, 4])
    #expect(writeRequests.map(\.data) == [Array("abcd".utf8), Array("efgh".utf8)])

    let firstWriteRequest = try #require(writeRequests.first(where: { $0.offset == 0 }))
    let secondWriteRequest = try #require(writeRequests.first(where: { $0.offset == 4 }))

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: secondWriteRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            ),
            .status(
                SSHSFTPStatusMessage(
                    requestID: firstWriteRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            ),
        ]
    )

    let sentMessagesAfterThirdWrite = try await waitForSentSFTPMessages(
        minimumCount: 4,
        from: fixture
    )
    #expect(sentMessagesAfterThirdWrite.count == 4)
    let thirdWriteMessage = try #require(sentMessagesAfterThirdWrite.last)

    guard case let .writeFile(thirdWriteRequest) = thirdWriteMessage else {
        Issue.record("Expected trailing SFTP message to be writeFile, got \(thirdWriteMessage)")
        return
    }

    #expect(thirdWriteRequest.handle == fileHandle)
    #expect(thirdWriteRequest.offset == 8)
    #expect(thirdWriteRequest.data == Array("ij".utf8))

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: thirdWriteRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            ),
        ]
    )

    let sentMessagesAfterClose = try await waitForSentSFTPMessages(
        minimumCount: 5,
        from: fixture
    )
    #expect(sentMessagesAfterClose.count == 5)
    let closeMessage = try #require(sentMessagesAfterClose.last)

    #expect(
        closeMessage
            == .close(
                SSHSFTPCloseMessage(
                    requestID: thirdWriteRequest.requestID + 1,
                    handle: fileHandle
                )
            )
    )

    guard case let .close(closeRequest) = closeMessage else {
        Issue.record("Expected trailing SFTP message to be close, got \(closeMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: closeRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    try await writeTask.value
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .write, bytesTransferred: 4, totalBytes: 10),
                .init(operation: .write, bytesTransferred: 8, totalBytes: 10),
                .init(operation: .write, bytesTransferred: 10, totalBytes: 10),
            ]
    )
}

@Test
func sshConnectionResumesSFTPUploadFromExistingRemoteSize() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x10, 0x32, 0x54, 0x76])
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let connection = SSHConnection(
        metadata: SSHConnectionMetadata(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: [],
            hostKeyAlgorithm: "ssh-ed25519",
            hostKeyFingerprintSHA256: "fingerprint",
            hostKeyTrustMethod: .acceptAnyVerifiedHostKey
        ),
        client: fixture.client,
        lifetime: SSHConnectionLifetime(),
        logHandler: .disabled
    )
    let sftp = try await connection.openSFTP()

    let uploadTask = Task {
        try await sftp.resumeUploadFile(
            "/root/output.txt",
            data: Array("abcdefghijkl".utf8),
            chunkSize: 4,
            maxConcurrentWrites: 2,
            progress: { value in
                await progressRecorder.record(value)
            }
        )
    }
    defer { uploadTask.cancel() }

    let initialMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    let statMessage = try #require(initialMessages.first)
    let statRequest: SSHSFTPStatMessage
    switch statMessage {
    case let .stat(message):
        statRequest = message
    default:
        Issue.record("Expected first SFTP message to be stat, got \(statMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: statRequest.requestID,
                    attributes: SSHSFTPFileAttributes(
                        flags: SSHSFTPFileAttributes.sizeFlag,
                        size: 5,
                        userID: nil,
                        groupID: nil,
                        permissions: nil,
                        accessTime: nil,
                        modificationTime: nil,
                        extensions: []
                    )
                )
            )
        ]
    )

    let openMessages = try await waitForSentSFTPMessages(
        minimumCount: 2,
        from: fixture
    )
    let openMessage = try #require(openMessages.last)
    let openRequest: SSHSFTPOpenFileMessage
    switch openMessage {
    case let .openFile(message):
        openRequest = message
    default:
        Issue.record("Expected second SFTP message to be openFile, got \(openMessage)")
        return
    }
    #expect(openRequest.pflags == [.write, .create])

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let sentMessages = try await waitForSentSFTPMessages(
        minimumCount: 4,
        from: fixture
    )
    #expect(sentMessages.count == 4)

    let writeRequests = sentMessages.compactMap { message -> SSHSFTPWriteFileMessage? in
        guard case let .writeFile(writeMessage) = message else {
            return nil
        }
        return writeMessage
    }
    #expect(writeRequests.count == 2)
    #expect(writeRequests.map(\.offset) == [5, 9])
    #expect(writeRequests.map(\.data) == [Array("fghi".utf8), Array("jkl".utf8)])

    let firstWriteRequest = try #require(writeRequests.first(where: { $0.offset == 5 }))
    let secondWriteRequest = try #require(writeRequests.first(where: { $0.offset == 9 }))

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: secondWriteRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            ),
            .status(
                SSHSFTPStatusMessage(
                    requestID: firstWriteRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            ),
        ]
    )

    let sentMessagesAfterClose = try await waitForSentSFTPMessages(
        minimumCount: 5,
        from: fixture
    )
    let closeMessage = try #require(sentMessagesAfterClose.last)
    let closeRequest: SSHSFTPCloseMessage
    switch closeMessage {
    case let .close(message):
        closeRequest = message
    default:
        Issue.record("Expected trailing SFTP message to be close, got \(closeMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: closeRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    let result = try await uploadTask.value
    #expect(
        result == SSHSFTPResumeUploadResult(
            path: "/root/output.txt",
            startingOffset: 5,
            bytesUploaded: 7,
            totalBytes: 12
        )
    )
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .write, bytesTransferred: 5, totalBytes: 12),
                .init(operation: .write, bytesTransferred: 9, totalBytes: 12),
                .init(operation: .write, bytesTransferred: 12, totalBytes: 12),
            ]
    )
}

@Test
func sshConnectionResumeUploadStartsFromZeroWhenRemoteFileIsMissing() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0xaa, 0xbb, 0xcc, 0xdd])
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let connection = SSHConnection(
        metadata: SSHConnectionMetadata(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: [],
            hostKeyAlgorithm: "ssh-ed25519",
            hostKeyFingerprintSHA256: "fingerprint",
            hostKeyTrustMethod: .acceptAnyVerifiedHostKey
        ),
        client: fixture.client,
        lifetime: SSHConnectionLifetime(),
        logHandler: .disabled
    )
    let sftp = try await connection.openSFTP()

    let uploadTask = Task {
        try await sftp.resumeUploadFile(
            "/root/new.txt",
            data: Array("abcde".utf8),
            chunkSize: 4,
            maxConcurrentWrites: 2,
            progress: { value in
                await progressRecorder.record(value)
            }
        )
    }
    defer { uploadTask.cancel() }

    let initialMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    let statMessage = try #require(initialMessages.first)
    let statRequest: SSHSFTPStatMessage
    switch statMessage {
    case let .stat(message):
        statRequest = message
    default:
        Issue.record("Expected first SFTP message to be stat, got \(statMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: statRequest.requestID,
                    statusCode: .noSuchFile,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    let openMessages = try await waitForSentSFTPMessages(
        minimumCount: 2,
        from: fixture
    )
    let openMessage = try #require(openMessages.last)
    let openRequest: SSHSFTPOpenFileMessage
    switch openMessage {
    case let .openFile(message):
        openRequest = message
    default:
        Issue.record("Expected second SFTP message to be openFile, got \(openMessage)")
        return
    }
    #expect(openRequest.pflags == [.write, .create])

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let sentMessages = try await waitForSentSFTPMessages(
        minimumCount: 4,
        from: fixture
    )
    #expect(sentMessages.count == 4)

    let writeRequests = sentMessages.compactMap { message -> SSHSFTPWriteFileMessage? in
        guard case let .writeFile(writeMessage) = message else {
            return nil
        }
        return writeMessage
    }
    #expect(writeRequests.count == 2)
    #expect(writeRequests.map(\.offset) == [0, 4])
    #expect(writeRequests.map(\.data) == [Array("abcd".utf8), Array("e".utf8)])

    let firstWriteRequest = try #require(writeRequests.first(where: { $0.offset == 0 }))
    let secondWriteRequest = try #require(writeRequests.first(where: { $0.offset == 4 }))

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: firstWriteRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            ),
            .status(
                SSHSFTPStatusMessage(
                    requestID: secondWriteRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            ),
        ]
    )

    let sentMessagesAfterClose = try await waitForSentSFTPMessages(
        minimumCount: 5,
        from: fixture
    )
    let closeMessage = try #require(sentMessagesAfterClose.last)
    let closeRequest: SSHSFTPCloseMessage
    switch closeMessage {
    case let .close(message):
        closeRequest = message
    default:
        Issue.record("Expected trailing SFTP message to be close, got \(closeMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: closeRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    let result = try await uploadTask.value
    #expect(
        result == SSHSFTPResumeUploadResult(
            path: "/root/new.txt",
            startingOffset: 0,
            bytesUploaded: 5,
            totalBytes: 5
        )
    )
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .write, bytesTransferred: 4, totalBytes: 5),
                .init(operation: .write, bytesTransferred: 5, totalBytes: 5),
            ]
    )
}

@Test
func sshConnectionResumeUploadRejectsRemoteFileLargerThanLocalData() async throws {
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let connection = SSHConnection(
        metadata: SSHConnectionMetadata(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: [],
            hostKeyAlgorithm: "ssh-ed25519",
            hostKeyFingerprintSHA256: "fingerprint",
            hostKeyTrustMethod: .acceptAnyVerifiedHostKey
        ),
        client: fixture.client,
        lifetime: SSHConnectionLifetime(),
        logHandler: .disabled
    )
    let sftp = try await connection.openSFTP()

    let uploadTask = Task {
        try await sftp.resumeUploadFile(
            "/root/output.txt",
            data: Array("abc".utf8)
        )
    }
    defer { uploadTask.cancel() }

    let initialMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    let statMessage = try #require(initialMessages.first)
    let statRequest: SSHSFTPStatMessage
    switch statMessage {
    case let .stat(message):
        statRequest = message
    default:
        Issue.record("Expected first SFTP message to be stat, got \(statMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: statRequest.requestID,
                    attributes: SSHSFTPFileAttributes(
                        flags: SSHSFTPFileAttributes.sizeFlag,
                        size: 5,
                        userID: nil,
                        groupID: nil,
                        permissions: nil,
                        accessTime: nil,
                        modificationTime: nil,
                        extensions: []
                    )
                )
            )
        ]
    )

    do {
        _ = try await uploadTask.value
        Issue.record("Expected resume upload to reject remote file larger than local data")
    } catch let error as SSHSFTPResumeError {
        #expect(
            error == .remoteFileIsLargerThanLocalData(
                path: "/root/output.txt",
                remoteSize: 5,
                localSize: 3
            )
        )
    } catch {
        Issue.record("Expected SSHSFTPResumeError, got \(String(reflecting: error))")
    }

    let sentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
    #expect(sentMessages.count == 1)
}

@Test
func sshConnectionResumesSFTPDownloadFromExistingLocalData() async throws {
    let fileHandle = SSHSFTPHandle(bytes: [0x31, 0x42, 0x53, 0x64])
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let connection = SSHConnection(
        metadata: SSHConnectionMetadata(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: [],
            hostKeyAlgorithm: "ssh-ed25519",
            hostKeyFingerprintSHA256: "fingerprint",
            hostKeyTrustMethod: .acceptAnyVerifiedHostKey
        ),
        client: fixture.client,
        lifetime: SSHConnectionLifetime(),
        logHandler: .disabled
    )
    let sftp = try await connection.openSFTP()

    let downloadTask = Task {
        try await sftp.resumeDownloadFile(
            "/root/output.txt",
            existingData: Array("abcde".utf8),
            chunkSize: 4,
            maxConcurrentReads: 2,
            progress: { value in
                await progressRecorder.record(value)
            }
        )
    }
    defer { downloadTask.cancel() }

    let initialMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    let statMessage = try #require(initialMessages.first)
    let statRequest: SSHSFTPStatMessage
    switch statMessage {
    case let .stat(message):
        statRequest = message
    default:
        Issue.record("Expected first SFTP message to be stat, got \(statMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: statRequest.requestID,
                    attributes: SSHSFTPFileAttributes(
                        flags: SSHSFTPFileAttributes.sizeFlag,
                        size: 12,
                        userID: nil,
                        groupID: nil,
                        permissions: nil,
                        accessTime: nil,
                        modificationTime: nil,
                        extensions: []
                    )
                )
            )
        ]
    )

    let openMessages = try await waitForSentSFTPMessages(
        minimumCount: 2,
        from: fixture
    )
    let openMessage = try #require(openMessages.last)
    let openRequest: SSHSFTPOpenFileMessage
    switch openMessage {
    case let .openFile(message):
        openRequest = message
    default:
        Issue.record("Expected second SFTP message to be openFile, got \(openMessage)")
        return
    }
    #expect(openRequest.pflags == [.read])

    try await fixture.server.appendSFTPMessages(
        [
            .handle(
                SSHSFTPHandleMessage(
                    requestID: openRequest.requestID,
                    handle: fileHandle
                )
            )
        ]
    )

    let sentMessages = try await waitForSentSFTPMessages(
        minimumCount: 4,
        from: fixture
    )
    #expect(sentMessages.count == 4)

    let readRequests = sentMessages.compactMap { message -> SSHSFTPReadFileMessage? in
        guard case let .readFile(readMessage) = message else {
            return nil
        }
        return readMessage
    }
    #expect(readRequests.count == 2)
    #expect(readRequests.map(\.offset) == [5, 9])
    #expect(readRequests.map(\.length) == [4, 4])

    let firstReadRequest = try #require(readRequests.first(where: { $0.offset == 5 }))
    let secondReadRequest = try #require(readRequests.first(where: { $0.offset == 9 }))

    try await fixture.server.appendSFTPMessages(
        [
            .data(
                SSHSFTPDataMessage(
                    requestID: secondReadRequest.requestID,
                    data: Array("jkl".utf8)
                )
            ),
            .data(
                SSHSFTPDataMessage(
                    requestID: firstReadRequest.requestID,
                    data: Array("fghi".utf8)
                )
            ),
        ]
    )

    let sentMessagesAfterEOFRead = try await waitForSentSFTPMessages(
        minimumCount: 6,
        from: fixture
    )
    let eofReadMessage = try #require(sentMessagesAfterEOFRead.last)
    let eofReadRequest: SSHSFTPReadFileMessage
    switch eofReadMessage {
    case let .readFile(message):
        eofReadRequest = message
    default:
        Issue.record("Expected trailing SFTP message to be readFile, got \(eofReadMessage)")
        return
    }

    #expect(eofReadRequest.offset == 12)
    #expect(eofReadRequest.length == 4)

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: eofReadRequest.requestID,
                    statusCode: .endOfFile,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    let sentMessagesAfterClose = try await waitForSentSFTPMessages(
        minimumCount: 7,
        from: fixture
    )
    let closeMessage = try #require(sentMessagesAfterClose.last)
    let closeRequest: SSHSFTPCloseMessage
    switch closeMessage {
    case let .close(message):
        closeRequest = message
    default:
        Issue.record("Expected trailing SFTP message to be close, got \(closeMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .status(
                SSHSFTPStatusMessage(
                    requestID: closeRequest.requestID,
                    statusCode: .ok,
                    errorMessage: "",
                    languageTag: ""
                )
            )
        ]
    )

    let result = try await downloadTask.value
    #expect(
        result == SSHSFTPResumeDownloadResult(
            path: "/root/output.txt",
            startingOffset: 5,
            bytesDownloaded: 7,
            totalBytes: 12,
            data: Array("abcdefghijkl".utf8)
        )
    )
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .read, bytesTransferred: 5, totalBytes: 12),
                .init(operation: .read, bytesTransferred: 9, totalBytes: 12),
                .init(operation: .read, bytesTransferred: 12, totalBytes: 12),
            ]
    )
}

@Test
func sshConnectionResumeDownloadReturnsExistingDataWhenAlreadyComplete() async throws {
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)
    let progressRecorder = SFTPTransferProgressRecorder()

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let connection = SSHConnection(
        metadata: SSHConnectionMetadata(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: [],
            hostKeyAlgorithm: "ssh-ed25519",
            hostKeyFingerprintSHA256: "fingerprint",
            hostKeyTrustMethod: .acceptAnyVerifiedHostKey
        ),
        client: fixture.client,
        lifetime: SSHConnectionLifetime(),
        logHandler: .disabled
    )
    let sftp = try await connection.openSFTP()

    let downloadTask = Task {
        try await sftp.resumeDownloadFile(
            "/root/output.txt",
            existingData: Array("hello".utf8),
            progress: { value in
                await progressRecorder.record(value)
            }
        )
    }
    defer { downloadTask.cancel() }

    let initialMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    let statMessage = try #require(initialMessages.first)
    let statRequest: SSHSFTPStatMessage
    switch statMessage {
    case let .stat(message):
        statRequest = message
    default:
        Issue.record("Expected first SFTP message to be stat, got \(statMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: statRequest.requestID,
                    attributes: SSHSFTPFileAttributes(
                        flags: SSHSFTPFileAttributes.sizeFlag,
                        size: 5,
                        userID: nil,
                        groupID: nil,
                        permissions: nil,
                        accessTime: nil,
                        modificationTime: nil,
                        extensions: []
                    )
                )
            )
        ]
    )

    let result = try await downloadTask.value
    #expect(
        result == SSHSFTPResumeDownloadResult(
            path: "/root/output.txt",
            startingOffset: 5,
            bytesDownloaded: 0,
            totalBytes: 5,
            data: Array("hello".utf8)
        )
    )
    #expect(
        await progressRecorder.snapshot()
            == [
                .init(operation: .read, bytesTransferred: 5, totalBytes: 5)
            ]
    )

    let sentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
    #expect(sentMessages.count == 1)
}

@Test
func sshConnectionResumeDownloadRejectsRemoteFileSmallerThanLocalData() async throws {
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let connection = SSHConnection(
        metadata: SSHConnectionMetadata(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: [],
            hostKeyAlgorithm: "ssh-ed25519",
            hostKeyFingerprintSHA256: "fingerprint",
            hostKeyTrustMethod: .acceptAnyVerifiedHostKey
        ),
        client: fixture.client,
        lifetime: SSHConnectionLifetime(),
        logHandler: .disabled
    )
    let sftp = try await connection.openSFTP()

    let downloadTask = Task {
        try await sftp.resumeDownloadFile(
            "/root/output.txt",
            existingData: Array("abcdefg".utf8)
        )
    }
    defer { downloadTask.cancel() }

    let initialMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    let statMessage = try #require(initialMessages.first)
    let statRequest: SSHSFTPStatMessage
    switch statMessage {
    case let .stat(message):
        statRequest = message
    default:
        Issue.record("Expected first SFTP message to be stat, got \(statMessage)")
        return
    }

    try await fixture.server.appendSFTPMessages(
        [
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: statRequest.requestID,
                    attributes: SSHSFTPFileAttributes(
                        flags: SSHSFTPFileAttributes.sizeFlag,
                        size: 5,
                        userID: nil,
                        groupID: nil,
                        permissions: nil,
                        accessTime: nil,
                        modificationTime: nil,
                        extensions: []
                    )
                )
            )
        ]
    )

    do {
        _ = try await downloadTask.value
        Issue.record("Expected resume download to reject local data larger than the remote file")
    } catch let error as SSHSFTPResumeError {
        #expect(
            error == .remoteFileIsSmallerThanLocalData(
                path: "/root/output.txt",
                remoteSize: 5,
                localSize: 7
            )
        )
    } catch {
        Issue.record("Expected SSHSFTPResumeError, got \(String(reflecting: error))")
    }

    let sentMessages = try await extractConcurrentSentSFTPMessages(from: fixture)
    #expect(sentMessages.count == 1)
}

@Test
func sshConnectionRoutesConcurrentSFTPRepliesOnSingleClient() async throws {
    let expectedAttributes = SSHSFTPFileAttributes(
        flags: SSHSFTPFileAttributes.sizeFlag | SSHSFTPFileAttributes.permissionsFlag,
        size: 512,
        userID: nil,
        groupID: nil,
        permissions: 0o644,
        accessTime: nil,
        modificationTime: nil,
        extensions: []
    )
    let expectedLinkEntry = SSHSFTPNameEntry(
        filename: "/root/releases/current",
        longName: "/root/releases/current",
        attributes: .empty
    )
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 106)

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let connection = SSHConnection(
        metadata: SSHConnectionMetadata(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: [],
            hostKeyAlgorithm: "ssh-ed25519",
            hostKeyFingerprintSHA256: "fingerprint",
            hostKeyTrustMethod: .acceptAnyVerifiedHostKey
        ),
        client: fixture.client,
        lifetime: SSHConnectionLifetime(),
        logHandler: .disabled
    )
    let sftp = try await connection.openSFTP()

    let statTask = Task {
        try await sftp.stat("/root/example.txt")
    }

    let firstSentMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    #expect(firstSentMessages.count == 1)
    let statRequestID = try #require(firstStatRequestID(in: firstSentMessages))

    let readLinkTask = Task {
        try await sftp.readLink("/root/current")
    }

    let sentSFTPMessages = try await waitForSentSFTPMessages(
        minimumCount: 2,
        from: fixture
    )
    #expect(sentSFTPMessages.count == 2)
    let readLinkRequestID = try #require(firstReadLinkRequestID(in: sentSFTPMessages))

    try await fixture.server.appendSFTPMessages(
        [
            .name(
                SSHSFTPNameMessage(
                    requestID: readLinkRequestID,
                    entries: [expectedLinkEntry]
                )
            ),
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: statRequestID,
                    attributes: expectedAttributes
                )
            ),
        ]
    )

    let receivedAttributes = try await statTask.value
    let receivedLinkEntry = try await readLinkTask.value

    #expect(receivedAttributes == expectedAttributes)
    #expect(receivedLinkEntry == expectedLinkEntry)
}

@Test
func sshConnectionIgnoresCancelledConcurrentSFTPReplyOnSingleClient() async throws {
    let survivingEntry = SSHSFTPNameEntry(
        filename: "/root/releases/live",
        longName: "/root/releases/live",
        attributes: .empty
    )
    let fixture = try await makeConcurrentSFTPFixture(senderChannel: 107)

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let connection = SSHConnection(
        metadata: SSHConnectionMetadata(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: [],
            hostKeyAlgorithm: "ssh-ed25519",
            hostKeyFingerprintSHA256: "fingerprint",
            hostKeyTrustMethod: .acceptAnyVerifiedHostKey
        ),
        client: fixture.client,
        lifetime: SSHConnectionLifetime(),
        logHandler: .disabled
    )
    let sftp = try await connection.openSFTP()

    let cancelledTask = Task {
        try await sftp.stat("/root/cancelled.txt")
    }

    let firstSentMessages = try await waitForSentSFTPMessages(
        minimumCount: 1,
        from: fixture
    )
    #expect(firstSentMessages.count == 1)
    let cancelledRequestID = try #require(firstStatRequestID(in: firstSentMessages))

    let survivingTask = Task {
        try await sftp.readLink("/root/current")
    }

    let sentSFTPMessages = try await waitForSentSFTPMessages(
        minimumCount: 2,
        from: fixture
    )
    #expect(sentSFTPMessages.count == 2)
    let survivingRequestID = try #require(firstReadLinkRequestID(in: sentSFTPMessages))

    cancelledTask.cancel()

    do {
        _ = try await cancelledTask.value
        Issue.record("Expected cancelled SFTP request to throw CancellationError")
    } catch is CancellationError {
    } catch {
        Issue.record("Expected CancellationError, got \(String(reflecting: error))")
    }

    try await fixture.server.appendSFTPMessages(
        [
            .attributes(
                SSHSFTPAttributesMessage(
                    requestID: cancelledRequestID,
                    attributes: SSHSFTPFileAttributes(
                        flags: SSHSFTPFileAttributes.sizeFlag,
                        size: 1_024,
                        userID: nil,
                        groupID: nil,
                        permissions: nil,
                        accessTime: nil,
                        modificationTime: nil,
                        extensions: []
                    )
                )
            ),
            .name(
                SSHSFTPNameMessage(
                    requestID: survivingRequestID,
                    entries: [survivingEntry]
                )
            ),
        ]
    )

    let receivedEntry = try await survivingTask.value
    #expect(receivedEntry == survivingEntry)
}

@Test
func sshClientExpiresPublicSFTPFileHandleWithConnectionScope() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 82,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let channelSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let versionPayload = try makeSFTPChannelDataPayload(
        .version(
            SSHSFTPVersionMessage(
                version: 3,
                extensions: []
            )
        )
    )
    let fileHandle = SSHSFTPHandle(bytes: [0xde, 0xad, 0xbe, 0xef])
    let handlePayload = try makeSFTPChannelDataPayload(
        .handle(
            SSHSFTPHandleMessage(
                requestID: 0,
                handle: fileHandle
            )
        )
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            channelSuccessPayload,
            versionPayload,
            handlePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    var escapedHandle: SFTPFileHandle?
    try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let sftp = try await connection.openSFTP()
        escapedHandle = try await sftp.openFile("/tmp/example.txt")
    }

    let handle = try #require(escapedHandle)
    do {
        _ = try await handle.stat()
        Issue.record("Expected SFTP file handle wrapper scope to expire after withConnection returned")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
}

@Test
func sshClientOpensDirectTCPIPChannelAndExpiresWrapperScope() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 91,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("PONG".utf8)
            )
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            dataPayload,
            eofPayload,
            closePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    var escapedChannel: SSHDirectTCPIPChannel?
    let output: SSHDirectTCPIPChannelOutput = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let channel = try await connection.openDirectTCPIPChannel(
            targetHost: "db.internal",
            targetPort: 5432,
            originatorAddress: "127.0.0.1",
            originatorPort: 61001
        )
        escapedChannel = channel
        try await channel.write("PING")
        try await channel.sendEOF()
        return try await channel.collectDataUntilClose()
    }

    #expect(output.data == Array("PONG".utf8))
    #expect(output.didReceiveEOF)

    let channel = try #require(escapedChannel)
    do {
        _ = try await channel.readChunk()
        Issue.record("Expected direct-tcpip wrapper scope to expire after withConnection returned")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
}

@Test
func sshClientOpensDirectStreamLocalChannelAndExpiresWrapperScope() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 92,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("PONG".utf8)
            )
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            dataPayload,
            eofPayload,
            closePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    var escapedChannel: SSHDirectStreamLocalChannel?
    let output: SSHDirectStreamLocalChannelOutput = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let channel = try await connection.openDirectStreamLocalChannel(
            socketPath: "/run/postgresql/.s.PGSQL.5432",
            originatorAddress: "127.0.0.1",
            originatorPort: 61001
        )
        escapedChannel = channel
        try await channel.write("PING")
        try await channel.sendEOF()
        return try await channel.collectDataUntilClose()
    }

    #expect(output.data == Array("PONG".utf8))
    #expect(output.didReceiveEOF)

    let channel = try #require(escapedChannel)
    do {
        _ = try await channel.readChunk()
        Issue.record("Expected direct-streamlocal wrapper scope to expire after withConnection returned")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
}

@Test
func sshClientStreamsDirectTCPIPChannelEventsAndExpiresWrapperScope() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 91,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let dataPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("PONG".utf8)
            )
        )
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            dataPayload,
            eofPayload,
            closePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    var escapedChannel: SSHDirectTCPIPChannel?
    let events: [SSHTCPIPChannelEvent] = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let channel = try await connection.openDirectTCPIPChannel(
            targetHost: "db.internal",
            targetPort: 5432,
            originatorAddress: "127.0.0.1",
            originatorPort: 61001
        )
        escapedChannel = channel

        var streamedEvents: [SSHTCPIPChannelEvent] = []
        for try await event in channel.events {
            streamedEvents.append(event)
        }
        return streamedEvents
    }

    #expect(
        events == [
            .data(Array("PONG".utf8)),
            .endOfFile,
        ]
    )

    let channel = try #require(escapedChannel)
    do {
        _ = try await channel.nextEvent()
        Issue.record("Expected direct-tcpip wrapper scope to expire after withConnection returned")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
}

@Test
func sshClientDirectTCPIPEventSequenceCancellationBestEffortClosesChannel() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 55,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
        ],
        receiveDelayNanoseconds: 200_000_000
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let connection = try await SSHClient.connect(
        configuration: configuration,
        transportFactory: { _ in
            transport
        }
    )
    let channel = try await connection.openDirectTCPIPChannel(
        targetHost: "db.internal",
        targetPort: 5432,
        originatorAddress: "127.0.0.1",
        originatorPort: 61001
    )
    let baselineSentCount = await transport.sentPayloads().count

    let task = Task {
        for try await _ in channel.events {
        }
    }

    try? await Task.sleep(nanoseconds: 50_000_000)
    task.cancel()

    do {
        try await task.value
        Issue.record("Expected direct-tcpip event-sequence cancellation")
    } catch {
        #expect(error is CancellationError)
    }

    #expect(
        await waitForSentPayloadCount(
            on: transport,
            minimumCount: baselineSentCount + 1
        )
    )

    let sentPayloads = await transport.sentPayloads()
    let decryptionContext = try makeConnectionFixtureClientToServerDecryptionContext(
        sentPayloads: sentPayloads
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: decryptionContext.algorithms,
        keyMaterial: decryptionContext.keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(4).joined()))

    var packets: [SSHBinaryPacket] = []
    while let packet = try parser.nextPacket() {
        packets.append(packet)
    }

    let closePacket = try #require(packets.last)
    #expect(
        try SSHConnectionMessageParser().parse(closePacket.payload)
            == .channelClose(
                SSHChannelCloseMessage(recipientChannel: 55)
            )
    )

    await connection.close()
}

@Test
func sshClientStreamsShellEventsAndExpiresWrapperScope() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 73,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let stdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 0,
                data: Array("hello shell\n".utf8)
            )
        )
    )
    let stderrPayload = try SSHConnectionMessageSerializer().serialize(
        .channelExtendedData(
            SSHChannelExtendedDataMessage(
                recipientChannel: 0,
                dataTypeCode: SSHChannelExtendedDataMessage.standardErrorDataTypeCode,
                data: Array("warning shell\n".utf8)
            )
        )
    )
    let exitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 0, exitStatus: 7)
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 0))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 0))
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            ptySuccessPayload,
            shellSuccessPayload,
            stdoutPayload,
            stderrPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    var escapedSession: SSHSession?
    let events: [SSHSessionEvent] = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let session = try await connection.openShell()
        escapedSession = session

        var streamedEvents: [SSHSessionEvent] = []
        for try await event in session.events {
            streamedEvents.append(event)
        }
        return streamedEvents
    }

    #expect(
        events == [
            .standardOutput(Array("hello shell\n".utf8)),
            .standardError(Array("warning shell\n".utf8)),
            .exitStatus(7),
            .endOfFile,
        ]
    )

    let session = try #require(escapedSession)
    do {
        _ = try await session.nextEvent()
        Issue.record("Expected shell wrapper scope to expire after withConnection returned")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
}

@Test
func sshClientOpenShellSendsEnvironmentRequestsThroughPublicWrapper() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 73,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let environmentSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            environmentSuccessPayload,
            ptySuccessPayload,
            shellSuccessPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )
    let environmentVariable = SSHSessionEnvironmentVariable(
        name: "LANG",
        value: "en_US.UTF-8"
    )

    try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let session = try await connection.openShell(
            environment: [environmentVariable]
        )
        try await session.close()
    }

    let sentPayloads = await transport.sentPayloads()
    let decryptionContext = try makeConnectionFixtureClientToServerDecryptionContext(
        sentPayloads: sentPayloads
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: decryptionContext.algorithms,
        keyMaterial: decryptionContext.keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    parser.append(bytes: Array(sentPayloads.dropFirst(4).joined()))

    var channelRequests: [SSHChannelRequestMessage] = []
    while let packet = try parser.nextPacket() {
        guard packet.payload.first == SSHConnectionMessageID.channelRequest.rawValue else {
            continue
        }

        let message = try SSHConnectionMessageParser().parse(packet.payload)
        if case let .channelRequest(value) = message {
            channelRequests.append(value)
        }
    }

    #expect(channelRequests.count == 3)
    #expect(
        try SSHSessionRequestCoder().parseEnvironmentRequest(from: channelRequests[0])
            == environmentVariable
    )
    #expect(
        try SSHSessionRequestCoder().parsePseudoTerminalRequest(from: channelRequests[1])
            == .default
    )
    try SSHSessionRequestCoder().parseShellRequest(from: channelRequests[2])
}

@Test
func sshClientSharesConnectionAcrossShellExecAndSFTP() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let shellOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 70,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let execOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 1,
                senderChannel: 71,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let sftpOpenConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 2,
                senderChannel: 72,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let sftpSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 2))
    )
    let execSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 1))
    )
    let stdoutPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 1,
                data: Array("hostname\n".utf8)
            )
        )
    )
    let versionPacket = try SSHSFTPPacketSerializer().serialize(
        payload: SSHSFTPMessageSerializer().serialize(
            .version(
                SSHSFTPVersionMessage(
                    version: 3,
                    extensions: []
                )
            )
        )
    )
    let versionPayload = try SSHConnectionMessageSerializer().serialize(
        .channelData(
            SSHChannelDataMessage(
                recipientChannel: 2,
                data: versionPacket
            )
        )
    )
    let exitStatusPayload = try SSHConnectionMessageSerializer().serialize(
        SSHSessionRequestCoder().makeExitStatusRequest(recipientChannel: 1, exitStatus: 0)
    )
    let eofPayload = try SSHConnectionMessageSerializer().serialize(
        .channelEOF(SSHChannelEOFMessage(recipientChannel: 1))
    )
    let closePayload = try SSHConnectionMessageSerializer().serialize(
        .channelClose(SSHChannelCloseMessage(recipientChannel: 1))
    )
    let transport = ConnectionFixtureMockSSHByteStreamTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            shellOpenConfirmationPayload,
            ptySuccessPayload,
            shellSuccessPayload,
            execOpenConfirmationPayload,
            execSuccessPayload,
            sftpOpenConfirmationPayload,
            sftpSuccessPayload,
            stdoutPayload,
            versionPayload,
            exitStatusPayload,
            eofPayload,
            closePayload,
        ],
        receiveDelayNanoseconds: 50_000_000
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let summary = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let shell = try await connection.openShell()
        let execSession = try await connection.openExec("hostname")
        async let execResultTask = execSession.collectOutputUntilClose()
        let sftp = try await connection.openSFTP()
        let version = try await sftp.currentVersionExchange()
        let execResult = try await execResultTask

        try await shell.close()

        return (
            String(decoding: execResult.standardOutput, as: UTF8.self),
            version.serverVersion
        )
    }

    #expect(summary.0 == "hostname\n")
    #expect(summary.1 == 3)
}

@Test
func sshClientResizesPseudoTerminalThroughShellWrapper() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 73,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            ptySuccessPayload,
            shellSuccessPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    var escapedSession: SSHSession?
    try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let session = try await connection.openShell()
        escapedSession = session

        try await session.resizePseudoTerminal(
            characterWidth: 140,
            characterHeight: 45,
            pixelWidth: 1680,
            pixelHeight: 1050
        )
    }

    let session = try #require(escapedSession)
    do {
        try await session.resizePseudoTerminal(
            characterWidth: 80,
            characterHeight: 24
        )
        Issue.record("Expected shell resize API to expire after withConnection returned")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
}

@Test
func sshClientSendsSignalThroughShellWrapperAndExpiresWithConnection() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let authSuccessPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let openConfirmationPayload = try SSHConnectionMessageSerializer().serialize(
        .channelOpenConfirmation(
            SSHChannelOpenConfirmationMessage(
                recipientChannel: 0,
                senderChannel: 73,
                initialWindowSize: 1_048_576,
                maximumPacketSize: 32_768,
                channelTypeData: []
            )
        )
    )
    let ptySuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let shellSuccessPayload = try SSHConnectionMessageSerializer().serialize(
        .channelSuccess(SSHChannelSuccessMessage(recipientChannel: 0))
    )
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            authSuccessPayload,
            openConfirmationPayload,
            ptySuccessPayload,
            shellSuccessPayload,
        ]
    )
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: .password("s3cr3t"),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    var escapedSession: SSHSession?
    try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        let session = try await connection.openShell()
        escapedSession = session

        try await session.sendSignal(.terminate)
    }

    let session = try #require(escapedSession)
    do {
        try await session.sendSignal(.interrupt)
        Issue.record("Expected shell signal API to expire after withConnection returned")
    } catch {
        #expect(error as? SSHClientError == .connectionScopeEnded)
    }
}

private func makeNegotiatedDiagnosticsSnapshot(
    encryptionAlgorithmClientToServer: String,
    encryptionAlgorithmServerToClient: String,
    macAlgorithmClientToServer: String,
    macAlgorithmServerToClient: String
) -> SSHTransportProtocolDiagnosticsSnapshot {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: encryptionAlgorithmClientToServer,
        encryptionAlgorithmServerToClient: encryptionAlgorithmServerToClient,
        macAlgorithmClientToServer: macAlgorithmClientToServer,
        macAlgorithmServerToClient: macAlgorithmServerToClient,
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )

    return SSHTransportProtocolDiagnosticsSnapshot(
        phase: .authenticated,
        clientIdentification: "SSH-2.0-Traversio_Test",
        remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
        preIdentificationLines: [],
        keepaliveIntervalNanoseconds: 10_000_000_000,
        keepaliveReplyTimeoutNanoseconds: 10_000_000_000,
        responseTimeoutNanoseconds: nil,
        negotiatedAlgorithms: SSHTransportProtocolNegotiatedAlgorithmsSnapshot(
            algorithms: negotiatedAlgorithms,
            usesStrictKeyExchange: true
        ),
        didReceiveServerExtensionInfo: true,
        serverExtensionNames: ["server-sig-algs"],
        serverSignatureAlgorithms: ["ssh-ed25519", "rsa-sha2-512"],
        remoteDisconnect: nil,
        remoteDebugMessages: []
    )
}
