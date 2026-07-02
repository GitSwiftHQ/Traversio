// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Dispatch

extension SSHTransportProtocolClient {
    package func exchangeIdentifications() async throws -> SSHVersionExchange {
        if let versionExchange = self.versionExchange {
            return versionExchange
        }

        try self.checkCancellation()
        try await self.transport.send(self.clientIdentification.serializedBytes(), endOfStream: false)
        try self.checkCancellation()

        var preIdentificationLines: [String] = []

        while true {
            try self.checkCancellation()
            let chunk = try await self.transport.receive(atLeast: 1, atMost: self.maximumReadSize)
            try self.checkCancellation()
            self.identificationParser.append(bytes: chunk.bytes)

            while let event = try self.identificationParser.nextEvent() {
                switch event {
                case let .preIdentificationLine(line):
                    preIdentificationLines.append(line)
                case let .identification(remoteIdentification):
                    let bufferedPostIdentificationBytes =
                        self.identificationParser.takeBufferedBytes()
                    if !bufferedPostIdentificationBytes.isEmpty {
                        self.binaryPacketParser.append(bytes: bufferedPostIdentificationBytes)
                    }
                    let versionExchange = SSHVersionExchange(
                        clientIdentification: self.clientIdentification,
                        remoteIdentification: remoteIdentification,
                        preIdentificationLines: preIdentificationLines
                    )
                    self.versionExchange = versionExchange
                    return versionExchange
                }
            }

            if chunk.endOfStream {
                throw SSHTransportError.endOfStreamBeforeIdentification
            }
        }
    }

    func send(
        message: SSHTransportMessage,
        allowDuringTransportRekey: Bool = false
    ) async throws {
        try self.requireVersionExchange()

        let payload = try self.messageSerializer.serialize(message)
        try await self.sendPayload(
            payload,
            allowDuringTransportRekey: allowDuringTransportRekey
        )
    }

    func receiveMessage() async throws -> SSHTransportMessage {
        try self.requireVersionExchange()
        let packet = try await self.receivePacket()
        let message = try self.messageParser.parse(packet.payload)
        self.recordTransportMessageSideEffects(message)
        return message
    }

    func disconnect(
        reasonCode: SSHDisconnectReasonCode = .byApplication,
        description: String = "connection closed by client",
        languageTag: String = ""
    ) async {
        self.prepareForTransportLifecycleClose()
        guard self.versionExchange != nil else {
            return
        }

        do {
            let payload = try self.messageSerializer.serialize(
                .disconnect(
                    SSHDisconnectMessage(
                        reasonCode: reasonCode,
                        description: description,
                        languageTag: languageTag
                    )
                )
            )
            try await self.sendPayload(
                payload,
                endOfStream: false,
                respectCancellation: false,
                allowDuringTransportRekey: true
            )
        } catch {
            // Closing is best-effort. The caller has already invalidated the public lifetime.
        }

        self.cancelIdleRekeyTask()
        self.cancelKeepaliveTask()
    }

    func prepareForTransportLifecycleClose(
        preservePendingBackgroundFailure: Bool = true
    ) {
        self.backgroundFailureHandler = nil
        if !preservePendingBackgroundFailure {
            self.pendingBackgroundTransportFailure = nil
        }
        self.cancelIdleRekeyTask()
        self.cancelKeepaliveTask()
    }

    func abortTransportLifecycle() {
        self.prepareForTransportLifecycleClose(preservePendingBackgroundFailure: false)
    }

    package func disconnectForInternalValidation() async {
        await self.disconnect()
    }

    func beginCurve25519KeyExchange(
        negotiation explicitNegotiation: SSHKeyExchangeInitNegotiation? = nil
    ) async throws -> SSHCurve25519ClientKeyExchangeResult {
        try self.requireVersionExchange()

        let negotiation: SSHKeyExchangeInitNegotiation
        if let explicitNegotiation {
            negotiation = explicitNegotiation
        } else {
            negotiation = try await self.exchangeKeyExchangeInit()
        }
        let keyExchangeAlgorithm = negotiation.algorithms.keyExchangeAlgorithm
        let curve25519KeyExchange = SSHCurve25519KeyExchange()
        let clientKeyPair = try curve25519KeyExchange.generateKeyPair(
            keyExchangeAlgorithm: keyExchangeAlgorithm
        )
        let clientKeyExchangeInitPayload = try self.messageSerializer.serialize(
            .keyExchangeInit(negotiation.localProposal)
        )
        let serverKeyExchangeInitPayload = try self.messageSerializer.serialize(
            .keyExchangeInit(negotiation.remoteProposal)
        )

        try await self.send(
            message: .keyExchangeECDHInit(
                SSHKeyExchangeECDHInitMessage(publicKey: clientKeyPair.publicKey)
            ),
            allowDuringTransportRekey: true
        )

        if negotiation.shouldIgnoreNextPacketFromServer {
            _ = try await self.receivePacket()
        }

        while true {
            try self.checkCancellation()
            let message = try await self.receiveNextKeyExchangeTransportMessage()
            switch message {
            case .ignore, .debug:
                try self.validateStrictKeyExchangeMessage(
                    message,
                    negotiation: negotiation
                )
                continue
            case let .keyExchangeECDHReply(reply):
                return try curve25519KeyExchange.completeClientKeyExchange(
                    keyExchangeAlgorithm: keyExchangeAlgorithm,
                    clientIdentification: self.clientIdentification,
                    serverIdentification: try self.requireVersionExchangeValue().remoteIdentification,
                    clientKeyExchangeInitPayload: clientKeyExchangeInitPayload,
                    serverKeyExchangeInitPayload: serverKeyExchangeInitPayload,
                    clientKeyPair: clientKeyPair,
                    serverHostKey: reply.hostKey,
                    serverEphemeralPublicKey: reply.publicKey,
                    serverSignature: reply.signature
                )
            default:
                throw SSHTransportError.unexpectedTransportMessage(
                    expected: .keyExchangeECDHReply,
                    received: message.messageID
                )
            }
        }
    }

    func exchangeKeyExchangeInit(
        localProposal explicitLocalProposal: SSHKeyExchangeInitMessage? = nil
    ) async throws -> SSHKeyExchangeInitNegotiation {
        try self.requireVersionExchange()

        if explicitLocalProposal == nil,
           self.sessionIdentifier == nil,
           let negotiation = self.keyExchangeInitNegotiation {
            return negotiation
        }

        let localProposal = try explicitLocalProposal ?? self.keyExchangePreferences.makeKeyExchangeInitMessage()
        try await self.send(
            message: .keyExchangeInit(localProposal),
            allowDuringTransportRekey: true
        )

        while true {
            try self.checkCancellation()
            let message = try await self.receiveNextKeyExchangeTransportMessage()

            switch message {
            case .ignore, .debug, .extensionInfo:
                continue
            case let .keyExchangeInit(remoteProposal):
                let negotiation = try self.algorithmNegotiator.negotiate(
                    localProposal: localProposal,
                    remoteProposal: remoteProposal
                )
                try self.validateInitialStrictKeyExchangeOrdering(negotiation: negotiation)
                self.keyExchangeInitNegotiation = negotiation
                return negotiation
            default:
                throw SSHTransportError.unexpectedTransportMessage(
                    expected: .keyExchangeInit,
                    received: message.messageID
                )
            }
        }
    }
    func activateCurve25519Transport(
        negotiation: SSHKeyExchangeInitNegotiation,
        keyExchangeResult: SSHCurve25519ClientKeyExchangeResult,
        remoteEndpoint: SSHSocketEndpoint? = nil,
        hostKeyVerifier: SSHHostKeyVerifier = SSHHostKeyVerifier(),
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy,
        hostKeyTrustTimeoutNanoseconds: UInt64? = nil,
        keyDeriver: SSHTransportKeyDeriver = SSHTransportKeyDeriver()
    ) async throws -> SSHCurve25519TransportActivation {
        let evaluation = try await self.evaluateCurve25519HostKeyTrust(
            negotiation: negotiation,
            keyExchangeResult: keyExchangeResult,
            remoteEndpoint: remoteEndpoint,
            hostKeyVerifier: hostKeyVerifier,
            hostKeyTrustPolicy: hostKeyTrustPolicy,
            hostKeyTrustTimeoutNanoseconds: hostKeyTrustTimeoutNanoseconds
        )

        return try await self.activateTrustedCurve25519Transport(
            evaluation: evaluation,
            remoteEndpoint: remoteEndpoint,
            hostKeyVerifier: hostKeyVerifier,
            hostKeyTrustPolicy: hostKeyTrustPolicy,
            keyDeriver: keyDeriver
        )
    }

    func evaluateCurve25519HostKeyTrust(
        negotiation: SSHKeyExchangeInitNegotiation,
        keyExchangeResult: SSHCurve25519ClientKeyExchangeResult,
        remoteEndpoint: SSHSocketEndpoint? = nil,
        hostKeyVerifier: SSHHostKeyVerifier = SSHHostKeyVerifier(),
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy,
        hostKeyTrustTimeoutNanoseconds: UInt64? = nil
    ) async throws -> SSHCurve25519HostKeyTrustEvaluation {
        try self.requireVersionExchange()

        let verifiedHostKey = try keyExchangeResult.verifyServerHostKey(
            expectedHostKeyAlgorithm: negotiation.algorithms.serverHostKeyAlgorithm,
            verifier: hostKeyVerifier
        )
        let sessionIdentifier = self.sessionIdentifier ?? keyExchangeResult.sessionIdentifier
        let hostKeyTrust = try await withOptionalTimeout(
            nanoseconds: hostKeyTrustTimeoutNanoseconds,
            timeoutError: SSHTimeoutError.hostKeyTrust(
                durationNanoseconds: hostKeyTrustTimeoutNanoseconds ?? 1
            )
        ) {
            try await hostKeyTrustPolicy.evaluate(
                verifiedHostKey,
                context: SSHHostKeyValidationContext(
                    remoteEndpoint: remoteEndpoint,
                    remoteIdentification: try self.requireVersionExchangeValue().remoteIdentification
                )
            )
        }
        return SSHCurve25519HostKeyTrustEvaluation(
            negotiation: negotiation,
            keyExchangeResult: keyExchangeResult,
            verifiedHostKey: verifiedHostKey,
            hostKeyTrust: hostKeyTrust,
            sessionIdentifier: sessionIdentifier
        )
    }

    func activateTrustedCurve25519Transport(
        evaluation: SSHCurve25519HostKeyTrustEvaluation,
        remoteEndpoint: SSHSocketEndpoint? = nil,
        hostKeyVerifier: SSHHostKeyVerifier = SSHHostKeyVerifier(),
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy,
        keyDeriver: SSHTransportKeyDeriver = SSHTransportKeyDeriver()
    ) async throws -> SSHCurve25519TransportActivation {
        let negotiation = evaluation.negotiation
        let keyExchangeResult = evaluation.keyExchangeResult
        let sessionIdentifier = evaluation.sessionIdentifier
        let transportKeyMaterial = try keyExchangeResult.deriveTransportKeyMaterial(
            negotiatedAlgorithms: negotiation.algorithms,
            sessionIdentifier: sessionIdentifier,
            keyDeriver: keyDeriver
        )
        let shouldResetSequenceNumbersForNewKeys =
            self.strictKeyExchangeWasNegotiated || negotiation.usesStrictKeyExchange
        if negotiation.usesStrictKeyExchange, self.sessionIdentifier == nil {
            self.strictKeyExchangeWasNegotiated = true
        }

        try await self.send(
            message: .newKeys(SSHNewKeysMessage()),
            allowDuringTransportRekey: true
        )
        if shouldResetSequenceNumbersForNewKeys {
            self.outboundPacketSequenceNumber = 0
        }
        self.outboundEncryptedPacketSerializer = try SSHOutboundEncryptedPacketSerializer(
            negotiatedAlgorithms: negotiation.algorithms,
            keyMaterial: transportKeyMaterial,
            direction: .clientToServer,
            authenticationHasCompleted: self.authenticatedServiceName != nil,
            initialSequenceNumber: self.outboundPacketSequenceNumber
        )

        while true {
            try self.checkCancellation()
            let message = try await self.receiveNextKeyExchangeTransportMessage()
            switch message {
            case .ignore, .debug:
                try self.validateStrictKeyExchangeMessage(
                    message,
                    negotiation: negotiation
                )
                continue
            case .newKeys:
                if shouldResetSequenceNumbersForNewKeys {
                    self.inboundPacketSequenceNumber = 0
                }
                var encryptedPacketParser = try SSHInboundEncryptedPacketParser(
                    negotiatedAlgorithms: negotiation.algorithms,
                    keyMaterial: transportKeyMaterial,
                    direction: .serverToClient,
                    authenticationHasCompleted: self.authenticatedServiceName != nil,
                    initialSequenceNumber: self.inboundPacketSequenceNumber
                )
                if var existingEncryptedPacketParser = self.inboundEncryptedPacketParser {
                    encryptedPacketParser.append(bytes: existingEncryptedPacketParser.takeBufferedBytes())
                } else {
                    encryptedPacketParser.append(bytes: self.binaryPacketParser.takeBufferedBytes())
                }
                self.inboundEncryptedPacketParser = encryptedPacketParser
                self.sessionIdentifier = sessionIdentifier
                self.keyExchangeInitNegotiation = negotiation
                self.outboundEncryptedPacketCountSinceLastKeyExchange = 0
                self.inboundEncryptedPacketCountSinceLastKeyExchange = 0
                if self.authenticatedServiceName != nil {
                    self.noteProtectedTransportActivity()
                }
                self.transportRekeyHandler = { remoteProposal, client in
                    let localProposal = try client.keyExchangePreferences
                        .makeReexchangeKeyExchangeInitMessage()
                    let negotiation = try client.algorithmNegotiator.negotiate(
                        localProposal: localProposal,
                        remoteProposal: remoteProposal
                    )

                    try await client.send(
                        message: .keyExchangeInit(localProposal),
                        allowDuringTransportRekey: true
                    )
                    let keyExchangeResult = try await client.beginCurve25519KeyExchange(
                        negotiation: negotiation
                    )
                    _ = try await client.activateCurve25519Transport(
                        negotiation: negotiation,
                        keyExchangeResult: keyExchangeResult,
                        remoteEndpoint: remoteEndpoint,
                        hostKeyVerifier: hostKeyVerifier,
                        hostKeyTrustPolicy: hostKeyTrustPolicy,
                        keyDeriver: keyDeriver
                    )
                }
                self.localTransportRekeyHandler = { client in
                    let localProposal = try client.keyExchangePreferences
                        .makeReexchangeKeyExchangeInitMessage()
                    let negotiation = try await client.exchangeKeyExchangeInit(
                        localProposal: localProposal
                    )
                    let keyExchangeResult = try await client.beginCurve25519KeyExchange(
                        negotiation: negotiation
                    )
                    _ = try await client.activateCurve25519Transport(
                        negotiation: negotiation,
                        keyExchangeResult: keyExchangeResult,
                        remoteEndpoint: remoteEndpoint,
                        hostKeyVerifier: hostKeyVerifier,
                        hostKeyTrustPolicy: hostKeyTrustPolicy,
                        keyDeriver: keyDeriver
                    )
                }

                return SSHCurve25519TransportActivation(
                    negotiation: negotiation,
                    keyExchangeResult: keyExchangeResult,
                    verifiedHostKey: evaluation.verifiedHostKey,
                    hostKeyTrust: evaluation.hostKeyTrust,
                    transportKeyMaterial: transportKeyMaterial
                )
            default:
                throw SSHTransportError.unexpectedTransportMessage(
                    expected: .newKeys,
                    received: message.messageID
                )
            }
        }
    }
    package func completeCurve25519KeyExchange(
        negotiation explicitNegotiation: SSHKeyExchangeInitNegotiation? = nil,
        remoteEndpoint: SSHSocketEndpoint? = nil,
        hostKeyVerifier: SSHHostKeyVerifier = SSHHostKeyVerifier(),
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy,
        keyDeriver: SSHTransportKeyDeriver = SSHTransportKeyDeriver()
    ) async throws -> SSHCurve25519TransportActivation {
        let negotiation: SSHKeyExchangeInitNegotiation
        if let explicitNegotiation {
            negotiation = explicitNegotiation
        } else {
            negotiation = try await self.exchangeKeyExchangeInit()
        }

        let keyExchangeResult = try await self.beginCurve25519KeyExchange(
            negotiation: negotiation
        )
        return try await self.activateCurve25519Transport(
            negotiation: negotiation,
            keyExchangeResult: keyExchangeResult,
            remoteEndpoint: remoteEndpoint,
            hostKeyVerifier: hostKeyVerifier,
            hostKeyTrustPolicy: hostKeyTrustPolicy,
            keyDeriver: keyDeriver
        )
    }
    func completeRemoteKeyReexchange(
        remoteProposal: SSHKeyExchangeInitMessage
    ) async throws {
        guard let transportRekeyHandler else {
            throw SSHTransportError.unexpectedTransportMessage(
                expected: .serviceAccept,
                received: .keyExchangeInit
            )
        }

        try await self.withTransportRekeyInProgress {
            try await transportRekeyHandler(remoteProposal, self)
        }
        self.completedRemoteRekeyCount &+= 1
    }
    func completeLocalKeyReexchangeIfNeeded() async throws {
        try await self.completeLocalKeyReexchangeIfNeeded(forcedTrigger: nil)
    }
    func completeLocalKeyReexchangeIfNeeded(
        forcedTrigger: SSHTransportAutomaticRekeyTrigger?
    ) async throws {
        // OpenSSH's pre-auth state machine does not accept client-initiated KEXINIT
        // during ssh-userauth, so keep automatic local rekey on the send path until
        // the connection has completed authentication.
        guard self.authenticatedServiceName != nil,
              !self.isTransportRekeyInProgress,
              self.outboundEncryptedPacketSerializer != nil,
              self.inboundEncryptedPacketParser != nil,
              let localTransportRekeyHandler else {
            return
        }

        let trigger = forcedTrigger
            ?? self.mandatorySequenceNumberCeilingTrigger()
            ?? self.pendingIdleRekeyTrigger
            ?? self.automaticRekeyPolicy.nextTrigger(
                  outboundPacketCount: self.outboundEncryptedPacketCountSinceLastKeyExchange,
                  inboundPacketCount: self.inboundEncryptedPacketCountSinceLastKeyExchange,
                  idleNanosecondsSinceLastActivity: self.idleNanosecondsSinceLastProtectedActivity()
              )
        guard trigger != nil else {
            return
        }
        self.pendingIdleRekeyTrigger = nil

        try await self.withTransportRekeyInProgress {
            try await localTransportRekeyHandler(self)
        }
        self.completedLocalRekeyCount &+= 1
    }

    /// Returns `true` when the negotiated cipher (in either direction) derives its packet nonce
    /// solely from the 32-bit sequence number, and is therefore vulnerable to nonce/keystream
    /// reuse if the counter is allowed to wrap. Only `chacha20-poly1305@openssh.com` qualifies:
    /// AES-GCM uses an independent 64-bit invocation counter and AES-CTR a continuous cipher
    /// state, neither of which repeats when the sequence number wraps.
    func activeCipherUsesSequenceNumberNonce() -> Bool {
        guard let algorithms = self.keyExchangeInitNegotiation?.algorithms else {
            return false
        }

        return Self.encryptionAlgorithmUsesSequenceNumberNonce(
            algorithms.encryptionAlgorithmClientToServer
        ) || Self.encryptionAlgorithmUsesSequenceNumberNonce(
            algorithms.encryptionAlgorithmServerToClient
        )
    }

    static func encryptionAlgorithmUsesSequenceNumberNonce(_ algorithmName: String) -> Bool {
        algorithmName == "chacha20-poly1305@openssh.com"
    }

    /// A hard, non-disable-able rekey trigger returned once a sequence-number-nonce cipher has
    /// protected `sequenceNumberNonceRekeyCeiling` packets in either direction since the last key
    /// exchange. This is deliberately checked ahead of (and independently of) the configured
    /// automatic-rekey policy so that even a `.disabled` policy cannot let the 32-bit counter wrap
    /// and reuse a nonce. Returns `nil` for ciphers whose nonce does not depend on the sequence
    /// number.
    func mandatorySequenceNumberCeilingTrigger() -> SSHTransportAutomaticRekeyTrigger? {
        guard self.activeCipherUsesSequenceNumberNonce() else {
            return nil
        }

        let ceiling = SSHTransportAutomaticRekeyPolicy.sequenceNumberNonceRekeyCeiling
        let outboundCount = self.outboundEncryptedPacketCountSinceLastKeyExchange
        if outboundCount >= ceiling {
            return .mandatorySequenceNumberCeiling(currentCount: outboundCount, ceiling: ceiling)
        }

        let inboundCount = self.inboundEncryptedPacketCountSinceLastKeyExchange
        if inboundCount >= ceiling {
            return .mandatorySequenceNumberCeiling(currentCount: inboundCount, ceiling: ceiling)
        }

        return nil
    }

    /// Backstop for the sequence-number-nonce ceiling: if the ceiling has been reached but a rekey
    /// cannot be initiated (no local rekey handler, not yet authenticated, or serializers missing),
    /// refuse to protect another packet rather than silently reuse a nonce. When a rekey *is*
    /// possible this returns without throwing and `completeLocalKeyReexchangeIfNeeded` forces the
    /// rekey via `mandatorySequenceNumberCeilingTrigger()`.
    func enforceSequenceNumberNonceCeilingClosedIfUnableToRekey() throws {
        guard let trigger = self.mandatorySequenceNumberCeilingTrigger(),
              case let .mandatorySequenceNumberCeiling(currentCount, ceiling) = trigger else {
            return
        }

        let canRekey = self.authenticatedServiceName != nil
            && !self.isTransportRekeyInProgress
            && self.outboundEncryptedPacketSerializer != nil
            && self.inboundEncryptedPacketParser != nil
            && self.localTransportRekeyHandler != nil
        if canRekey {
            return
        }

        throw SSHTransportSequenceNumberNonceError.ceilingReachedWithoutRekey(
            currentCount: currentCount,
            ceiling: ceiling
        )
    }

    // Test seam: primes the since-last-key-exchange packet counters so a test can drive the
    // sequence-number-nonce ceiling without actually pushing 2^31 packets through the transport.
    func primeEncryptedPacketCountsSinceLastKeyExchange(outbound: UInt64, inbound: UInt64) {
        self.outboundEncryptedPacketCountSinceLastKeyExchange = outbound
        self.inboundEncryptedPacketCountSinceLastKeyExchange = inbound
    }

    func receivePacket(
        respectingTransportReceiveCancellation: Bool = true
    ) async throws -> SSHBinaryPacket {
        try await self.acquireInboundPacketReceiveTurn(
            respectCancellation: respectingTransportReceiveCancellation
        )
        do {
            let packet = try await self.receivePacketWhileHoldingGate(
                respectingTransportReceiveCancellation: respectingTransportReceiveCancellation
            )
            self.releaseInboundPacketReceiveTurn()
            return packet
        } catch {
            self.releaseInboundPacketReceiveTurn()
            throw error
        }
    }

    func receivePacketWhileHoldingGate(
        respectingTransportReceiveCancellation: Bool
    ) async throws -> SSHBinaryPacket {
        while true {
            try self.throwPendingBackgroundTransportFailureIfNeeded()
            if respectingTransportReceiveCancellation {
                try self.checkCancellation()
            }
            if let packet = try self.binaryPacketParser.nextPacket() {
                self.inboundPacketSequenceNumber &+= 1
                return packet
            }

            if var encryptedPacketParser = self.inboundEncryptedPacketParser {
                let packet = try encryptedPacketParser.nextPacket()
                self.inboundEncryptedPacketParser = encryptedPacketParser
                if let packet {
                    self.inboundPacketSequenceNumber &+= 1
                    if !self.isTransportRekeyInProgress {
                        self.inboundEncryptedPacketCountSinceLastKeyExchange &+= 1
                        self.noteProtectedTransportActivity()
                    }
                    return packet
                }
            }

            let chunk = try await self.receiveTransportChunk(
                atLeast: 1,
                atMost: self.maximumReadSize,
                respectCancellation: respectingTransportReceiveCancellation
            )
            if var encryptedPacketParser = self.inboundEncryptedPacketParser {
                encryptedPacketParser.append(bytes: chunk.bytes)
                let packet = try encryptedPacketParser.nextPacket()
                self.inboundEncryptedPacketParser = encryptedPacketParser

                if let packet {
                    self.inboundPacketSequenceNumber &+= 1
                    if !self.isTransportRekeyInProgress {
                        self.inboundEncryptedPacketCountSinceLastKeyExchange &+= 1
                        self.noteProtectedTransportActivity()
                    }
                    return packet
                }
            } else {
                self.binaryPacketParser.append(bytes: chunk.bytes)

                if let packet = try self.binaryPacketParser.nextPacket() {
                    self.inboundPacketSequenceNumber &+= 1
                    return packet
                }
            }

            if chunk.endOfStream {
                if respectingTransportReceiveCancellation && Task.isCancelled {
                    throw CancellationError()
                }
                throw SSHTransportError.endOfStreamBeforePacket
            }
        }
    }

    func sendUserAuthenticationMessage(
        _ message: SSHUserAuthenticationMessage
    ) async throws {
        let payload = try self.userAuthenticationMessageSerializer.serialize(message)
        try await self.sendPayload(payload)
    }

    func sendConnectionMessage(
        _ message: SSHConnectionMessage,
        respectCancellation: Bool = true,
        respectTransportSendCancellation: Bool? = nil
    ) async throws {
        let payload = try self.connectionMessageSerializer.serialize(message)
        try await self.sendPayload(
            payload,
            respectCancellation: respectCancellation,
            respectTransportSendCancellation: respectTransportSendCancellation
        )
    }

    func sendPayload(
        _ payload: [UInt8],
        endOfStream: Bool = false,
        respectCancellation: Bool = true,
        respectTransportSendCancellation: Bool? = nil,
        allowDuringTransportRekey: Bool = false
    ) async throws {
        while true {
            if !allowDuringTransportRekey {
                try await self.prepareProtectedSend(
                    respectCancellation: respectCancellation
                )
            }
            if respectCancellation {
                try self.checkCancellation()
            }
            try await self.acquireOutboundPacketSendTurn(
                respectCancellation: respectCancellation
            )
            do {
                if !allowDuringTransportRekey {
                    try self.throwPendingBackgroundTransportFailureIfNeeded()
                    if self.isTransportRekeyInProgress {
                        self.releaseOutboundPacketSendTurn()
                        continue
                    }
                }
                if respectCancellation {
                    try self.checkCancellation()
                }
                let packetBytes: [UInt8]
                if var encryptedPacketSerializer = self.outboundEncryptedPacketSerializer {
                    packetBytes = try encryptedPacketSerializer.serialize(payload: payload)
                    self.outboundEncryptedPacketSerializer = encryptedPacketSerializer
                } else {
                    packetBytes = try self.packetSerializer.serialize(payload: payload)
                }
                try await self.sendTransportBytes(
                    packetBytes,
                    endOfStream: endOfStream,
                    respectCancellation: respectTransportSendCancellation ?? respectCancellation
                )
                self.outboundPacketSequenceNumber &+= 1
                if self.outboundEncryptedPacketSerializer != nil && !self.isTransportRekeyInProgress {
                    self.outboundEncryptedPacketCountSinceLastKeyExchange &+= 1
                    self.noteProtectedTransportActivity()
                }
                self.releaseOutboundPacketSendTurn()
                return
            } catch {
                self.releaseOutboundPacketSendTurn()
                throw error
            }
        }
    }

    private func sendTransportBytes(
        _ bytes: [UInt8],
        endOfStream: Bool,
        respectCancellation: Bool
    ) async throws {
        if let transport = self.transport as? any SSHCancellationControllingByteStreamTransport {
            try await transport.send(
                bytes,
                endOfStream: endOfStream,
                respectCancellation: respectCancellation
            )
            return
        }

        try await self.transport.send(bytes, endOfStream: endOfStream)
    }

    private func receiveTransportChunk(
        atLeast minimum: Int,
        atMost maximum: Int,
        respectCancellation: Bool
    ) async throws -> SSHByteStreamChunk {
        if let transport = self.transport as? any SSHCancellationControllingByteStreamTransport {
            return try await transport.receive(
                atLeast: minimum,
                atMost: maximum,
                respectCancellation: respectCancellation
            )
        }

        return try await self.transport.receive(atLeast: minimum, atMost: maximum)
    }

    package func prepareProtectedSend(respectCancellation: Bool = true) async throws {
        try await self.prepareProtectedTransportActivity(
            respectCancellation: respectCancellation
        )
    }

    package func prepareProtectedReceive(respectCancellation: Bool = true) async throws {
        try await self.prepareProtectedTransportActivity(
            respectCancellation: respectCancellation
        )
    }

    func prepareProtectedTransportActivity(respectCancellation: Bool = true) async throws {
        try self.throwPendingBackgroundTransportFailureIfNeeded()
        try await self.waitForTransportRekeyToComplete(
            respectCancellation: respectCancellation
        )
        try self.throwPendingBackgroundTransportFailureIfNeeded()
        try self.enforceSequenceNumberNonceCeilingClosedIfUnableToRekey()
        try await self.completeLocalKeyReexchangeIfNeeded()
        try await self.waitForTransportRekeyToComplete(
            respectCancellation: respectCancellation
        )
        try self.throwPendingBackgroundTransportFailureIfNeeded()
    }

    func parseTransportMessageIfPossible(
        _ payload: [UInt8]
    ) throws -> SSHTransportMessage? {
        guard let messageID = payload.first,
              SSHTransportMessageID(rawValue: messageID) != nil else {
            return nil
        }

        let message = try self.messageParser.parse(payload)
        self.recordTransportMessageSideEffects(message)
        return message
    }

    func recordTransportMessageSideEffects(_ message: SSHTransportMessage) {
        switch message {
        case let .disconnect(disconnect):
            self.lastDisconnectMessage = disconnect
        case let .debug(debug):
            self.recordedDebugMessages.append(debug)
            if self.recordedDebugMessages.count > Self.maximumRecordedDebugMessages {
                self.recordedDebugMessages.removeFirst(
                    self.recordedDebugMessages.count - Self.maximumRecordedDebugMessages
                )
            }
        case let .extensionInfo(extensionInfo):
            self.didReceiveServerExtensionInfo = true
            for entry in extensionInfo.entries {
                self.serverExtensions[entry.name] = entry.value
            }
        default:
            break
        }
    }

    func handleProtectedTransportMessage(
        _ message: SSHTransportMessage
    ) async throws -> Bool {
        switch message {
        case .ignore, .debug, .extensionInfo:
            return true
        case let .keyExchangeInit(remoteProposal):
            try await self.completeRemoteKeyReexchange(remoteProposal: remoteProposal)
            return true
        default:
            return false
        }
    }

    func activateDelayedTransportCompressionIfNeeded() {
        if var serializer = self.outboundEncryptedPacketSerializer {
            serializer.activateDelayedCompressionIfNeeded()
            self.outboundEncryptedPacketSerializer = serializer
        }

        if var parser = self.inboundEncryptedPacketParser {
            parser.activateDelayedCompressionIfNeeded()
            self.inboundEncryptedPacketParser = parser
        }
    }

    package func serverExtensionValue(named name: String) -> [UInt8]? {
        self.serverExtensions[name]
    }

    package func diagnosticsSnapshot() -> SSHTransportProtocolDiagnosticsSnapshot {
        SSHTransportProtocolDiagnosticsSnapshot(
            phase: self.currentSetupPhase(),
            clientIdentification: self.clientIdentification.rawValue,
            remoteIdentification: self.versionExchange?.remoteIdentification.rawValue,
            preIdentificationLines: self.versionExchange?.preIdentificationLines ?? [],
            keepaliveIntervalNanoseconds: self.keepalivePolicy.intervalNanoseconds,
            keepaliveReplyTimeoutNanoseconds: self.keepalivePolicy.responseTimeoutNanoseconds,
            responseTimeoutNanoseconds: self.responseTimeoutNanoseconds,
            negotiatedAlgorithms: self.keyExchangeInitNegotiation.map {
                SSHTransportProtocolNegotiatedAlgorithmsSnapshot(
                    algorithms: $0.algorithms,
                    usesStrictKeyExchange: self.strictKeyExchangeWasNegotiated
                        || $0.usesStrictKeyExchange
                )
            },
            didReceiveServerExtensionInfo: self.didReceiveServerExtensionInfo,
            serverExtensionNames: self.serverExtensions.keys.sorted(),
            serverSignatureAlgorithms: self.serverSignatureAlgorithms(),
            remoteDisconnect: self.lastDisconnectMessage.map {
                SSHTransportProtocolRemoteDisconnectSnapshot(message: $0)
            },
            remoteDebugMessages: self.recordedDebugMessages.map {
                SSHTransportProtocolRemoteDebugSnapshot(message: $0)
            }
        )
    }

    package func rekeyMetricsSnapshot() -> SSHTransportProtocolRekeyMetricsSnapshot {
        SSHTransportProtocolRekeyMetricsSnapshot(
            completedRemoteRekeyCount: self.completedRemoteRekeyCount,
            completedLocalRekeyCount: self.completedLocalRekeyCount,
            outboundEncryptedPacketCountSinceLastKeyExchange:
                self.outboundEncryptedPacketCountSinceLastKeyExchange,
            inboundEncryptedPacketCountSinceLastKeyExchange:
                self.inboundEncryptedPacketCountSinceLastKeyExchange,
            isTransportRekeyInProgress: self.isTransportRekeyInProgress
        )
    }

    package func runtimeStateSnapshot() -> SSHTransportProtocolRuntimeStateSnapshot {
        SSHTransportProtocolRuntimeStateSnapshot(
            setupPhase: self.currentSetupPhase(),
            managedSessionCount: self.managedSessionStates.count,
            pendingManagedSessionCount: self.pendingManagedSessionLocalChannelIDs.count,
            pendingChannelOpenResponseCount: self.pendingChannelOpenResponses.count,
            pendingChannelRequestReplyCount: self.pendingChannelRequestReplies.count,
            pendingPreManagedSessionMessageCount: self.pendingPreManagedSessionMessages.count,
            pendingGlobalRequestReplyCount: self.pendingGlobalRequestReplies.count,
            deferredConnectionMessageCount: self.deferredConnectionMessagesDuringTransportRekey.count,
            pendingConnectionMessageAfterTransportRekeyCount:
                self.pendingConnectionMessagesAfterTransportRekey.count,
            activeConnectionMessageWaiterCount: self.activeConnectionMessageWaiterCount,
            activeGlobalRequestReplyWaiterCount: self.activeGlobalRequestReplyWaiterCount,
            inboundPacketReceiveTurnWaiterCount: self.inboundPacketReceiveTurnWaiters.count,
            outboundPacketSendWaiterCount: self.outboundPacketSendWaiters.count,
            connectionMessageWaiterProgressWaiterCount:
                self.connectionMessageWaiterProgressWaiters.count,
            transportRekeyWaiterCount: self.transportRekeyWaiters.count,
            isReceivingInboundPacket: self.isReceivingInboundPacket,
            isSendingOutboundPacket: self.isSendingOutboundPacket,
            isTransportRekeyInProgress: self.isTransportRekeyInProgress
        )
    }

    package func compressionActivationSnapshot() -> (outbound: Bool, inbound: Bool) {
        (
            outbound: self.outboundEncryptedPacketSerializer?.isCompressionActive ?? false,
            inbound: self.inboundEncryptedPacketParser?.isCompressionActive ?? false
        )
    }

    func selectPublicKeyAuthenticationAlgorithm(
        for privateKey: any SSHPublicKeyAuthenticationPrivateKey,
        preferredAlgorithmNames: [String]? = nil
    ) -> String {
        self.selectPublicKeyAuthenticationAlgorithm(
            supportedAlgorithmNames: privateKey.supportedAlgorithmNames,
            preferredAlgorithmNames: preferredAlgorithmNames
        )
    }

    func selectPublicKeyAuthenticationAlgorithm(
        supportedAlgorithmNames: [String],
        preferredAlgorithmNames: [String]? = nil
    ) -> String {
        let supportedAlgorithms = supportedAlgorithmNames
        let candidateAlgorithms: [String]
        if let preferredAlgorithmNames {
            candidateAlgorithms = preferredAlgorithmNames.filter { supportedAlgorithms.contains($0) }
        } else {
            candidateAlgorithms = supportedAlgorithms
        }

        precondition(!candidateAlgorithms.isEmpty)

        guard candidateAlgorithms.count > 1,
              let rawServerSignatureAlgorithms = self.serverExtensions["server-sig-algs"],
              let serverSignatureAlgorithms = String(
                  bytes: rawServerSignatureAlgorithms,
                  encoding: .utf8
              )?.split(separator: ",").map(String.init) else {
            return candidateAlgorithms[0]
        }

        for algorithm in candidateAlgorithms where serverSignatureAlgorithms.contains(algorithm) {
            return algorithm
        }

        return candidateAlgorithms[0]
    }

    func currentSetupPhase() -> SSHTransportProtocolSetupPhase {
        if self.authenticatedServiceName != nil {
            return .authenticated
        }

        if self.sessionIdentifier != nil ||
            self.outboundEncryptedPacketSerializer != nil ||
            self.inboundEncryptedPacketParser != nil {
            return .authentication
        }

        if self.versionExchange != nil {
            return .keyExchange
        }

        return .identification
    }

    func idleNanosecondsSinceLastProtectedActivity(
        nowNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> UInt64? {
        guard let lastProtectedTransportActivityNanoseconds else {
            return nil
        }

        return nowNanoseconds >= lastProtectedTransportActivityNanoseconds
            ? nowNanoseconds - lastProtectedTransportActivityNanoseconds
            : 0
    }

    func noteProtectedTransportActivity(
        nowNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) {
        self.lastProtectedTransportActivityNanoseconds = nowNanoseconds
        self.pendingIdleRekeyTrigger = nil
        self.refreshIdleRekeySchedulingIfNeeded()
        self.refreshKeepaliveSchedulingIfNeeded()
    }
    // Ensures a single long-lived idle-rekey timer task is running. Idempotent and cheap: while a
    // timer is already scheduled this returns immediately, so the hot per-packet activity path does
    // not cancel and re-spawn a task per packet. The running timer reschedules itself against the
    // stored "last activity" timestamp.
    func refreshIdleRekeySchedulingIfNeeded() {
        guard self.authenticatedServiceName != nil,
              self.outboundEncryptedPacketSerializer != nil,
              self.inboundEncryptedPacketParser != nil,
              !self.isTransportRekeyInProgress,
              self.automaticRekeyPolicy.idleTimeIntervalNanoseconds != nil,
              self.idleRekeyTaskHandle == nil else {
            return
        }

        self.startIdleRekeyTimerTask()
    }

    private func startIdleRekeyTimerTask() {
        self.idleRekeyTaskGeneration &+= 1
        self.idleRekeyTimerScheduleCount &+= 1
        let generation = self.idleRekeyTaskGeneration
        let client = self
        let task = Task { [weak client] in
            await client?.runIdleRekeyTimerLoop(expectedGeneration: generation)
        }
        self.idleRekeyTaskHandle = SSHCancellationHandle(cancelOperation: {
            task.cancel()
        })
    }

    private func runIdleRekeyTimerLoop(expectedGeneration: UInt64) async {
        while expectedGeneration == self.idleRekeyTaskGeneration {
            guard let idleTimeIntervalNanoseconds =
                    self.automaticRekeyPolicy.idleTimeIntervalNanoseconds else {
                break
            }

            let remainingNanoseconds = self.nanosecondsUntilIdleRekeyDeadline(
                idleTimeIntervalNanoseconds: idleTimeIntervalNanoseconds
            )
            if remainingNanoseconds > 0 {
                do {
                    try await Task.sleep(nanoseconds: remainingNanoseconds)
                } catch {
                    return
                }
                continue
            }

            switch await self.handleIdleRekeyDeadlineReached(expectedGeneration: expectedGeneration) {
            case .reschedule:
                // Activity raced in just before the deadline; loop to sleep out the new deadline.
                continue
            case .stop:
                // Either the rekey fired (which cancels this timer via `withTransportRekeyInProgress`
                // and bumps the generation) or the trigger was deferred to the send path.
                return
            }
        }

        if expectedGeneration == self.idleRekeyTaskGeneration {
            self.idleRekeyTaskHandle = nil
        }
    }

    func nanosecondsUntilIdleRekeyDeadline(idleTimeIntervalNanoseconds: UInt64) -> UInt64 {
        guard let idleNanoseconds = self.idleNanosecondsSinceLastProtectedActivity() else {
            return idleTimeIntervalNanoseconds
        }

        return idleNanoseconds >= idleTimeIntervalNanoseconds
            ? 0
            : idleTimeIntervalNanoseconds - idleNanoseconds
    }

    private enum SSHIdleRekeyDeadlineOutcome {
        case reschedule
        case stop
    }

    private func handleIdleRekeyDeadlineReached(
        expectedGeneration: UInt64
    ) async -> SSHIdleRekeyDeadlineOutcome {
        guard expectedGeneration == self.idleRekeyTaskGeneration else {
            return .stop
        }

        guard let trigger = self.automaticRekeyPolicy.nextTrigger(
            outboundPacketCount: self.outboundEncryptedPacketCountSinceLastKeyExchange,
            inboundPacketCount: self.inboundEncryptedPacketCountSinceLastKeyExchange,
            idleNanosecondsSinceLastActivity: self.idleNanosecondsSinceLastProtectedActivity()
        ) else {
            // No trigger is due — protected activity moved the deadline forward. Keep the same timer
            // running and let it sleep out the new deadline.
            return .reschedule
        }

        guard case .idleTimeInterval = trigger else {
            return .stop
        }

        if self.isTransportRekeyInProgress ||
            self.isReceivingInboundPacket ||
            self.activeConnectionMessageWaiterCount > 0 {
            self.pendingIdleRekeyTrigger = trigger
            return .stop
        }

        // Detach the handle before rekeying so the `cancelIdleRekeyTask()` inside
        // `withTransportRekeyInProgress` does not cancel this still-running timer task.
        self.idleRekeyTaskHandle = nil
        do {
            try await self.completeLocalKeyReexchangeIfNeeded(forcedTrigger: trigger)
        } catch is CancellationError {
            return .stop
        } catch {
            self.recordPendingBackgroundTransportFailure(error)
        }
        return .stop
    }

    func cancelIdleRekeyTask() {
        self.idleRekeyTaskHandle?.cancel()
        self.idleRekeyTaskHandle = nil
        self.idleRekeyTaskGeneration &+= 1
    }

    func validateInitialStrictKeyExchangeOrdering(
        negotiation: SSHKeyExchangeInitNegotiation
    ) throws {
        guard negotiation.usesStrictKeyExchange,
              self.sessionIdentifier == nil,
              self.inboundPacketSequenceNumber != 1 else {
            return
        }

        throw SSHTransportError.strictKeyExchangeViolation(
            "The server's SSH_MSG_KEXINIT was not the first packet after identification."
        )
    }

    func validateStrictKeyExchangeMessage(
        _ message: SSHTransportMessage,
        negotiation: SSHKeyExchangeInitNegotiation
    ) throws {
        guard negotiation.usesStrictKeyExchange,
              self.sessionIdentifier == nil else {
            return
        }

        throw SSHTransportError.strictKeyExchangeViolation(
            "Received \(message.messageID) during the initial strict key exchange."
        )
    }

    func serverSignatureAlgorithms() -> [String]? {
        guard let rawValue = self.serverExtensions["server-sig-algs"],
              let stringValue = String(bytes: rawValue, encoding: .utf8) else {
            return nil
        }

        return stringValue.split(separator: ",").map(String.init)
    }

    func parseConnectionMessageIfPossible(
        _ payload: [UInt8]
    ) throws -> SSHConnectionMessage? {
        guard let messageID = payload.first,
              SSHConnectionMessageID(rawValue: messageID) != nil else {
            return nil
        }

        return try self.connectionMessageParser.parse(payload)
    }

    func receiveNextKeyExchangeTransportMessage() async throws -> SSHTransportMessage {
        while true {
            try self.checkCancellation()
            let packet = try await self.receivePacket()

            if let transportMessage = try self.parseTransportMessageIfPossible(packet.payload) {
                return transportMessage
            }

            if self.authenticatedServiceName != nil,
               let connectionMessage = try self.parseConnectionMessageIfPossible(packet.payload) {
                self.deferredConnectionMessagesDuringTransportRekey.append(connectionMessage)
                continue
            }

            throw SSHWireError.unknownMessageType(packet.payload[0])
        }
    }

    func requireSessionIdentifier() throws -> [UInt8] {
        guard let sessionIdentifier = self.sessionIdentifier else {
            throw SSHUserAuthenticationError.sessionIdentifierRequired
        }

        return sessionIdentifier
    }

    func requireVersionExchange() throws {
        guard self.versionExchange != nil else {
            throw SSHTransportError.versionExchangeRequired
        }
    }

    func acquireInboundPacketReceiveTurn(
        respectCancellation: Bool = true
    ) async throws {
        guard self.isReceivingInboundPacket else {
            self.isReceivingInboundPacket = true
            return
        }

        switch await self.waitOnInboundPacketReceiveTurnWaiterQueue(
            respectCancellation: respectCancellation
        ) {
        case .ready:
            if respectCancellation && Task.isCancelled {
                self.releaseInboundPacketReceiveTurn()
                throw CancellationError()
            }
        case .cancelled:
            throw CancellationError()
        }
    }

    func acquireOutboundPacketSendTurn(
        respectCancellation: Bool = true
    ) async throws {
        guard !self.isSendingOutboundPacket else {
            switch await self.waitOnOutboundPacketSendWaiterQueue(
                respectCancellation: respectCancellation
            ) {
            case .ready:
                if respectCancellation && Task.isCancelled {
                    self.releaseOutboundPacketSendTurn()
                    throw CancellationError()
                }
            case .cancelled:
                throw CancellationError()
            }
            return
        }

        self.isSendingOutboundPacket = true
    }

    func releaseInboundPacketReceiveTurn() {
        if self.resumeNextInboundPacketReceiveTurnWaiterReady() {
            return
        }

        self.isReceivingInboundPacket = false
    }

    func releaseOutboundPacketSendTurn() {
        if self.resumeNextOutboundPacketSendWaiterReady() {
            return
        }

        self.isSendingOutboundPacket = false
    }

    func withConnectionMessageWaiterTurn<Result>(
        _ operation: () async throws -> Result
    ) async throws -> Result {
        self.activeConnectionMessageWaiterCount += 1
        defer {
            self.activeConnectionMessageWaiterCount -= 1
            if self.activeConnectionMessageWaiterCount == 0 {
                self.resumeAllConnectionMessageWaiterProgressWaitersReady()
            }
        }

        return try await operation()
    }

    func waitForConnectionMessageWaiterProgress(
        respectCancellation: Bool = true
    ) async throws {
        guard self.activeConnectionMessageWaiterCount > 0 else {
            return
        }

        switch await self.waitOnConnectionMessageWaiterProgressQueue(
            respectCancellation: respectCancellation
        ) {
        case .ready:
            if respectCancellation {
                try self.checkCancellation()
            }
        case .cancelled:
            throw CancellationError()
        }
    }

    func waitForTransportRekeyToComplete(
        respectCancellation: Bool = true
    ) async throws {
        while self.isTransportRekeyInProgress {
            switch await self.waitOnTransportRekeyWaiterQueue(
                respectCancellation: respectCancellation
            ) {
            case .ready:
                if respectCancellation {
                    try self.checkCancellation()
                }
            case .cancelled:
                throw CancellationError()
            }
        }
    }

    func withTransportRekeyInProgress<Result>(
        _ operation: () async throws -> Result
    ) async throws -> Result {
        self.cancelIdleRekeyTask()
        self.cancelKeepaliveTask()
        self.isTransportRekeyInProgress = true

        do {
            let result = try await operation()
            self.isTransportRekeyInProgress = false
            try await self.flushDeferredConnectionMessagesAfterTransportRekey()
            self.resumeAllTransportRekeyWaitersReady()
            return result
        } catch {
            self.isTransportRekeyInProgress = false
            self.resumeAllTransportRekeyWaitersReady()
            self.deferredConnectionMessagesDuringTransportRekey.removeAll(keepingCapacity: true)
            throw error
        }
    }

    func waitOnInboundPacketReceiveTurnWaiterQueue(
        respectCancellation: Bool = true
    ) async -> SSHActorWaiterResume {
        let waiterID = self.allocateActorWaiterID()
        let client = self

        guard respectCancellation else {
            return await withCheckedContinuation { continuation in
                self.inboundPacketReceiveTurnWaiters.install(
                    waiterID: waiterID,
                    continuation: continuation
                )
            }
        }

        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                self.inboundPacketReceiveTurnWaiters.install(
                    waiterID: waiterID,
                    continuation: continuation
                )
            }
        } onCancel: {
            Task {
                await client.cancelInboundPacketReceiveTurnWaiter(waiterID: waiterID)
            }
        }
    }

    func waitOnOutboundPacketSendWaiterQueue(
        respectCancellation: Bool = true
    ) async -> SSHActorWaiterResume {
        let waiterID = self.allocateActorWaiterID()
        let client = self

        guard respectCancellation else {
            return await withCheckedContinuation { continuation in
                self.outboundPacketSendWaiters.install(
                    waiterID: waiterID,
                    continuation: continuation
                )
            }
        }

        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                self.outboundPacketSendWaiters.install(
                    waiterID: waiterID,
                    continuation: continuation
                )
            }
        } onCancel: {
            Task {
                await client.cancelOutboundPacketSendWaiter(waiterID: waiterID)
            }
        }
    }

    func allocateActorWaiterID() -> SSHActorWaiterQueue.WaiterID {
        let waiterID = self.nextActorWaiterID
        self.nextActorWaiterID &+= 1
        return waiterID
    }

    func cancelInboundPacketReceiveTurnWaiter(
        waiterID: SSHActorWaiterQueue.WaiterID
    ) {
        guard let continuation = self.inboundPacketReceiveTurnWaiters.remove(waiterID: waiterID)
        else {
            return
        }

        continuation.resume(returning: SSHActorWaiterResume.cancelled)
    }

    func cancelOutboundPacketSendWaiter(
        waiterID: SSHActorWaiterQueue.WaiterID
    ) {
        guard let continuation = self.outboundPacketSendWaiters.remove(waiterID: waiterID)
        else {
            return
        }

        continuation.resume(returning: SSHActorWaiterResume.cancelled)
    }

    func resumeNextInboundPacketReceiveTurnWaiterReady() -> Bool {
        guard let continuation = self.inboundPacketReceiveTurnWaiters.popNext() else {
            return false
        }

        continuation.resume(returning: SSHActorWaiterResume.ready)
        return true
    }

    func resumeNextOutboundPacketSendWaiterReady() -> Bool {
        guard let continuation = self.outboundPacketSendWaiters.popNext() else {
            return false
        }

        continuation.resume(returning: SSHActorWaiterResume.ready)
        return true
    }

    func waitOnConnectionMessageWaiterProgressQueue(
        respectCancellation: Bool = true
    ) async -> SSHActorWaiterResume {
        let waiterID = self.allocateActorWaiterID()
        let client = self

        guard respectCancellation else {
            return await withCheckedContinuation { continuation in
                self.connectionMessageWaiterProgressWaiters.install(
                    waiterID: waiterID,
                    continuation: continuation
                )
            }
        }

        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                self.connectionMessageWaiterProgressWaiters.install(
                    waiterID: waiterID,
                    continuation: continuation
                )
            }
        } onCancel: {
            Task {
                await client.cancelConnectionMessageWaiterProgressWaiter(waiterID: waiterID)
            }
        }
    }

    func cancelConnectionMessageWaiterProgressWaiter(
        waiterID: SSHActorWaiterQueue.WaiterID
    ) {
        guard let continuation = self.connectionMessageWaiterProgressWaiters.remove(
            waiterID: waiterID
        ) else {
            return
        }

        continuation.resume(returning: SSHActorWaiterResume.cancelled)
    }

    func resumeAllConnectionMessageWaiterProgressWaitersReady() {
        let continuations = self.connectionMessageWaiterProgressWaiters.popAll()
        for continuation in continuations {
            continuation.resume(returning: SSHActorWaiterResume.ready)
        }
    }

    func waitOnTransportRekeyWaiterQueue(
        respectCancellation: Bool = true
    ) async -> SSHActorWaiterResume {
        let waiterID = self.allocateActorWaiterID()
        let client = self

        guard respectCancellation else {
            return await withCheckedContinuation { continuation in
                self.transportRekeyWaiters.install(
                    waiterID: waiterID,
                    continuation: continuation
                )
            }
        }

        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                self.transportRekeyWaiters.install(
                    waiterID: waiterID,
                    continuation: continuation
                )
            }
        } onCancel: {
            Task {
                await client.cancelTransportRekeyWaiter(waiterID: waiterID)
            }
        }
    }

    func cancelTransportRekeyWaiter(
        waiterID: SSHActorWaiterQueue.WaiterID
    ) {
        guard let continuation = self.transportRekeyWaiters.remove(waiterID: waiterID) else {
            return
        }

        continuation.resume(returning: SSHActorWaiterResume.cancelled)
    }

    func resumeAllTransportRekeyWaitersReady() {
        let continuations = self.transportRekeyWaiters.popAll()
        for continuation in continuations {
            continuation.resume(returning: SSHActorWaiterResume.ready)
        }
    }

    func waitOnOutboundGlobalRequestWaiterQueue() async -> SSHActorWaiterResume {
        let waiterID = self.allocateActorWaiterID()
        let client = self

        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                self.outboundGlobalRequestWaiters.install(
                    waiterID: waiterID,
                    continuation: continuation
                )
            }
        } onCancel: {
            Task {
                await client.cancelOutboundGlobalRequestWaiter(waiterID: waiterID)
            }
        }
    }

    func cancelOutboundGlobalRequestWaiter(
        waiterID: SSHActorWaiterQueue.WaiterID
    ) {
        guard let continuation = self.outboundGlobalRequestWaiters.remove(waiterID: waiterID)
        else {
            return
        }

        continuation.resume(returning: SSHActorWaiterResume.cancelled)
    }

    func resumeNextOutboundGlobalRequestWaiterReady() -> Bool {
        guard let continuation = self.outboundGlobalRequestWaiters.popNext() else {
            return false
        }

        continuation.resume(returning: SSHActorWaiterResume.ready)
        return true
    }

    func requireAuthenticatedConnectionService() throws {
        guard self.authenticatedServiceName == "ssh-connection" else {
            throw SSHConnectionError.authenticatedConnectionRequired
        }
    }

    func requireVersionExchangeValue() throws -> SSHVersionExchange {
        guard let versionExchange = self.versionExchange else {
            throw SSHTransportError.versionExchangeRequired
        }

        return versionExchange
    }

    func checkCancellation() throws {
        try Task.checkCancellation()
    }

    func throwPendingBackgroundTransportFailureIfNeeded() throws {
        guard let pendingBackgroundTransportFailure else {
            return
        }

        self.pendingBackgroundTransportFailure = nil
        throw pendingBackgroundTransportFailure
    }

    func hasPendingBackgroundTransportFailure() -> Bool {
        self.pendingBackgroundTransportFailure != nil
    }

    func setBackgroundFailureHandler(
        _ handler: (@Sendable (any Error & Sendable) async -> Void)?
    ) {
        self.backgroundFailureHandler = handler
    }

    func hasBackgroundFailureHandler() -> Bool {
        self.backgroundFailureHandler != nil
    }

    func recordPendingBackgroundTransportFailure(
        _ error: any Error & Sendable
    ) {
        let shouldNotify = self.pendingBackgroundTransportFailure == nil
        self.pendingBackgroundTransportFailure = error

        guard shouldNotify,
              let backgroundFailureHandler = self.backgroundFailureHandler else {
            return
        }

        Task {
            await backgroundFailureHandler(error)
        }
    }

    func forwardingFallbackKeepalivePolicy() -> SSHTransportKeepalivePolicy? {
        guard self.keepalivePolicy.intervalNanoseconds == nil else {
            return nil
        }

        let intervalNanoseconds = min(
            self.responseTimeoutNanoseconds
                ?? Self.defaultForwardingFallbackKeepaliveIntervalNanoseconds,
            Self.defaultForwardingFallbackKeepaliveIntervalNanoseconds
        )
        let responseTimeoutNanoseconds = min(
            self.responseTimeoutNanoseconds ?? intervalNanoseconds,
            intervalNanoseconds
        )

        return SSHTransportKeepalivePolicy(
            intervalNanoseconds: intervalNanoseconds,
            responseTimeoutNanoseconds: responseTimeoutNanoseconds
        )
    }
}
package struct SSHCurve25519TransportActivation: Equatable, Sendable {
    package let negotiation: SSHKeyExchangeInitNegotiation
    package let keyExchangeResult: SSHCurve25519ClientKeyExchangeResult
    package let verifiedHostKey: SSHVerifiedHostKey
    package let hostKeyTrust: SSHHostKeyTrust
    package let transportKeyMaterial: SSHTransportKeyMaterial

    package var negotiatedAlgorithmsSnapshot: SSHTransportProtocolNegotiatedAlgorithmsSnapshot {
        SSHTransportProtocolNegotiatedAlgorithmsSnapshot(
            algorithms: self.negotiation.algorithms,
            usesStrictKeyExchange: self.negotiation.usesStrictKeyExchange
        )
    }
}

package struct SSHCurve25519HostKeyTrustEvaluation: Equatable, Sendable {
    package let negotiation: SSHKeyExchangeInitNegotiation
    package let keyExchangeResult: SSHCurve25519ClientKeyExchangeResult
    package let verifiedHostKey: SSHVerifiedHostKey
    package let hostKeyTrust: SSHHostKeyTrust
    package let sessionIdentifier: [UInt8]
}

struct SSHCancellationHandle: Sendable {
    let cancelOperation: @Sendable () -> Void

    func cancel() {
        self.cancelOperation()
    }
}

/// Raised when a sequence-number-nonce cipher (chacha20-poly1305) has protected as many packets as
/// the hard `sequenceNumberNonceRekeyCeiling` allows but the connection is unable to rekey. The
/// connection is failed closed rather than reusing a nonce/keystream.
package enum SSHTransportSequenceNumberNonceError: Error, Equatable, Sendable {
    case ceilingReachedWithoutRekey(currentCount: UInt64, ceiling: UInt64)
}
