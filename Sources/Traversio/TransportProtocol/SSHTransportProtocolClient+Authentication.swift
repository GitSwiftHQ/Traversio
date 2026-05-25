// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

extension SSHTransportProtocolClient {
    package func discoverAuthenticationMethods(
        username: String,
        serviceName: String = "ssh-connection"
    ) async throws -> SSHAuthenticationMethodDiscoveryResult {
        try self.requireVersionExchange()

        guard self.outboundEncryptedPacketSerializer != nil,
              self.inboundEncryptedPacketParser != nil else {
            throw SSHUserAuthenticationError.confidentialTransportRequired
        }

        _ = try await self.requestService("ssh-userauth")
        try await self.sendUserAuthenticationMessage(
            .request(
                SSHUserAuthenticationRequestMessage(
                    username: username,
                    serviceName: serviceName,
                    method: .none
                )
            )
        )

        var banners: [SSHAuthenticationBanner] = []

        while true {
            try self.checkCancellation()
            let packet = try await self.receivePacket()
            if let transportMessage = try self.parseTransportMessageIfPossible(packet.payload) {
                if try await self.handleProtectedTransportMessage(transportMessage) {
                    continue
                }
                throw SSHUserAuthenticationError.unexpectedTransportMessage(
                    transportMessage.messageID
                )
            }

            if packet.payload.first == SSHUserAuthenticationMessageID.passwordChangeRequest.rawValue {
                throw SSHUserAuthenticationError.unexpectedAuthenticationMessage(
                    .passwordChangeRequest
                )
            }

            let message = try self.userAuthenticationMessageParser.parse(packet.payload)
            switch message {
            case let .banner(banner):
                banners.append(
                    SSHAuthenticationBanner(
                        message: banner.message,
                        languageTag: banner.languageTag
                    )
                )
            case .success:
                self.authenticatedServiceName = serviceName
                self.activateDelayedTransportCompressionIfNeeded()
                self.refreshIdleRekeySchedulingIfNeeded()
                self.refreshKeepaliveSchedulingIfNeeded()
                return SSHAuthenticationMethodDiscoveryResult(
                    username: username,
                    serviceName: serviceName,
                    availableMethods: [],
                    partialSuccess: false,
                    allowsUnauthenticatedAccess: true,
                    banners: banners
                )
            case let .failure(failure):
                return SSHAuthenticationMethodDiscoveryResult(
                    username: username,
                    serviceName: serviceName,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    allowsUnauthenticatedAccess: false,
                    banners: banners
                )
            case .request, .passwordChangeRequest:
                throw SSHUserAuthenticationError.unexpectedAuthenticationMessage(
                    message.messageID
                )
            }
        }
    }

    func requestService(_ serviceName: String) async throws -> SSHServiceAcceptMessage {
        try self.requireVersionExchange()

        if self.acceptedServices.contains(serviceName) {
            return SSHServiceAcceptMessage(serviceName: serviceName)
        }

        try await self.send(
            message: .serviceRequest(
                SSHServiceRequestMessage(serviceName: serviceName)
            )
        )

        while true {
            try self.checkCancellation()
            let message = try await self.receiveMessage()
            switch message {
            case .ignore, .debug, .extensionInfo:
                continue
            case let .keyExchangeInit(remoteProposal):
                try await self.completeRemoteKeyReexchange(remoteProposal: remoteProposal)
                continue
            case let .serviceAccept(accept):
                guard accept.serviceName == serviceName else {
                    throw SSHUserAuthenticationError.unexpectedServiceAccept(
                        expected: serviceName,
                        received: accept.serviceName
                    )
                }
                self.acceptedServices.insert(serviceName)
                return accept
            default:
                throw SSHTransportError.unexpectedTransportMessage(
                    expected: .serviceAccept,
                    received: message.messageID
                )
            }
        }
    }

    package func authenticatePassword(
        username: String,
        password: String,
        serviceName: String = "ssh-connection"
    ) async throws -> SSHPasswordAuthenticationResult {
        try await self.authenticatePassword(
            username: username,
            request: SSHPasswordAuthenticationRequest(password: password),
            serviceName: serviceName
        )
    }

    package func authenticatePasswordChange(
        username: String,
        oldPassword: String,
        newPassword: String,
        serviceName: String = "ssh-connection"
    ) async throws -> SSHPasswordAuthenticationResult {
        try await self.authenticatePassword(
            username: username,
            request: SSHPasswordAuthenticationRequest(
                oldPassword: oldPassword,
                newPassword: newPassword
            ),
            serviceName: serviceName
        )
    }

    private func authenticatePassword(
        username: String,
        request: SSHPasswordAuthenticationRequest,
        serviceName: String
    ) async throws -> SSHPasswordAuthenticationResult {
        try self.requireVersionExchange()

        guard self.outboundEncryptedPacketSerializer != nil,
              self.inboundEncryptedPacketParser != nil else {
            throw SSHUserAuthenticationError.confidentialTransportRequired
        }

        _ = try await self.requestService("ssh-userauth")
        try await self.sendUserAuthenticationMessage(
            .request(
                    SSHUserAuthenticationRequestMessage(
                        username: username,
                        serviceName: serviceName,
                        method: .password(request)
                    )
                )
            )

        var banners: [SSHUserAuthenticationBannerMessage] = []

        while true {
            try self.checkCancellation()
            let packet = try await self.receivePacket()
            if let transportMessage = try self.parseTransportMessageIfPossible(packet.payload) {
                if try await self.handleProtectedTransportMessage(transportMessage) {
                    continue
                }
                throw SSHUserAuthenticationError.unexpectedTransportMessage(
                    transportMessage.messageID
                )
            }

            if packet.payload.first == SSHUserAuthenticationMessageID.passwordChangeRequest.rawValue {
                return SSHPasswordAuthenticationResult(
                    username: username,
                    serviceName: serviceName,
                    banners: banners,
                    outcome: .passwordChangeRequired(
                        try self.userAuthenticationMessageParser.parsePasswordChangeRequest(
                            packet.payload
                        )
                    )
                )
            }

            let message = try self.userAuthenticationMessageParser.parse(packet.payload)
            switch message {
            case let .banner(banner):
                banners.append(banner)
            case let .success(success):
                self.authenticatedServiceName = serviceName
                self.activateDelayedTransportCompressionIfNeeded()
                self.refreshIdleRekeySchedulingIfNeeded()
                self.refreshKeepaliveSchedulingIfNeeded()
                return SSHPasswordAuthenticationResult(
                    username: username,
                    serviceName: serviceName,
                    banners: banners,
                    outcome: .success(success)
                )
            case let .failure(failure):
                return SSHPasswordAuthenticationResult(
                    username: username,
                    serviceName: serviceName,
                    banners: banners,
                    outcome: .failure(failure)
                )
            case let .passwordChangeRequest(changeRequest):
                return SSHPasswordAuthenticationResult(
                    username: username,
                    serviceName: serviceName,
                    banners: banners,
                    outcome: .passwordChangeRequired(changeRequest)
                )
            case .request:
                throw SSHUserAuthenticationError.unexpectedAuthenticationMessage(
                    message.messageID
                )
            }
        }
    }
    package func authenticatePublicKey(
        username: String,
        privateKey: any SSHPublicKeyAuthenticationPrivateKey,
        preferredAlgorithmNames: [String]? = nil,
        serviceName: String = "ssh-connection"
    ) async throws -> SSHPublicKeyAuthenticationResult {
        try await self.authenticatePublicKey(
            username: username,
            credential: SSHPublicKeyAuthenticationCredential(privateKey: privateKey),
            preferredAlgorithmNames: preferredAlgorithmNames,
            serviceName: serviceName
        )
    }

    package func authenticatePublicKey(
        username: String,
        algorithmNames: [String],
        publicKey: [UInt8],
        preferredAlgorithmNames: [String]? = nil,
        serviceName: String = "ssh-connection",
        signatureProvider: @escaping @Sendable (
            SSHPublicKeyAuthenticationSigningRequest
        ) async throws -> [UInt8]
    ) async throws -> SSHPublicKeyAuthenticationResult {
        try await self.authenticatePublicKey(
            username: username,
            credential: SSHPublicKeyAuthenticationCredential(
                algorithmNames: algorithmNames,
                publicKey: publicKey,
                signatureProvider: signatureProvider
            ),
            preferredAlgorithmNames: preferredAlgorithmNames,
            serviceName: serviceName
        )
    }

    private func authenticatePublicKey(
        username: String,
        credential: SSHPublicKeyAuthenticationCredential,
        preferredAlgorithmNames: [String]? = nil,
        serviceName: String = "ssh-connection"
    ) async throws -> SSHPublicKeyAuthenticationResult {
        try self.requireVersionExchange()

        guard self.outboundEncryptedPacketSerializer != nil,
              self.inboundEncryptedPacketParser != nil else {
            throw SSHUserAuthenticationError.confidentialTransportRequired
        }

        let sessionIdentifier = try self.requireSessionIdentifier()
        _ = try await self.requestService("ssh-userauth")

        let selectedAlgorithmName = self.selectPublicKeyAuthenticationAlgorithm(
            supportedAlgorithmNames: credential.supportedAlgorithmNames,
            preferredAlgorithmNames: preferredAlgorithmNames
        )
        let unsignedRequest = try credential.makeRequest(selectedAlgorithmName)
        try await self.sendUserAuthenticationMessage(
            .request(
                SSHUserAuthenticationRequestMessage(
                    username: username,
                    serviceName: serviceName,
                    method: .publicKey(unsignedRequest)
                )
            )
        )

        enum PublicKeyAuthenticationState {
            case awaitingConfirmation
            case awaitingResult
        }

        var banners: [SSHUserAuthenticationBannerMessage] = []
        var state = PublicKeyAuthenticationState.awaitingConfirmation

        while true {
            try self.checkCancellation()
            let packet = try await self.receivePacket()
            if let transportMessage = try self.parseTransportMessageIfPossible(packet.payload) {
                if try await self.handleProtectedTransportMessage(transportMessage) {
                    continue
                }
                throw SSHUserAuthenticationError.unexpectedTransportMessage(
                    transportMessage.messageID
                )
            }

            if packet.payload.first == SSHUserAuthenticationMessageID.passwordChangeRequest.rawValue {
                let publicKeyOK = try self.userAuthenticationMessageParser.parsePublicKeyOK(packet.payload)

                guard state == .awaitingConfirmation,
                      publicKeyOK.algorithmName == unsignedRequest.algorithmName,
                      publicKeyOK.publicKey == unsignedRequest.publicKey else {
                    throw SSHUserAuthenticationError.publicKeyConfirmationMismatch
                }

                let unsignedMessage = SSHUserAuthenticationRequestMessage(
                    username: username,
                    serviceName: serviceName,
                    method: .publicKey(unsignedRequest)
                )
                let signatureData = try unsignedMessage.publicKeySignatureData(
                    sessionIdentifier: sessionIdentifier
                )
                let signature = try await credential.sign(
                    SSHPublicKeyAuthenticationSigningRequest(
                        username: username,
                        serviceName: serviceName,
                        algorithmName: selectedAlgorithmName,
                        publicKey: unsignedRequest.publicKey,
                        signatureData: signatureData
                    )
                )
                try await self.sendUserAuthenticationMessage(
                    .request(
                        SSHUserAuthenticationRequestMessage(
                            username: username,
                            serviceName: serviceName,
                            method: .publicKey(unsignedRequest.withSignature(signature))
                        )
                    )
                )
                state = .awaitingResult
                continue
            }

            let message = try self.userAuthenticationMessageParser.parse(packet.payload)
            switch message {
            case let .banner(banner):
                banners.append(banner)
            case let .success(success):
                guard state == .awaitingResult else {
                    throw SSHUserAuthenticationError.unexpectedAuthenticationMessage(
                        message.messageID
                    )
                }
                self.authenticatedServiceName = serviceName
                self.activateDelayedTransportCompressionIfNeeded()
                self.refreshIdleRekeySchedulingIfNeeded()
                self.refreshKeepaliveSchedulingIfNeeded()
                return SSHPublicKeyAuthenticationResult(
                    username: username,
                    serviceName: serviceName,
                    algorithmName: selectedAlgorithmName,
                    banners: banners,
                    outcome: .success(success)
                )
            case let .failure(failure):
                return SSHPublicKeyAuthenticationResult(
                    username: username,
                    serviceName: serviceName,
                    algorithmName: selectedAlgorithmName,
                    banners: banners,
                    outcome: .failure(failure)
                )
            case .request, .passwordChangeRequest:
                throw SSHUserAuthenticationError.unexpectedAuthenticationMessage(
                    message.messageID
                )
            }
        }
    }

    package func authenticateKeyboardInteractive(
        username: String,
        submethods: [String] = [],
        serviceName: String = "ssh-connection",
        responseProvider: @escaping @Sendable (SSHKeyboardInteractiveChallenge) async throws -> [String]
    ) async throws -> SSHKeyboardInteractiveAuthenticationResult {
        try self.requireVersionExchange()

        guard self.outboundEncryptedPacketSerializer != nil,
              self.inboundEncryptedPacketParser != nil else {
            throw SSHUserAuthenticationError.confidentialTransportRequired
        }

        _ = try await self.requestService("ssh-userauth")
        try await self.sendUserAuthenticationMessage(
            .request(
                SSHUserAuthenticationRequestMessage(
                    username: username,
                    serviceName: serviceName,
                    method: .keyboardInteractive(
                        SSHKeyboardInteractiveAuthenticationRequest(
                            languageTag: "",
                            submethods: submethods
                        )
                    )
                )
            )
        )

        var banners: [SSHUserAuthenticationBannerMessage] = []

        while true {
            try self.checkCancellation()
            let packet = try await self.receivePacket()
            if let transportMessage = try self.parseTransportMessageIfPossible(packet.payload) {
                if try await self.handleProtectedTransportMessage(transportMessage) {
                    continue
                }
                throw SSHUserAuthenticationError.unexpectedTransportMessage(
                    transportMessage.messageID
                )
            }

            if packet.payload.first == SSHUserAuthenticationMessageID.passwordChangeRequest.rawValue {
                let infoRequest = try self.userAuthenticationMessageParser
                    .parseKeyboardInteractiveInfoRequest(packet.payload)
                let challenge = SSHKeyboardInteractiveChallenge(
                    username: username,
                    serviceName: serviceName,
                    name: infoRequest.name,
                    instruction: infoRequest.instruction,
                    languageTag: infoRequest.languageTag,
                    prompts: infoRequest.prompts.map {
                        SSHKeyboardInteractivePrompt(
                            prompt: $0.prompt,
                            shouldEcho: $0.shouldEcho
                        )
                    }
                )
                let responses = try await responseProvider(challenge)
                guard responses.count == infoRequest.prompts.count else {
                    throw SSHAuthenticationMethodError.invalidKeyboardInteractiveResponseCount(
                        expected: infoRequest.prompts.count,
                        received: responses.count
                    )
                }

                try await self.sendPayload(
                    self.userAuthenticationMessageSerializer.serializeKeyboardInteractiveInfoResponse(
                        SSHKeyboardInteractiveInformationResponseMessage(responses: responses)
                    )
                )
                continue
            }

            let message = try self.userAuthenticationMessageParser.parse(packet.payload)
            switch message {
            case let .banner(banner):
                banners.append(banner)
            case let .success(success):
                self.authenticatedServiceName = serviceName
                self.activateDelayedTransportCompressionIfNeeded()
                self.refreshIdleRekeySchedulingIfNeeded()
                self.refreshKeepaliveSchedulingIfNeeded()
                return SSHKeyboardInteractiveAuthenticationResult(
                    username: username,
                    serviceName: serviceName,
                    submethods: submethods,
                    banners: banners,
                    outcome: .success(success)
                )
            case let .failure(failure):
                return SSHKeyboardInteractiveAuthenticationResult(
                    username: username,
                    serviceName: serviceName,
                    submethods: submethods,
                    banners: banners,
                    outcome: .failure(failure)
                )
            case .request, .passwordChangeRequest:
                throw SSHUserAuthenticationError.unexpectedAuthenticationMessage(
                    message.messageID
                )
            }
        }
    }
}
