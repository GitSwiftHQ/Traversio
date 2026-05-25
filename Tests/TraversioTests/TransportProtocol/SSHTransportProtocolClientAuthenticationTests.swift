// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation
import Security
import Testing
@testable import Traversio

actor KeyboardInteractiveChallengeRecorder {
    private var challenges: [SSHKeyboardInteractiveChallenge] = []

    func record(_ challenge: SSHKeyboardInteractiveChallenge) {
        self.challenges.append(challenge)
    }

    func recordedChallenges() -> [SSHKeyboardInteractiveChallenge] {
        self.challenges
    }
}

actor PublicKeySigningRequestRecorder {
    private var requests: [SSHPublicKeyAuthenticationSigningRequest] = []

    func record(_ request: SSHPublicKeyAuthenticationSigningRequest) {
        self.requests.append(request)
    }

    func recordedRequests() -> [SSHPublicKeyAuthenticationSigningRequest] {
        self.requests
    }
}

@Test
func transportAutomaticRekeyPolicyMapsPublicPolicyThresholds() {
    let internalPolicy = SSHTransportAutomaticRekeyPolicy(
        SSHAutomaticRekeyPolicy(
            outboundPacketThreshold: 7,
            inboundPacketThreshold: nil,
            idleTimeInterval: 0.25
        )
    )

    #expect(internalPolicy.outboundPacketThreshold == 7)
    #expect(internalPolicy.inboundPacketThreshold == nil)
    #expect(internalPolicy.idleTimeIntervalNanoseconds == 250_000_000)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientAuthenticatesPasswordAfterEncryptedActivation() async throws {
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
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            bannerPayload,
            successPayload,
        ]
    )

    let result = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    #expect(
        result
            == SSHPasswordAuthenticationResult(
                username: "root",
                serviceName: "ssh-connection",
                banners: [
                    SSHUserAuthenticationBannerMessage(
                        message: "Authorized use only",
                        languageTag: "en-US"
                    )
                ],
                outcome: .success(SSHUserAuthenticationSuccessMessage())
            )
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2] + sentPayloads[3])
    let serviceRequestPacket = try #require(try parser.nextPacket())
    let passwordRequestPacket = try #require(try parser.nextPacket())

    #expect(sentPayloads.count == 4)
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
                    method: .password(SSHPasswordAuthenticationRequest(password: "s3cr3t"))
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientDefersAutomaticLocalRekeyUntilAfterAuthentication() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            successPayload,
        ],
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy(
            outboundPacketThreshold: 1,
            inboundPacketThreshold: nil,
            idleTimeIntervalNanoseconds: nil
        )
    )

    let result = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let rekeyMetrics = await fixture.client.rekeyMetricsSnapshot()

    #expect(
        result.outcome
            == SSHPasswordAuthenticationOutcome.success(SSHUserAuthenticationSuccessMessage())
    )
    #expect(rekeyMetrics.completedLocalRekeyCount == 0)

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2] + sentPayloads[3])
    let serviceRequestPacket = try #require(try parser.nextPacket())
    let passwordRequestPacket = try #require(try parser.nextPacket())

    #expect(sentPayloads.count == 4)
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
                    method: .password(SSHPasswordAuthenticationRequest(password: "s3cr3t"))
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientActivatesDelayedCompressionAfterAuthenticationSuccess() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            successPayload,
        ],
        compressionAlgorithmClientToServer: "zlib@openssh.com",
        compressionAlgorithmServerToClient: "zlib@openssh.com"
    )
    let beforeAuthenticationCompression = await fixture.client.compressionActivationSnapshot()

    #expect(beforeAuthenticationCompression.outbound == false)
    #expect(beforeAuthenticationCompression.inbound == false)

    _ = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let afterAuthenticationCompression = await fixture.client.compressionActivationSnapshot()

    #expect(afterAuthenticationCompression.outbound == true)
    #expect(afterAuthenticationCompression.inbound == true)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientStartsAutomaticLocalRekeyBeforeFirstPostAuthenticationSend() async throws {
    let transport = ServiceRequestRekeyMockSSHByteStreamTransport(
        rekeyMode: .clientInitiatedAfterAuthentication,
        strictKeyExchange: true
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test"),
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy(
            outboundPacketThreshold: 1,
            inboundPacketThreshold: nil,
            idleTimeIntervalNanoseconds: nil
        )
    )

    _ = try await client.exchangeIdentifications()
    _ = try await client.completeCurve25519KeyExchange(
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey
    )
    let authentication = try await client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    try await client.prepareProtectedSend()

    let rekeyClientProposal = try #require(await transport.rekeyClientProposal())
    let rekeyMetrics = await client.rekeyMetricsSnapshot()

    #expect(
        authentication.outcome
            == SSHPasswordAuthenticationOutcome.success(SSHUserAuthenticationSuccessMessage())
    )
    #expect(!rekeyClientProposal.keyExchangeAlgorithms.contains("ext-info-c"))
    #expect(!rekeyClientProposal.keyExchangeAlgorithms.contains("kex-strict-c-v00@openssh.com"))
    #expect(rekeyMetrics.completedLocalRekeyCount == 1)
    #expect(rekeyMetrics.completedRemoteRekeyCount == 0)
    #expect(rekeyMetrics.outboundEncryptedPacketCountSinceLastKeyExchange == 0)
    #expect(rekeyMetrics.inboundEncryptedPacketCountSinceLastKeyExchange == 0)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientStartsAutomaticLocalRekeyBeforeFirstPostAuthenticationReceiveWait() async throws {
    let transport = ServiceRequestRekeyMockSSHByteStreamTransport(
        rekeyMode: .clientInitiatedAfterAuthentication,
        strictKeyExchange: true
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test"),
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy(
            outboundPacketThreshold: nil,
            inboundPacketThreshold: 1,
            idleTimeIntervalNanoseconds: nil
        )
    )

    _ = try await client.exchangeIdentifications()
    _ = try await client.completeCurve25519KeyExchange(
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey
    )
    let authentication = try await client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    try await client.prepareProtectedReceive()

    let rekeyClientProposal = try #require(await transport.rekeyClientProposal())
    let rekeyMetrics = await client.rekeyMetricsSnapshot()

    #expect(
        authentication.outcome
            == SSHPasswordAuthenticationOutcome.success(SSHUserAuthenticationSuccessMessage())
    )
    #expect(!rekeyClientProposal.keyExchangeAlgorithms.contains("ext-info-c"))
    #expect(!rekeyClientProposal.keyExchangeAlgorithms.contains("kex-strict-c-v00@openssh.com"))
    #expect(rekeyMetrics.completedLocalRekeyCount == 1)
    #expect(rekeyMetrics.completedRemoteRekeyCount == 0)
    #expect(rekeyMetrics.outboundEncryptedPacketCountSinceLastKeyExchange == 0)
    #expect(rekeyMetrics.inboundEncryptedPacketCountSinceLastKeyExchange == 0)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientStartsAutomaticLocalRekeyAfterAuthenticationIdleInterval() async throws {
    let transport = ServiceRequestRekeyMockSSHByteStreamTransport(
        rekeyMode: .clientInitiatedAfterAuthentication,
        strictKeyExchange: true
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test"),
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy(
            outboundPacketThreshold: nil,
            inboundPacketThreshold: nil,
            idleTimeIntervalNanoseconds: 100_000_000
        )
    )

    _ = try await client.exchangeIdentifications()
    _ = try await client.completeCurve25519KeyExchange(
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey
    )
    let authentication = try await client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )
    let rekeyClientProposal = try #require(
        await waitForRekeyClientProposal(on: transport)
    )
    let rekeyMetrics = try #require(
        await waitForCompletedLocalRekeyMetrics(on: client)
    )

    #expect(
        authentication.outcome
            == SSHPasswordAuthenticationOutcome.success(SSHUserAuthenticationSuccessMessage())
    )
    #expect(!rekeyClientProposal.keyExchangeAlgorithms.contains("ext-info-c"))
    #expect(!rekeyClientProposal.keyExchangeAlgorithms.contains("kex-strict-c-v00@openssh.com"))
    #expect(rekeyMetrics.completedLocalRekeyCount == 1)
    #expect(rekeyMetrics.completedRemoteRekeyCount == 0)
    #expect(rekeyMetrics.outboundEncryptedPacketCountSinceLastKeyExchange == 0)
    #expect(rekeyMetrics.inboundEncryptedPacketCountSinceLastKeyExchange == 0)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientResetsIdleAutomaticRekeyTimerAfterProtectedActivity() async throws {
    let transport = ServiceRequestRekeyMockSSHByteStreamTransport(
        rekeyMode: .clientInitiatedAfterAuthentication,
        strictKeyExchange: true
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test"),
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy(
            outboundPacketThreshold: nil,
            inboundPacketThreshold: nil,
            idleTimeIntervalNanoseconds: 500_000_000
        )
    )

    _ = try await client.exchangeIdentifications()
    _ = try await client.completeCurve25519KeyExchange(
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey
    )
    let authentication = try await client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    try? await Task.sleep(nanoseconds: 100_000_000)
    await client.noteProtectedTransportActivity()

    try? await Task.sleep(nanoseconds: 150_000_000)
    #expect(await transport.rekeyClientProposal() == nil)

    let rekeyClientProposal = try #require(
        await waitForRekeyClientProposal(on: transport)
    )
    let rekeyMetrics = try #require(
        await waitForCompletedLocalRekeyMetrics(on: client)
    )

    #expect(
        authentication.outcome
            == SSHPasswordAuthenticationOutcome.success(SSHUserAuthenticationSuccessMessage())
    )
    #expect(!rekeyClientProposal.keyExchangeAlgorithms.contains("ext-info-c"))
    #expect(!rekeyClientProposal.keyExchangeAlgorithms.contains("kex-strict-c-v00@openssh.com"))
    #expect(rekeyMetrics.completedLocalRekeyCount == 1)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCancelsIdleAutomaticRekeyWhenDisconnected() async throws {
    let transport = ServiceRequestRekeyMockSSHByteStreamTransport(
        rekeyMode: .clientInitiatedAfterAuthentication,
        strictKeyExchange: true
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test"),
        automaticRekeyPolicy: SSHTransportAutomaticRekeyPolicy(
            outboundPacketThreshold: nil,
            inboundPacketThreshold: nil,
            idleTimeIntervalNanoseconds: 100_000_000
        )
    )

    _ = try await client.exchangeIdentifications()
    _ = try await client.completeCurve25519KeyExchange(
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey
    )
    let authentication = try await client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    await client.disconnect()
    try? await Task.sleep(nanoseconds: 200_000_000)

    #expect(
        authentication.outcome
            == SSHPasswordAuthenticationOutcome.success(SSHUserAuthenticationSuccessMessage())
    )
    #expect(await transport.rekeyClientProposal() == nil)
    let rekeyMetrics = await client.rekeyMetricsSnapshot()
    #expect(rekeyMetrics.completedLocalRekeyCount == 0)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientStoresServerSignatureAlgorithmsFromExtensionInfo() async throws {
    let extensionInfoPayload = try SSHTransportMessageSerializer().serialize(
        .extensionInfo(
            SSHExtensionInfoMessage(
                entries: [
                    SSHExtensionInfoEntry(
                        name: "server-sig-algs",
                        value: Array("rsa-sha2-512,rsa-sha2-256".utf8)
                    )
                ]
            )
        )
    )
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            extensionInfoPayload,
            serviceAcceptPayload,
        ]
    )

    _ = try await fixture.client.requestService("ssh-userauth")
    let serverSignatureAlgorithms = await fixture.client.serverExtensionValue(
        named: "server-sig-algs"
    )

    #expect(
        serverSignatureAlgorithms == Array("rsa-sha2-512,rsa-sha2-256".utf8)
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientAuthenticatesEd25519PublicKeyAfterEncryptedActivation() async throws {
    let privateKey = try SSHEd25519PrivateKey(rawRepresentation: Array(0x01...0x20))
    let unsignedRequest = try privateKey.makeRequest(algorithmName: "ssh-ed25519")
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let bannerPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .banner(
            SSHUserAuthenticationBannerMessage(
                message: "Public key accepted",
                languageTag: "en-US"
            )
        )
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
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            bannerPayload,
            publicKeyOKPayload,
            successPayload,
        ]
    )

    let result = try await fixture.client.authenticatePublicKey(
        username: "root",
        privateKey: privateKey
    )

    #expect(
        result
            == SSHPublicKeyAuthenticationResult(
                username: "root",
                serviceName: "ssh-connection",
                algorithmName: "ssh-ed25519",
                banners: [
                    SSHUserAuthenticationBannerMessage(
                        message: "Public key accepted",
                        languageTag: "en-US"
                    )
                ],
                outcome: .success(SSHUserAuthenticationSuccessMessage())
            )
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4])
    let serviceRequestPacket = try #require(try parser.nextPacket())
    let unsignedPublicKeyRequestPacket = try #require(try parser.nextPacket())
    let signedPublicKeyRequestPacket = try #require(try parser.nextPacket())

    #expect(sentPayloads.count == 5)
    #expect(
        try SSHTransportMessageParser().parse(serviceRequestPacket.payload)
            == .serviceRequest(
                SSHServiceRequestMessage(serviceName: "ssh-userauth")
            )
    )
    let unsignedParsedMessage = try SSHUserAuthenticationMessageParser().parse(
        unsignedPublicKeyRequestPacket.payload
    )
    let unsignedRequestMessage = try #require({
        if case let .request(message) = unsignedParsedMessage {
            return message
        }
        return nil
    }())
    let unsignedPublicKeyRequest = try #require({
        if case let .publicKey(request) = unsignedRequestMessage.method {
            return request
        }
        return nil
    }())
    let signedParsedMessage = try SSHUserAuthenticationMessageParser().parse(
        signedPublicKeyRequestPacket.payload
    )
    let requestMessage = try #require({
        if case let .request(message) = signedParsedMessage {
            return message
        }
        return nil
    }())
    let publicKeyRequest = try #require({
        if case let .publicKey(request) = requestMessage.method {
            return request
        }
        return nil
    }())
    let signatureBlob = try #require(publicKeyRequest.signature)
    var signatureReader = SSHWireReader(bytes: signatureBlob)
    let signatureAlgorithm = try signatureReader.readUTF8String()
    let rawSignature = try signatureReader.readString()
    #expect(signatureReader.isAtEnd)

    var publicKeyReader = SSHWireReader(bytes: unsignedRequest.publicKey)
    let publicKeyAlgorithm = try publicKeyReader.readUTF8String()
    let rawPublicKey = try publicKeyReader.readString()
    #expect(publicKeyReader.isAtEnd)

    let signatureData = try requestMessage.publicKeySignatureData(
        sessionIdentifier: fixture.activation.keyExchangeResult.sessionIdentifier
    )
    let cryptoPublicKey = try Curve25519.Signing.PublicKey(
        rawRepresentation: Data(rawPublicKey)
    )

    #expect(requestMessage.username == "root")
    #expect(requestMessage.serviceName == "ssh-connection")
    #expect(unsignedRequestMessage.username == "root")
    #expect(unsignedRequestMessage.serviceName == "ssh-connection")
    #expect(unsignedPublicKeyRequest.algorithmName == unsignedRequest.algorithmName)
    #expect(unsignedPublicKeyRequest.publicKey == unsignedRequest.publicKey)
    #expect(unsignedPublicKeyRequest.signature == nil)
    #expect(publicKeyRequest.algorithmName == unsignedRequest.algorithmName)
    #expect(publicKeyRequest.publicKey == unsignedRequest.publicKey)
    #expect(signatureAlgorithm == "ssh-ed25519")
    #expect(publicKeyAlgorithm == "ssh-ed25519")
    #expect(rawSignature.count == 64)
    #expect(
        cryptoPublicKey.isValidSignature(
            Data(rawSignature),
            for: Data(signatureData)
        )
    )
}

@Test
func transportProtocolClientAuthenticatesPublicKeyWithSignatureProvider() async throws {
    let seed: [UInt8] = Array(0x01...0x20)
    let privateKey = try SSHEd25519PrivateKey(rawRepresentation: seed)
    let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed))
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
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            publicKeyOKPayload,
            successPayload,
        ]
    )
    let recorder = PublicKeySigningRequestRecorder()

    let result = try await fixture.client.authenticatePublicKey(
        username: "root",
        algorithmNames: ["ssh-ed25519"],
        publicKey: unsignedRequest.publicKey,
        signatureProvider: { request in
            await recorder.record(request)
            let rawSignature = try signingKey.signature(for: Data(request.signatureData))
            return request.makeSignatureBlob(rawSignature: Array(rawSignature))
        }
    )

    #expect(
        result.outcome
            == SSHPublicKeyAuthenticationOutcome.success(SSHUserAuthenticationSuccessMessage())
    )
    #expect(result.algorithmName == "ssh-ed25519")

    let signingRequests = await recorder.recordedRequests()
    let signingRequest = try #require(signingRequests.first)
    #expect(signingRequests.count == 1)
    #expect(signingRequest.username == "root")
    #expect(signingRequest.serviceName == "ssh-connection")
    #expect(signingRequest.algorithmName == "ssh-ed25519")
    #expect(signingRequest.publicKey == unsignedRequest.publicKey)

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4])
    _ = try #require(try parser.nextPacket())
    let unsignedPublicKeyRequestPacket = try #require(try parser.nextPacket())
    let signedPublicKeyRequestPacket = try #require(try parser.nextPacket())

    let unsignedParsedMessage = try SSHUserAuthenticationMessageParser().parse(
        unsignedPublicKeyRequestPacket.payload
    )
    let unsignedRequestMessage = try #require({
        if case let .request(message) = unsignedParsedMessage {
            return message
        }
        return nil
    }())
    let signedParsedMessage = try SSHUserAuthenticationMessageParser().parse(
        signedPublicKeyRequestPacket.payload
    )
    let signedRequestMessage = try #require({
        if case let .request(message) = signedParsedMessage {
            return message
        }
        return nil
    }())
    let signedPublicKeyRequest = try #require({
        if case let .publicKey(request) = signedRequestMessage.method {
            return request
        }
        return nil
    }())
    let signatureBlob = try #require(signedPublicKeyRequest.signature)
    var signatureReader = SSHWireReader(bytes: signatureBlob)
    let signatureAlgorithm = try signatureReader.readUTF8String()
    let rawSignature = try signatureReader.readString()
    #expect(signatureReader.isAtEnd)

    let expectedSignatureData = try unsignedRequestMessage.publicKeySignatureData(
        sessionIdentifier: fixture.activation.keyExchangeResult.sessionIdentifier
    )
    #expect(signingRequest.signatureData == expectedSignatureData)
    #expect(signatureAlgorithm == "ssh-ed25519")
    #expect(
        signingKey.publicKey.isValidSignature(
            Data(rawSignature),
            for: Data(signingRequest.signatureData)
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReturnsPublicKeyAuthenticationFailureDetails() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let failurePayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .failure(
            SSHUserAuthenticationFailureMessage(
                authenticationsThatCanContinue: ["password"],
                partialSuccess: false
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            failurePayload,
        ]
    )
    let privateKey = try SSHEd25519PrivateKey(rawRepresentation: Array(0x01...0x20))

    let result = try await fixture.client.authenticatePublicKey(
        username: "root",
        privateKey: privateKey
    )

    #expect(
        result.outcome
            == .failure(
                SSHUserAuthenticationFailureMessage(
                    authenticationsThatCanContinue: ["password"],
                    partialSuccess: false
                )
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientAuthenticatesECDSAP256PublicKeyAfterEncryptedActivation() async throws {
    let cryptoPrivateKey = try P256.Signing.PrivateKey(rawRepresentation: Data(Array(0x01...0x20)))
    let privateKey = SSHECDSAPrivateKey.nistp256(
        rawRepresentation: Array(cryptoPrivateKey.rawRepresentation)
    )
    let unsignedRequest = try privateKey.makeRequest(algorithmName: "ecdsa-sha2-nistp256")
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
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            publicKeyOKPayload,
            successPayload,
        ]
    )

    let result = try await fixture.client.authenticatePublicKey(
        username: "root",
        privateKey: privateKey
    )

    #expect(
        result
            == SSHPublicKeyAuthenticationResult(
                username: "root",
                serviceName: "ssh-connection",
                algorithmName: "ecdsa-sha2-nistp256",
                banners: [],
                outcome: .success(SSHUserAuthenticationSuccessMessage())
            )
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4])
    _ = try #require(try parser.nextPacket())
    let unsignedPublicKeyRequestPacket = try #require(try parser.nextPacket())
    let signedPublicKeyRequestPacket = try #require(try parser.nextPacket())

    let unsignedParsedMessage = try SSHUserAuthenticationMessageParser().parse(
        unsignedPublicKeyRequestPacket.payload
    )
    let unsignedRequestMessage = try #require({
        if case let .request(message) = unsignedParsedMessage {
            return message
        }
        return nil
    }())
    let unsignedPublicKeyRequest = try #require({
        if case let .publicKey(request) = unsignedRequestMessage.method {
            return request
        }
        return nil
    }())

    var publicKeyReader = SSHWireReader(bytes: unsignedPublicKeyRequest.publicKey)
    let publicKeyAlgorithm = try publicKeyReader.readUTF8String()
    let curveName = try publicKeyReader.readUTF8String()
    let rawPublicKey = try publicKeyReader.readString()
    #expect(publicKeyReader.isAtEnd)

    let signedParsedMessage = try SSHUserAuthenticationMessageParser().parse(
        signedPublicKeyRequestPacket.payload
    )
    let requestMessage = try #require({
        if case let .request(message) = signedParsedMessage {
            return message
        }
        return nil
    }())
    let publicKeyRequest = try #require({
        if case let .publicKey(request) = requestMessage.method {
            return request
        }
        return nil
    }())
    let signatureBlob = try #require(publicKeyRequest.signature)
    var signatureReader = SSHWireReader(bytes: signatureBlob)
    let signatureAlgorithm = try signatureReader.readUTF8String()
    let rawSignature = try signatureReader.readString()
    #expect(signatureReader.isAtEnd)

    var ecdsaSignatureReader = SSHWireReader(bytes: rawSignature)
    let r = try ecdsaSignatureReader.readMPInt()
    let s = try ecdsaSignatureReader.readMPInt()
    #expect(ecdsaSignatureReader.isAtEnd)

    let signature = try P256.Signing.ECDSASignature(
        rawRepresentation: Data(
            normalizedECDSASignature(
                r: r,
                s: s,
                coordinateByteCount: 32
            )
        )
    )
    let publicKey = try P256.Signing.PublicKey(x963Representation: Data(rawPublicKey))
    let signatureData = try requestMessage.publicKeySignatureData(
        sessionIdentifier: fixture.activation.keyExchangeResult.sessionIdentifier
    )

    #expect(unsignedRequestMessage.username == "root")
    #expect(unsignedRequestMessage.serviceName == "ssh-connection")
    #expect(unsignedPublicKeyRequest.algorithmName == "ecdsa-sha2-nistp256")
    #expect(unsignedPublicKeyRequest.signature == nil)
    #expect(publicKeyAlgorithm == "ecdsa-sha2-nistp256")
    #expect(curveName == "nistp256")
    #expect(signatureAlgorithm == "ecdsa-sha2-nistp256")
    #expect(publicKey.isValidSignature(signature, for: Data(signatureData)))
}

private func waitForRekeyClientProposal(
    on transport: ServiceRequestRekeyMockSSHByteStreamTransport,
    maxAttempts: Int = 200
) async -> SSHKeyExchangeInitMessage? {
    for _ in 0..<maxAttempts {
        if let proposal = await transport.rekeyClientProposal() {
            return proposal
        }

        try? await Task.sleep(nanoseconds: 5_000_000)
    }

    return nil
}

private func waitForCompletedLocalRekeyMetrics(
    on client: SSHTransportProtocolClient,
    maxAttempts: Int = 200
) async -> SSHTransportProtocolRekeyMetricsSnapshot? {
    for _ in 0..<maxAttempts {
        let metrics = await client.rekeyMetricsSnapshot()
        if metrics.completedLocalRekeyCount == 1 &&
            metrics.completedRemoteRekeyCount == 0 &&
            metrics.outboundEncryptedPacketCountSinceLastKeyExchange == 0 &&
            metrics.inboundEncryptedPacketCountSinceLastKeyExchange == 0 &&
            !metrics.isTransportRekeyInProgress
        {
            return metrics
        }

        try? await Task.sleep(nanoseconds: 5_000_000)
    }

    return nil
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientAuthenticatesRSAPublicKeyWithSHA512ByDefault() async throws {
    let privateKey = try SSHRSAPrivateKey(
        openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM
    )
    let unsignedRequest = try privateKey.makeRequest(
        algorithmName: "rsa-sha2-512"
    )
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
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            publicKeyOKPayload,
            successPayload,
        ]
    )

    let result = try await fixture.client.authenticatePublicKey(
        username: "root",
        privateKey: privateKey
    )

    #expect(
        result
            == SSHPublicKeyAuthenticationResult(
                username: "root",
                serviceName: "ssh-connection",
                algorithmName: "rsa-sha2-512",
                banners: [],
                outcome: .success(SSHUserAuthenticationSuccessMessage())
            )
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4])
    _ = try #require(try parser.nextPacket())
    let unsignedPublicKeyRequestPacket = try #require(try parser.nextPacket())
    let signedPublicKeyRequestPacket = try #require(try parser.nextPacket())

    let unsignedParsedMessage = try SSHUserAuthenticationMessageParser().parse(
        unsignedPublicKeyRequestPacket.payload
    )
    let unsignedRequestMessage = try #require({
        if case let .request(message) = unsignedParsedMessage {
            return message
        }
        return nil
    }())
    let unsignedPublicKeyRequest = try #require({
        if case let .publicKey(request) = unsignedRequestMessage.method {
            return request
        }
        return nil
    }())

    var publicKeyReader = SSHWireReader(bytes: unsignedPublicKeyRequest.publicKey)
    let publicKeyType = try publicKeyReader.readUTF8String()
    let publicExponent = try publicKeyReader.readMPInt()
    let modulus = try publicKeyReader.readMPInt()
    #expect(publicKeyReader.isAtEnd)

    let signedParsedMessage = try SSHUserAuthenticationMessageParser().parse(
        signedPublicKeyRequestPacket.payload
    )
    let requestMessage = try #require({
        if case let .request(message) = signedParsedMessage {
            return message
        }
        return nil
    }())
    let publicKeyRequest = try #require({
        if case let .publicKey(request) = requestMessage.method {
            return request
        }
        return nil
    }())
    let signatureBlob = try #require(publicKeyRequest.signature)
    var signatureReader = SSHWireReader(bytes: signatureBlob)
    let signatureAlgorithm = try signatureReader.readUTF8String()
    let rawSignature = try signatureReader.readString()
    #expect(signatureReader.isAtEnd)

    let signatureData = try requestMessage.publicKeySignatureData(
        sessionIdentifier: fixture.activation.keyExchangeResult.sessionIdentifier
    )
    var error: Unmanaged<CFError>?
    let verified = SecKeyVerifySignature(
        try privateKey.publicSecKey(),
        .rsaSignatureMessagePKCS1v15SHA512,
        Data(signatureData) as CFData,
        Data(rawSignature) as CFData,
        &error
    )

    #expect(unsignedRequestMessage.username == "root")
    #expect(unsignedRequestMessage.serviceName == "ssh-connection")
    #expect(unsignedPublicKeyRequest.algorithmName == "rsa-sha2-512")
    #expect(publicKeyRequest.algorithmName == "rsa-sha2-512")
    #expect(signatureAlgorithm == "rsa-sha2-512")
    #expect(publicKeyType == "ssh-rsa")
    #expect(!publicExponent.isZero)
    #expect(!modulus.isZero)
    #expect(verified)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientUsesServerSignatureAlgorithmsForRSAPublicKeyAuth() async throws {
    let privateKey = try SSHRSAPrivateKey(
        openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM
    )
    let unsignedRequest = try privateKey.makeRequest(
        algorithmName: "rsa-sha2-256"
    )
    let extensionInfoPayload = try SSHTransportMessageSerializer().serialize(
        .extensionInfo(
            SSHExtensionInfoMessage(
                entries: [
                    SSHExtensionInfoEntry(
                        name: "server-sig-algs",
                        value: Array("rsa-sha2-256".utf8)
                    )
                ]
            )
        )
    )
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
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            extensionInfoPayload,
            serviceAcceptPayload,
            publicKeyOKPayload,
            successPayload,
        ]
    )

    let result = try await fixture.client.authenticatePublicKey(
        username: "root",
        privateKey: privateKey
    )

    #expect(result.algorithmName == "rsa-sha2-256")

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4])
    _ = try #require(try parser.nextPacket())
    let unsignedPublicKeyRequestPacket = try #require(try parser.nextPacket())
    let signedPublicKeyRequestPacket = try #require(try parser.nextPacket())

    let unsignedParsedMessage = try SSHUserAuthenticationMessageParser().parse(
        unsignedPublicKeyRequestPacket.payload
    )
    let unsignedRequestMessage = try #require({
        if case let .request(message) = unsignedParsedMessage {
            return message
        }
        return nil
    }())
    let unsignedPublicKeyRequest = try #require({
        if case let .publicKey(request) = unsignedRequestMessage.method {
            return request
        }
        return nil
    }())

    let signedParsedMessage = try SSHUserAuthenticationMessageParser().parse(
        signedPublicKeyRequestPacket.payload
    )
    let requestMessage = try #require({
        if case let .request(message) = signedParsedMessage {
            return message
        }
        return nil
    }())
    let publicKeyRequest = try #require({
        if case let .publicKey(request) = requestMessage.method {
            return request
        }
        return nil
    }())
    let signatureBlob = try #require(publicKeyRequest.signature)
    var signatureReader = SSHWireReader(bytes: signatureBlob)
    let signatureAlgorithm = try signatureReader.readUTF8String()
    let rawSignature = try signatureReader.readString()
    #expect(signatureReader.isAtEnd)

    let signatureData = try requestMessage.publicKeySignatureData(
        sessionIdentifier: fixture.activation.keyExchangeResult.sessionIdentifier
    )
    var error: Unmanaged<CFError>?
    let verified = SecKeyVerifySignature(
        try privateKey.publicSecKey(),
        .rsaSignatureMessagePKCS1v15SHA256,
        Data(signatureData) as CFData,
        Data(rawSignature) as CFData,
        &error
    )

    #expect(unsignedPublicKeyRequest.algorithmName == "rsa-sha2-256")
    #expect(publicKeyRequest.algorithmName == "rsa-sha2-256")
    #expect(signatureAlgorithm == "rsa-sha2-256")
    #expect(verified)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientUsesAdvertisedLegacySSHRSAForRSAPublicKeyAuthWhenPreferred() async throws {
    let privateKey = try SSHRSAPrivateKey(
        openSSHPrivateKey: sampleOpenSSHRSAPrivateKeyPEM
    )
    let unsignedRequest = try privateKey.makeRequest(
        algorithmName: "ssh-rsa"
    )
    let extensionInfoPayload = try SSHTransportMessageSerializer().serialize(
        .extensionInfo(
            SSHExtensionInfoMessage(
                entries: [
                    SSHExtensionInfoEntry(
                        name: "server-sig-algs",
                        value: Array("ssh-rsa".utf8)
                    )
                ]
            )
        )
    )
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
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            extensionInfoPayload,
            serviceAcceptPayload,
            publicKeyOKPayload,
            successPayload,
        ]
    )

    let result = try await fixture.client.authenticatePublicKey(
        username: "root",
        privateKey: privateKey,
        preferredAlgorithmNames: ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
    )

    #expect(result.algorithmName == "ssh-rsa")

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4])
    _ = try #require(try parser.nextPacket())
    let unsignedPublicKeyRequestPacket = try #require(try parser.nextPacket())
    let signedPublicKeyRequestPacket = try #require(try parser.nextPacket())

    let unsignedParsedMessage = try SSHUserAuthenticationMessageParser().parse(
        unsignedPublicKeyRequestPacket.payload
    )
    let unsignedRequestMessage = try #require({
        if case let .request(message) = unsignedParsedMessage {
            return message
        }
        return nil
    }())
    let unsignedPublicKeyRequest = try #require({
        if case let .publicKey(request) = unsignedRequestMessage.method {
            return request
        }
        return nil
    }())

    let signedParsedMessage = try SSHUserAuthenticationMessageParser().parse(
        signedPublicKeyRequestPacket.payload
    )
    let requestMessage = try #require({
        if case let .request(message) = signedParsedMessage {
            return message
        }
        return nil
    }())
    let publicKeyRequest = try #require({
        if case let .publicKey(request) = requestMessage.method {
            return request
        }
        return nil
    }())
    let signatureBlob = try #require(publicKeyRequest.signature)
    var signatureReader = SSHWireReader(bytes: signatureBlob)
    let signatureAlgorithm = try signatureReader.readUTF8String()
    let rawSignature = try signatureReader.readString()
    #expect(signatureReader.isAtEnd)

    let signatureData = try requestMessage.publicKeySignatureData(
        sessionIdentifier: fixture.activation.keyExchangeResult.sessionIdentifier
    )
    var error: Unmanaged<CFError>?
    let verified = SecKeyVerifySignature(
        try privateKey.publicSecKey(),
        .rsaSignatureMessagePKCS1v15SHA1,
        Data(signatureData) as CFData,
        Data(rawSignature) as CFData,
        &error
    )

    #expect(unsignedPublicKeyRequest.algorithmName == "ssh-rsa")
    #expect(publicKeyRequest.algorithmName == "ssh-rsa")
    #expect(signatureAlgorithm == "ssh-rsa")
    #expect(verified)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientAuthenticatesKeyboardInteractiveAfterEncryptedActivation() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let bannerPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .banner(
            SSHUserAuthenticationBannerMessage(
                message: "Interactive login",
                languageTag: "en-US"
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
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            bannerPayload,
            infoRequestPayload,
            successPayload,
        ]
    )

    let result = try await fixture.client.authenticateKeyboardInteractive(
        username: "root",
        submethods: ["pam"]
    ) { challenge in
        #expect(challenge.username == "root")
        #expect(challenge.serviceName == "ssh-connection")
        #expect(challenge.name == "Password Authentication")
        #expect(challenge.instruction == "Enter your password")
        #expect(challenge.languageTag == "en-US")
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

    #expect(
        result
            == SSHKeyboardInteractiveAuthenticationResult(
                username: "root",
                serviceName: "ssh-connection",
                submethods: ["pam"],
                banners: [
                    SSHUserAuthenticationBannerMessage(
                        message: "Interactive login",
                        languageTag: "en-US"
                    )
                ],
                outcome: .success(SSHUserAuthenticationSuccessMessage())
            )
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4])
    let serviceRequestPacket = try #require(try parser.nextPacket())
    let keyboardInteractiveRequestPacket = try #require(try parser.nextPacket())
    let infoResponsePacket = try #require(try parser.nextPacket())

    #expect(sentPayloads.count == 5)
    #expect(
        try SSHTransportMessageParser().parse(serviceRequestPacket.payload)
            == .serviceRequest(
                SSHServiceRequestMessage(serviceName: "ssh-userauth")
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
    #expect(keyboardInteractiveRequest.languageTag.isEmpty)
    #expect(keyboardInteractiveRequest.submethods == ["pam"])
    #expect(infoResponse.responses == ["s3cr3t"])
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientHandlesMultipleKeyboardInteractiveChallengesIncludingZeroPromptMessage() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let firstInfoRequestPayload = SSHUserAuthenticationMessageSerializer()
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
    let secondInfoRequestPayload = SSHUserAuthenticationMessageSerializer()
        .serializeKeyboardInteractiveInfoRequest(
            SSHKeyboardInteractiveInformationRequestMessage(
                name: "Password changed",
                instruction: "Password successfully changed for root.",
                languageTag: "en-US",
                prompts: []
            )
        )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            firstInfoRequestPayload,
            secondInfoRequestPayload,
            successPayload,
        ]
    )
    let recorder = KeyboardInteractiveChallengeRecorder()

    let result = try await fixture.client.authenticateKeyboardInteractive(
        username: "root"
    ) { challenge in
        await recorder.record(challenge)
        return challenge.prompts.isEmpty ? [] : ["s3cr3t"]
    }

    #expect(
        result.outcome
            == .success(SSHUserAuthenticationSuccessMessage())
    )

    let challenges = await recorder.recordedChallenges()
    #expect(challenges.count == 2)
    #expect(challenges[0].name == "Password Authentication")
    #expect(challenges[0].prompts.count == 1)
    #expect(challenges[1].name == "Password changed")
    #expect(challenges[1].instruction == "Password successfully changed for root.")
    #expect(challenges[1].prompts.isEmpty)

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2] + sentPayloads[3] + sentPayloads[4] + sentPayloads[5])
    _ = try #require(try parser.nextPacket())
    _ = try #require(try parser.nextPacket())
    let firstInfoResponsePacket = try #require(try parser.nextPacket())
    let secondInfoResponsePacket = try #require(try parser.nextPacket())

    let firstInfoResponse = try SSHUserAuthenticationMessageParser()
        .parseKeyboardInteractiveInfoResponse(firstInfoResponsePacket.payload)
    let secondInfoResponse = try SSHUserAuthenticationMessageParser()
        .parseKeyboardInteractiveInfoResponse(secondInfoResponsePacket.payload)

    #expect(firstInfoResponse.responses == ["s3cr3t"])
    #expect(secondInfoResponse.responses.isEmpty)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRejectsKeyboardInteractiveResponseCountMismatch() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let infoRequestPayload = SSHUserAuthenticationMessageSerializer()
        .serializeKeyboardInteractiveInfoRequest(
            SSHKeyboardInteractiveInformationRequestMessage(
                name: "OTP",
                instruction: "Enter both factors",
                languageTag: "en-US",
                prompts: [
                    SSHKeyboardInteractivePromptMessage(
                        prompt: "Password: ",
                        shouldEcho: false
                    ),
                    SSHKeyboardInteractivePromptMessage(
                        prompt: "Code: ",
                        shouldEcho: true
                    ),
                ]
            )
        )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            infoRequestPayload,
        ]
    )

    do {
        _ = try await fixture.client.authenticateKeyboardInteractive(
            username: "root"
        ) { _ in
            ["only-one-response"]
        }
        Issue.record("Expected keyboard-interactive response-count mismatch")
    } catch {
        #expect(
            error as? SSHAuthenticationMethodError
                == .invalidKeyboardInteractiveResponseCount(expected: 2, received: 1)
        )
    }

    let sentPayloads = await fixture.transport.sentPayloads()
    #expect(sentPayloads.count == 4)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientAuthenticatesPasswordWhenEncryptedBannerSpansMultipleTransportChunks() async throws {
    let bannerText = String(repeating: "Authorized use only.\r\n", count: 300)
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let bannerPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .banner(
            SSHUserAuthenticationBannerMessage(
                message: bannerText,
                languageTag: "en-US"
            )
        )
    )
    let successPayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .success(SSHUserAuthenticationSuccessMessage())
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            bannerPayload,
            successPayload,
        ],
        encryptedChunkSize: 1024
    )

    let result = try await fixture.client.authenticatePassword(
        username: "root",
        password: "s3cr3t"
    )

    #expect(
        result
            == SSHPasswordAuthenticationResult(
                username: "root",
                serviceName: "ssh-connection",
                banners: [
                    SSHUserAuthenticationBannerMessage(
                        message: bannerText,
                        languageTag: "en-US"
                    )
                ],
                outcome: .success(SSHUserAuthenticationSuccessMessage())
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientReturnsAuthenticationFailureDetails() async throws {
    let serviceAcceptPayload = try SSHTransportMessageSerializer().serialize(
        .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    )
    let failurePayload = try SSHUserAuthenticationMessageSerializer().serialize(
        .failure(
            SSHUserAuthenticationFailureMessage(
                authenticationsThatCanContinue: ["publickey", "password"],
                partialSuccess: false
            )
        )
    )
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            failurePayload,
        ]
    )

    let result = try await fixture.client.authenticatePassword(
        username: "root",
        password: "wrong"
    )

    #expect(
        result.outcome
            == .failure(
                SSHUserAuthenticationFailureMessage(
                    authenticationsThatCanContinue: ["publickey", "password"],
                    partialSuccess: false
                )
            )
    )
}

@Test
func transportProtocolClientRejectsPasswordAuthenticationBeforeEncryptedTransport() async throws {
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            )
        ]
    )
    let client = SSHTransportProtocolClient(transport: transport)

    _ = try await client.exchangeIdentifications()

    do {
        _ = try await client.authenticatePassword(username: "root", password: "s3cr3t")
        Issue.record("Expected confidential-transport-required error")
    } catch {
        #expect(
            error as? SSHUserAuthenticationError == .confidentialTransportRequired
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRejectsPublicKeyAuthenticationBeforeEncryptedTransport() async throws {
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            )
        ]
    )
    let client = SSHTransportProtocolClient(transport: transport)
    let privateKey = try SSHEd25519PrivateKey(rawRepresentation: Array(0x01...0x20))

    _ = try await client.exchangeIdentifications()

    do {
        _ = try await client.authenticatePublicKey(username: "root", privateKey: privateKey)
        Issue.record("Expected confidential-transport-required error")
    } catch {
        #expect(
            error as? SSHUserAuthenticationError == .confidentialTransportRequired
        )
    }
}

private func normalizedECDSASignature(
    r: SSHMPInt,
    s: SSHMPInt,
    coordinateByteCount: Int
) -> [UInt8] {
    normalizedECDSAComponent(r, coordinateByteCount: coordinateByteCount) +
        normalizedECDSAComponent(s, coordinateByteCount: coordinateByteCount)
}

private func normalizedECDSAComponent(
    _ value: SSHMPInt,
    coordinateByteCount: Int
) -> [UInt8] {
    let magnitude = value.encodedBytes.first == 0
        ? Array(value.encodedBytes.dropFirst())
        : value.encodedBytes
    return Array(repeating: 0, count: coordinateByteCount - magnitude.count) + magnitude
}

private let sampleOpenSSHRSAPrivateKeyPEM = """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAy1eZVE7exawA7HgfwhoRGc6aKI4xFucvPnj7y6aZitzJjCNfLner
8c6St28GS2JFUsnyWCNB5iLhoXbu8jK1usG/OIG6vAt9V6HvRDkXCFLhkrwynTUjNUo5YQ
6rkW5QxQfJE6Kl8sdZaq13nF8pcSFDi9IxPrtK1Nfeu6QycfsAAAH4to4I7raOCO4AAAAH
c3NoLXJzYQAAAIEAy1eZVE7exawA7HgfwhoRGc6aKI4xFucvPnj7y6aZitzJjCNfLner8c
6St28GS2JFUsnyWCNB5iLhoXbu8jK1usG/OIG6vAt9V6HvRDkXCFLhkrwynTUjNUo5YQ6r
kW5QxQfJE6Kl8sdZaq13nF8pcSFDi9IxPrtK1Nfeu6QycfsAAAADAQABAAAAgF8o+ZqY5m
w/mJcRiFs/86zOIRrFoHeFbXihCcU+jDCOLswkaZDHdHJPKB4sGRgCP0sFMyLILTjULh9w
F1bFIIIVuGJ5/vJLBL9CGfdfFgzA8Kr6pMq1c7DrGc6mIz3/A1AygqcBY55ZJydOMr1gWb
1YVrWODomfBldE7bLt5PhhAAAAQAndVkxvO8hwyEFGGwF3faHIAe/OxVb+MjaU25//Pe1/
h/e6tlCk4w9CODpyV685gV394eYwMcGDcIkipTNUDZsAAABBAPVgd+8FvkV0kG9SF17YiX
6NoWJrybBVU01qIPYQLFfHoLMbPnhksQH009V8NRkryUnhQkOp6VY2HeI8XdF59YMAAABB
ANQlQcwBS+JjcKZXlT8638uvcT94FjmtujMTPxhOs8fYwux4ENyj2linRvxbh7NPOWk0Q2
gy5hnGfCLzLruzYCkAAAAAAQID
-----END OPENSSH PRIVATE KEY-----
"""
