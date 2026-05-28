// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import CryptoKit
import Foundation
import Testing
@testable import Traversio

@Test
func transportProtocolClientDefaultIdentificationMatchesReleaseVersion() {
    #expect(TraversioRelease.version == "1.0.2")
    #expect(TraversioRelease.sshSoftwareVersion == "Traversio_1.0.2")
    #expect(TraversioRelease.sshIdentificationRawValue == "SSH-2.0-Traversio_1.0.2")
    #expect(SSHTransportProtocolClient.defaultClientIdentification.rawValue == TraversioRelease.sshIdentificationRawValue)
    #expect(SSHTransportProtocolClient.defaultClientIdentification.protocolVersion == "2.0")
    #expect(SSHTransportProtocolClient.defaultClientIdentification.softwareVersion == TraversioRelease.sshSoftwareVersion)
}

@Test
func transportProtocolClientPerformsVersionExchangeAndCapturesPrelude() async throws {
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("notice\r\nSSH-2.0-Open".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(
                bytes: Array("SSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
        ]
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test")
    )

    let exchange = try await client.exchangeIdentifications()

    #expect(exchange.clientIdentification.rawValue == "SSH-2.0-Traversio_Test")
    #expect(exchange.remoteIdentification.rawValue == "SSH-2.0-OpenSSH_9.9 test")
    #expect(exchange.preIdentificationLines == ["notice"])
    #expect(
        await transport.sentPayloads() ==
            [Array("SSH-2.0-Traversio_Test\r\n".utf8)]
    )
}

@Test
func transportProtocolClientRejectsMessagingBeforeVersionExchange() async throws {
    let client = SSHTransportProtocolClient(
        transport: ProtocolClientMockSSHByteStreamTransport(receiveChunks: [])
    )

    do {
        try await client.send(
            message: .serviceRequest(
                SSHServiceRequestMessage(serviceName: "ssh-userauth")
            )
        )
        Issue.record("Expected version-exchange-required error")
    } catch {
        #expect(error as? SSHTransportError == .versionExchangeRequired)
    }
}

@Test
func transportProtocolClientFramesTypedMessagesAfterVersionExchange() async throws {
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            )
        ]
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test")
    )

    _ = try await client.exchangeIdentifications()
    try await client.send(
        message: .serviceRequest(
            SSHServiceRequestMessage(serviceName: "ssh-userauth")
        )
    )

    let sentPayloads = await transport.sentPayloads()
    let serializer = SSHBinaryPacketSerializer()
    let messageSerializer = SSHTransportMessageSerializer()
    let expectedPacket = try serializer.serialize(
        payload: messageSerializer.serialize(
            .serviceRequest(SSHServiceRequestMessage(serviceName: "ssh-userauth"))
        )
    )

    #expect(sentPayloads.count == 2)
    #expect(sentPayloads[1] == expectedPacket)
}

@Test
func transportProtocolClientSendsDisconnectMessageWhenClosing() async throws {
    let fixture = try await makeActivatedTransportFixture(serverPayloadsAfterNewKeys: [])

    await fixture.client.disconnect(description: "closing test")

    let sentPayloads = await fixture.transport.sentPayloads()
    let sentEndOfStreamFlags = await fixture.transport.sentPayloadEndOfStreamFlags()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2])
    let disconnectPacket = try #require(try parser.nextPacket())

    #expect(sentPayloads.count == 3)
    #expect(sentEndOfStreamFlags.count == 3)
    #expect(sentEndOfStreamFlags[2] == false)
    #expect(
        try SSHTransportMessageParser().parse(disconnectPacket.payload)
            == .disconnect(
                SSHDisconnectMessage(
                    reasonCode: .byApplication,
                    description: "closing test",
                    languageTag: ""
                )
            )
    )
}

@Test
func transportProtocolClientReceivesChunkedTypedMessages() async throws {
    let packetSerializer = SSHBinaryPacketSerializer()
    let messageSerializer = SSHTransportMessageSerializer()
    let packetBytes = try packetSerializer.serialize(
        payload: messageSerializer.serialize(
            .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
        )
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(
                bytes: Array(packetBytes.prefix(7)),
                endOfStream: false
            ),
            SSHByteStreamChunk(
                bytes: Array(packetBytes.dropFirst(7)),
                endOfStream: false
            ),
        ]
    )
    let client = SSHTransportProtocolClient(transport: transport)

    _ = try await client.exchangeIdentifications()
    let message = try await client.receiveMessage()

    #expect(
        message == .serviceAccept(
            SSHServiceAcceptMessage(serviceName: "ssh-userauth")
        )
    )
}

@Test
func transportProtocolClientPreservesPacketsBufferedAfterIdentification() async throws {
    let packetSerializer = SSHBinaryPacketSerializer()
    let messageSerializer = SSHTransportMessageSerializer()
    let packetBytes = try packetSerializer.serialize(
        payload: messageSerializer.serialize(
            .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
        )
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-dropbear_2024.85\r\n".utf8) + packetBytes,
                endOfStream: false
            ),
        ]
    )
    let client = SSHTransportProtocolClient(transport: transport)

    let exchange = try await client.exchangeIdentifications()
    let message = try await client.receiveMessage()

    #expect(exchange.remoteIdentification.rawValue == "SSH-2.0-dropbear_2024.85")
    #expect(
        message == .serviceAccept(
            SSHServiceAcceptMessage(serviceName: "ssh-userauth")
        )
    )
}

@Test
func transportProtocolClientFailsIfPeerClosesMidPacket() async throws {
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(
                bytes: [0x00, 0x00, 0x00, 0x1c, 0x0a],
                endOfStream: true
            ),
        ]
    )
    let client = SSHTransportProtocolClient(transport: transport)

    _ = try await client.exchangeIdentifications()

    do {
        _ = try await client.receiveMessage()
        Issue.record("Expected end-of-stream-before-packet error")
    } catch {
        #expect(error as? SSHTransportError == .endOfStreamBeforePacket)
    }
}

@Test
func transportProtocolClientRejectsKeyExchangeInitBeforeVersionExchange() async throws {
    let client = SSHTransportProtocolClient(
        transport: ProtocolClientMockSSHByteStreamTransport(receiveChunks: [])
    )

    do {
        _ = try await client.exchangeKeyExchangeInit()
        Issue.record("Expected version-exchange-required error")
    } catch {
        #expect(error as? SSHTransportError == .versionExchangeRequired)
    }
}

@Test
func transportProtocolClientExchangesKeyExchangeInitAndNegotiatesAlgorithms() async throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256", "ecdh-sha2-nistp256"],
        serverHostKeyAlgorithms: ["ssh-ed25519", "rsa-sha2-512"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr", "aes256-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr", "aes256-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256", "hmac-sha2-512"],
        macAlgorithmsServerToClient: ["hmac-sha2-256", "hmac-sha2-512"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp256", "curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519", "rsa-sha2-512"],
        encryptionAlgorithmsClientToServer: ["aes256-ctr", "aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr", "aes256-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-512", "hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256", "hmac-sha2-512"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let packetSerializer = SSHBinaryPacketSerializer()
    let messageSerializer = SSHTransportMessageSerializer()
    let remoteKEXINITPacket = try packetSerializer.serialize(
        payload: messageSerializer.serialize(
            .keyExchangeInit(remoteProposal)
        )
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(
                bytes: Array(remoteKEXINITPacket.prefix(9)),
                endOfStream: false
            ),
            SSHByteStreamChunk(
                bytes: Array(remoteKEXINITPacket.dropFirst(9)),
                endOfStream: false
            ),
        ]
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test")
    )

    _ = try await client.exchangeIdentifications()
    let negotiation = try await client.exchangeKeyExchangeInit(
        localProposal: localProposal
    )

    let expectedLocalKEXINITPacket = try packetSerializer.serialize(
        payload: messageSerializer.serialize(
            .keyExchangeInit(localProposal)
        )
    )
    let sentPayloads = await transport.sentPayloads()

    #expect(negotiation.localProposal == localProposal)
    #expect(negotiation.remoteProposal == remoteProposal)
    #expect(negotiation.algorithms.keyExchangeAlgorithm == "curve25519-sha256")
    #expect(negotiation.algorithms.serverHostKeyAlgorithm == "ssh-ed25519")
    #expect(negotiation.algorithms.encryptionAlgorithmClientToServer == "aes128-ctr")
    #expect(negotiation.algorithms.encryptionAlgorithmServerToClient == "aes128-ctr")
    #expect(sentPayloads.count == 2)
    #expect(sentPayloads[1] == expectedLocalKEXINITPacket)
}

@Test
func transportProtocolClientSkipsIgnoreWhileWaitingForKeyExchangeInit() async throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let ignorePacket = try SSHBinaryPacketSerializer().serialize(
        payload: SSHTransportMessageSerializer().serialize(
            .ignore(SSHIgnoreMessage(data: [0xde, 0xad, 0xbe, 0xef]))
        )
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let kexinitPacket = try SSHBinaryPacketSerializer().serialize(
        payload: SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(remoteProposal)
        )
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(bytes: ignorePacket, endOfStream: false),
            SSHByteStreamChunk(bytes: kexinitPacket, endOfStream: false),
        ]
    )
    let client = SSHTransportProtocolClient(transport: transport)

    _ = try await client.exchangeIdentifications()
    let negotiation = try await client.exchangeKeyExchangeInit(localProposal: localProposal)

    #expect(negotiation.algorithms.keyExchangeAlgorithm == "curve25519-sha256")
}

@Test
func transportProtocolClientRejectsInitialStrictKeyExchangeWhenKEXINITIsNotFirstPacket() async throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256", "kex-strict-c-v00@openssh.com"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let ignorePacket = try SSHBinaryPacketSerializer().serialize(
        payload: SSHTransportMessageSerializer().serialize(
            .ignore(SSHIgnoreMessage(data: [0xde, 0xad, 0xbe, 0xef]))
        )
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let kexinitPacket = try SSHBinaryPacketSerializer().serialize(
        payload: SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(remoteProposal)
        )
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(bytes: ignorePacket, endOfStream: false),
            SSHByteStreamChunk(bytes: kexinitPacket, endOfStream: false),
        ]
    )
    let client = SSHTransportProtocolClient(transport: transport)

    _ = try await client.exchangeIdentifications()

    do {
        _ = try await client.exchangeKeyExchangeInit(localProposal: localProposal)
        Issue.record("Expected strict-key-exchange-violation error")
    } catch let error as SSHTransportError {
        switch error {
        case let .strictKeyExchangeViolation(details):
            #expect(
                details == "The server's SSH_MSG_KEXINIT was not the first packet after identification."
            )
        default:
            Issue.record("Expected strict-key-exchange-violation error, received \(error)")
        }
    }
}

@Test
func transportProtocolClientRejectsUnexpectedMessageWhileWaitingForKeyExchangeInit() async throws {
    let packet = try SSHBinaryPacketSerializer().serialize(
        payload: SSHTransportMessageSerializer().serialize(
            .serviceAccept(SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
        )
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(bytes: packet, endOfStream: false),
        ]
    )
    let client = SSHTransportProtocolClient(transport: transport)

    _ = try await client.exchangeIdentifications()

    do {
        _ = try await client.exchangeKeyExchangeInit()
        Issue.record("Expected unexpected-transport-message error")
    } catch {
        #expect(
            error as? SSHTransportError
                == .unexpectedTransportMessage(
                    expected: .keyExchangeInit,
                    received: .serviceAccept
                )
        )
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientBeginsCurve25519KeyExchangeAndComputesTranscript() async throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256", "ecdh-sha2-nistp256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: localProposal,
        remoteProposal: remoteProposal
    )
    let serverPrivateKey = try Curve25519.KeyAgreement.PrivateKey(
        rawRepresentation: Data(Array(0x21...0x40))
    )
    let serverPublicKey = Array(serverPrivateKey.publicKey.rawRepresentation)
    let serverHostKey = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8)
    let serverSignature = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8) + [0xde, 0xad, 0xbe, 0xef]
    let replyPacket = try SSHBinaryPacketSerializer().serialize(
        payload: SSHTransportMessageSerializer().serialize(
            .keyExchangeECDHReply(
                SSHKeyExchangeECDHReplyMessage(
                    hostKey: serverHostKey,
                    publicKey: serverPublicKey,
                    signature: serverSignature
                )
            )
        )
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(bytes: replyPacket, endOfStream: false),
        ]
    )
    let clientIdentification = try SSHIdentification(softwareVersion: "Traversio_Test")
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: clientIdentification
    )

    let versionExchange = try await client.exchangeIdentifications()
    let result = try await client.beginCurve25519KeyExchange(negotiation: negotiation)

    let sentPayloads = await transport.sentPayloads()
    let outboundECDHPacket = try SSHBinaryPacketParser.consumeSinglePacket(
        from: sentPayloads[1]
    )
    let outboundECDHMessage = try SSHTransportMessageParser().parse(outboundECDHPacket.payload)

    guard case let .keyExchangeECDHInit(initMessage) = outboundECDHMessage else {
        Issue.record("Expected outbound SSH_MSG_KEX_ECDH_INIT")
        return
    }

    let expectedSharedSecretBytes = try serverPrivateKey.sharedSecretFromKeyAgreement(
        with: try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: Data(initMessage.publicKey)
        )
    ).withUnsafeBytes { Array($0) }
    let expectedSharedSecret = SSHMPInt(unsignedMagnitude: expectedSharedSecretBytes)
    let expectedExchangeHash = makeExpectedCurve25519ExchangeHash(
        clientIdentification: clientIdentification,
        serverIdentification: versionExchange.remoteIdentification,
        clientKeyExchangeInitPayload: try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(localProposal)
        ),
        serverKeyExchangeInitPayload: try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(remoteProposal)
        ),
        serverHostKey: serverHostKey,
        clientEphemeralPublicKey: initMessage.publicKey,
        serverEphemeralPublicKey: serverPublicKey,
        sharedSecret: expectedSharedSecret
    )

    #expect(sentPayloads.count == 2)
    #expect(initMessage.publicKey.count == 32)
    #expect(result.keyExchangeAlgorithm == "curve25519-sha256")
    #expect(result.clientEphemeralPublicKey == initMessage.publicKey)
    #expect(result.serverHostKey == serverHostKey)
    #expect(result.serverEphemeralPublicKey == serverPublicKey)
    #expect(result.serverSignature == serverSignature)
    #expect(result.sharedSecret == expectedSharedSecret)
    #expect(result.exchangeHash == expectedExchangeHash)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientBeginsNISTP256KeyExchangeAndComputesTranscript() async throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp256", "curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: localProposal,
        remoteProposal: remoteProposal
    )
    let serverPrivateKey = try P256.KeyAgreement.PrivateKey(
        rawRepresentation: Data(Array(0x21...0x40))
    )
    let serverPublicKey = Array(serverPrivateKey.publicKey.x963Representation)
    let serverHostKey = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8)
    let serverSignature = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8) + [0xca, 0xfe, 0xba, 0xbe]
    let replyPacket = try SSHBinaryPacketSerializer().serialize(
        payload: SSHTransportMessageSerializer().serialize(
            .keyExchangeECDHReply(
                SSHKeyExchangeECDHReplyMessage(
                    hostKey: serverHostKey,
                    publicKey: serverPublicKey,
                    signature: serverSignature
                )
            )
        )
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(bytes: replyPacket, endOfStream: false),
        ]
    )
    let clientIdentification = try SSHIdentification(softwareVersion: "Traversio_Test")
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: clientIdentification
    )

    let versionExchange = try await client.exchangeIdentifications()
    let result = try await client.beginCurve25519KeyExchange(negotiation: negotiation)

    let sentPayloads = await transport.sentPayloads()
    let outboundECDHPacket = try SSHBinaryPacketParser.consumeSinglePacket(
        from: sentPayloads[1]
    )
    let outboundECDHMessage = try SSHTransportMessageParser().parse(outboundECDHPacket.payload)

    guard case let .keyExchangeECDHInit(initMessage) = outboundECDHMessage else {
        Issue.record("Expected outbound SSH_MSG_KEX_ECDH_INIT")
        return
    }

    let expectedSharedSecretBytes = try serverPrivateKey.sharedSecretFromKeyAgreement(
        with: try P256.KeyAgreement.PublicKey(
            x963Representation: Data(initMessage.publicKey)
        )
    ).withUnsafeBytes { Array($0) }
    let expectedSharedSecret = SSHMPInt(unsignedMagnitude: expectedSharedSecretBytes)
    let expectedExchangeHash = makeExpectedCurve25519ExchangeHash(
        clientIdentification: clientIdentification,
        serverIdentification: versionExchange.remoteIdentification,
        clientKeyExchangeInitPayload: try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(localProposal)
        ),
        serverKeyExchangeInitPayload: try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(remoteProposal)
        ),
        serverHostKey: serverHostKey,
        clientEphemeralPublicKey: initMessage.publicKey,
        serverEphemeralPublicKey: serverPublicKey,
        sharedSecret: expectedSharedSecret
    )

    #expect(sentPayloads.count == 2)
    #expect(initMessage.publicKey.count == 65)
    #expect(result.keyExchangeAlgorithm == "ecdh-sha2-nistp256")
    #expect(result.clientEphemeralPublicKey == initMessage.publicKey)
    #expect(result.serverHostKey == serverHostKey)
    #expect(result.serverEphemeralPublicKey == serverPublicKey)
    #expect(result.serverSignature == serverSignature)
    #expect(result.sharedSecret == expectedSharedSecret)
    #expect(result.exchangeHash == expectedExchangeHash)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientBeginsNISTP384KeyExchangeAndComputesSHA384Transcript() async throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp384", "ecdh-sha2-nistp256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp384"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: localProposal,
        remoteProposal: remoteProposal
    )
    let serverPrivateKey = try P384.KeyAgreement.PrivateKey(
        rawRepresentation: Data(makeFixedScalarBytes(length: 48, scalar: 2))
    )
    let serverPublicKey = Array(serverPrivateKey.publicKey.x963Representation)
    let serverHostKey = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8)
    let serverSignature = [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8) + [0x38, 0x40]
    let replyPacket = try SSHBinaryPacketSerializer().serialize(
        payload: SSHTransportMessageSerializer().serialize(
            .keyExchangeECDHReply(
                SSHKeyExchangeECDHReplyMessage(
                    hostKey: serverHostKey,
                    publicKey: serverPublicKey,
                    signature: serverSignature
                )
            )
        )
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(bytes: replyPacket, endOfStream: false),
        ]
    )
    let clientIdentification = try SSHIdentification(softwareVersion: "Traversio_Test")
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: clientIdentification
    )

    let versionExchange = try await client.exchangeIdentifications()
    let result = try await client.beginCurve25519KeyExchange(negotiation: negotiation)

    let sentPayloads = await transport.sentPayloads()
    let outboundECDHPacket = try SSHBinaryPacketParser.consumeSinglePacket(
        from: sentPayloads[1]
    )
    let outboundECDHMessage = try SSHTransportMessageParser().parse(outboundECDHPacket.payload)

    guard case let .keyExchangeECDHInit(initMessage) = outboundECDHMessage else {
        Issue.record("Expected outbound SSH_MSG_KEX_ECDH_INIT")
        return
    }

    let expectedSharedSecretBytes = try serverPrivateKey.sharedSecretFromKeyAgreement(
        with: try P384.KeyAgreement.PublicKey(
            x963Representation: Data(initMessage.publicKey)
        )
    ).withUnsafeBytes { Array($0) }
    let expectedSharedSecret = SSHMPInt(unsignedMagnitude: expectedSharedSecretBytes)
    let expectedExchangeHash = makeExpectedCurve25519ExchangeHash(
        clientIdentification: clientIdentification,
        serverIdentification: versionExchange.remoteIdentification,
        clientKeyExchangeInitPayload: try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(localProposal)
        ),
        serverKeyExchangeInitPayload: try SSHTransportMessageSerializer().serialize(
            .keyExchangeInit(remoteProposal)
        ),
        serverHostKey: serverHostKey,
        clientEphemeralPublicKey: initMessage.publicKey,
        serverEphemeralPublicKey: serverPublicKey,
        sharedSecret: expectedSharedSecret,
        hashAlgorithm: .sha384
    )

    #expect(sentPayloads.count == 2)
    #expect(initMessage.publicKey.count == 97)
    #expect(result.keyExchangeAlgorithm == "ecdh-sha2-nistp384")
    #expect(result.clientEphemeralPublicKey == initMessage.publicKey)
    #expect(result.serverHostKey == serverHostKey)
    #expect(result.serverEphemeralPublicKey == serverPublicKey)
    #expect(result.serverSignature == serverSignature)
    #expect(result.sharedSecret == expectedSharedSecret)
    #expect(result.exchangeHash == expectedExchangeHash)
    #expect(result.exchangeHash.count == 48)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientDiscardsGuessedPacketBeforeCurve25519Reply() async throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256", "ecdh-sha2-nistp256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["ecdh-sha2-nistp256", "curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"],
        firstKeyExchangePacketFollows: true
    )
    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: localProposal,
        remoteProposal: remoteProposal
    )
    let guessedPacket = try SSHBinaryPacketSerializer().serialize(payload: [0x7f, 0x00])
    let replyPacket = try SSHBinaryPacketSerializer().serialize(
        payload: SSHTransportMessageSerializer().serialize(
            .keyExchangeECDHReply(
                SSHKeyExchangeECDHReplyMessage(
                    hostKey: [0x01],
                    publicKey: Array(
                        try Curve25519.KeyAgreement.PrivateKey(
                            rawRepresentation: Data(Array(0x21...0x40))
                        ).publicKey.rawRepresentation
                    ),
                    signature: [0x02]
                )
            )
        )
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(bytes: guessedPacket, endOfStream: false),
            SSHByteStreamChunk(bytes: replyPacket, endOfStream: false),
        ]
    )
    let client = SSHTransportProtocolClient(transport: transport)

    _ = try await client.exchangeIdentifications()
    let result = try await client.beginCurve25519KeyExchange(negotiation: negotiation)

    #expect(negotiation.shouldIgnoreNextPacketFromServer == true)
    #expect(result.serverHostKey == [0x01])
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRejectsIgnoreDuringInitialStrictKeyExchange() async throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256", "kex-strict-c-v00@openssh.com"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: localProposal,
        remoteProposal: remoteProposal
    )
    let ignorePacket = try SSHBinaryPacketSerializer().serialize(
        payload: SSHTransportMessageSerializer().serialize(
            .ignore(SSHIgnoreMessage(data: [0xca, 0xfe]))
        )
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(bytes: ignorePacket, endOfStream: false),
        ]
    )
    let client = SSHTransportProtocolClient(transport: transport)

    _ = try await client.exchangeIdentifications()

    do {
        _ = try await client.beginCurve25519KeyExchange(negotiation: negotiation)
        Issue.record("Expected strict-key-exchange-violation error")
    } catch let error as SSHTransportError {
        switch error {
        case let .strictKeyExchangeViolation(details):
            #expect(details == "Received ignore during the initial strict key exchange.")
        default:
            Issue.record("Expected strict-key-exchange-violation error, received \(error)")
        }
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientActivatesNewKeysAndReceivesBufferedEncryptedPacket() async throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: localProposal,
        remoteProposal: remoteProposal
    )
    let exchangeHash = Array(0x80...0x9f).map(UInt8.init)
    let sessionIdentifier = Array(exchangeHash)
    let serverSigningKey = Curve25519.Signing.PrivateKey()
    var hostKeyWriter = SSHWireWriter()
    hostKeyWriter.write(utf8: "ssh-ed25519")
    hostKeyWriter.write(string: Array(serverSigningKey.publicKey.rawRepresentation))
    let hostKey = hostKeyWriter.bytes
    let signatureBytes = Array(
        try serverSigningKey.signature(for: Data(exchangeHash))
    )
    var signatureWriter = SSHWireWriter()
    signatureWriter.write(utf8: "ssh-ed25519")
    signatureWriter.write(string: signatureBytes)
    let signature = signatureWriter.bytes
    let keyExchangeResult = SSHCurve25519ClientKeyExchangeResult(
        keyExchangeAlgorithm: "curve25519-sha256",
        clientEphemeralPublicKey: Array(repeating: 0x11, count: 32),
        serverHostKey: hostKey,
        serverEphemeralPublicKey: Array(repeating: 0x22, count: 32),
        serverSignature: signature,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: exchangeHash,
        sessionIdentifier: sessionIdentifier
    )
    let keyMaterial = try keyExchangeResult.deriveTransportKeyMaterial(
        negotiatedAlgorithms: negotiation.algorithms
    )
    let clearNewKeysPacket = try SSHBinaryPacketSerializer().serialize(
        payload: SSHTransportMessageSerializer().serialize(.newKeys(SSHNewKeysMessage()))
    )
    var encryptedSerializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiation.algorithms,
        keyMaterial: keyMaterial,
        direction: .serverToClient,
        initialSequenceNumber: 1
    )
    let encryptedServiceAcceptPacket = try encryptedSerializer.serialize(
        payload: SSHTransportMessageSerializer().serialize(
            .serviceAccept(
                SSHServiceAcceptMessage(serviceName: "ssh-userauth")
            )
        )
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(
                bytes: clearNewKeysPacket + encryptedServiceAcceptPacket,
                endOfStream: false
            ),
        ]
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test")
    )

    _ = try await client.exchangeIdentifications()
    let activation = try await client.activateCurve25519Transport(
        negotiation: negotiation,
        keyExchangeResult: keyExchangeResult,
        hostKeyTrustPolicy: .acceptAnyVerifiedHostKey
    )

    let message = try await client.receiveMessage()
    let sentPayloads = await transport.sentPayloads()

    #expect(activation.verifiedHostKey.algorithmName == "ssh-ed25519")
    #expect(activation.hostKeyTrust.method == .acceptAnyVerifiedHostKey)
    #expect(activation.transportKeyMaterial == keyMaterial)
    #expect(sentPayloads.count == 2)
    #expect(
        try SSHBinaryPacketParser.consumeSinglePacket(from: sentPayloads[1]).payload
            == SSHTransportMessageSerializer().serialize(.newKeys(SSHNewKeysMessage()))
    )
    #expect(
        message == .serviceAccept(
            SSHServiceAcceptMessage(serviceName: "ssh-userauth")
        )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCompletesRemoteRekeyDuringServiceRequest() async throws {
    let transport = ServiceRequestRekeyMockSSHByteStreamTransport(
        rekeyMode: .remoteInitiated
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test")
    )

    _ = try await client.exchangeIdentifications()
    _ = try await client.completeCurve25519KeyExchange(
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey
    )
    let accept = try await client.requestService("ssh-userauth")
    let rekeyClientProposal = try #require(await transport.rekeyClientProposal())
    let rekeyMetrics = await client.rekeyMetricsSnapshot()

    #expect(accept == SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    #expect(!rekeyClientProposal.keyExchangeAlgorithms.contains("ext-info-c"))
    #expect(!rekeyClientProposal.keyExchangeAlgorithms.contains("kex-strict-c-v00@openssh.com"))
    #expect(rekeyMetrics.completedRemoteRekeyCount == 1)
    #expect(rekeyMetrics.completedLocalRekeyCount == 0)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientCompletesRemoteRekeyDuringServiceRequestAfterInitialStrictKeyExchange()
    async throws
{
    let transport = ServiceRequestRekeyMockSSHByteStreamTransport(
        rekeyMode: .remoteInitiated,
        strictKeyExchange: true
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test")
    )

    _ = try await client.exchangeIdentifications()
    _ = try await client.completeCurve25519KeyExchange(
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey
    )
    let accept = try await client.requestService("ssh-userauth")
    let rekeyMetrics = await client.rekeyMetricsSnapshot()

    #expect(accept == SSHServiceAcceptMessage(serviceName: "ssh-userauth"))
    #expect(rekeyMetrics.completedRemoteRekeyCount == 1)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientRechecksTransportRekeyAfterWaitingForOutboundSendTurn() async throws {
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [],
        sendDelayNanoseconds: 100_000_000
    )
    let baselineSentCount = await fixture.transport.sentPayloads().count
    let firstMessage = SSHConnectionMessage.globalRequest(
        SSHGlobalRequestMessage(
            requestName: "first@traversio.test",
            wantReply: false,
            requestData: []
        )
    )
    let secondMessage = SSHConnectionMessage.globalRequest(
        SSHGlobalRequestMessage(
            requestName: "second@traversio.test",
            wantReply: false,
            requestData: []
        )
    )

    let firstSendTask = Task {
        try await fixture.client.sendConnectionMessage(firstMessage)
    }
    try await Task.sleep(nanoseconds: 20_000_000)

    let secondSendTask = Task {
        try await fixture.client.sendConnectionMessage(secondMessage)
    }
    try await Task.sleep(nanoseconds: 20_000_000)

    let rekeyTask = Task {
        try await fixture.client.withTransportRekeyInProgress {
            try await Task.sleep(nanoseconds: 200_000_000)
        }
    }

    try await Task.sleep(nanoseconds: 150_000_000)
    let sentCountWhileRekeyInProgress = await fixture.transport.sentPayloads().count

    try await rekeyTask.value
    try await firstSendTask.value
    try await secondSendTask.value

    let finalSentCount = await fixture.transport.sentPayloads().count

    #expect(sentCountWhileRekeyInProgress == baselineSentCount + 1)
    #expect(finalSentCount == baselineSentCount + 2)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolDiagnosticsRetainStrictKeyExchangeAfterLaterRekey() async throws {
    let transport = ServiceRequestRekeyMockSSHByteStreamTransport(
        rekeyMode: .remoteInitiated,
        strictKeyExchange: true
    )
    let client = SSHTransportProtocolClient(
        transport: transport,
        clientIdentification: try SSHIdentification(softwareVersion: "Traversio_Test")
    )

    _ = try await client.exchangeIdentifications()
    _ = try await client.completeCurve25519KeyExchange(
        hostKeyTrustPolicy: SSHHostKeyTrustPolicy.acceptAnyVerifiedHostKey
    )
    _ = try await client.requestService("ssh-userauth")
    let snapshot = await client.diagnosticsSnapshot()
    let negotiatedAlgorithms = try #require(snapshot.negotiatedAlgorithms)

    #expect(negotiatedAlgorithms.keyExchangeAlgorithm == "curve25519-sha256")
    #expect(negotiatedAlgorithms.usesStrictKeyExchange == true)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolDiagnosticsCaptureServerExtensionInfoState() async throws {
    let extensionInfoPayload = try SSHTransportMessageSerializer().serialize(
        .extensionInfo(
            SSHExtensionInfoMessage(
                entries: [
                    SSHExtensionInfoEntry(
                        name: "delay-compression",
                        value: Array("zlib@openssh.com".utf8)
                    ),
                    SSHExtensionInfoEntry(
                        name: "server-sig-algs",
                        value: Array("rsa-sha2-512,rsa-sha2-256".utf8)
                    ),
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
    let snapshot = await fixture.client.diagnosticsSnapshot()

    #expect(snapshot.didReceiveServerExtensionInfo == true)
    #expect(snapshot.serverExtensionNames == ["delay-compression", "server-sig-algs"])
    #expect(snapshot.serverSignatureAlgorithms == ["rsa-sha2-512", "rsa-sha2-256"])
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientEncryptsMessagesAfterNewKeysActivation() async throws {
    let localProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x00...0x0f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let remoteProposal = try SSHKeyExchangeInitMessage(
        cookie: Array(0x10...0x1f),
        keyExchangeAlgorithms: ["curve25519-sha256"],
        serverHostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithmsClientToServer: ["aes128-ctr"],
        encryptionAlgorithmsServerToClient: ["aes128-ctr"],
        macAlgorithmsClientToServer: ["hmac-sha2-256"],
        macAlgorithmsServerToClient: ["hmac-sha2-256"],
        compressionAlgorithmsClientToServer: ["none"],
        compressionAlgorithmsServerToClient: ["none"]
    )
    let negotiation = try SSHKeyExchangeAlgorithmNegotiator().negotiate(
        localProposal: localProposal,
        remoteProposal: remoteProposal
    )
    let exchangeHash = Array(0x60...0x7f).map(UInt8.init)
    let signingKey = Curve25519.Signing.PrivateKey()
    var hostKeyWriter = SSHWireWriter()
    hostKeyWriter.write(utf8: "ssh-ed25519")
    hostKeyWriter.write(string: Array(signingKey.publicKey.rawRepresentation))
    var signatureWriter = SSHWireWriter()
    signatureWriter.write(utf8: "ssh-ed25519")
    signatureWriter.write(
        string: try Array(signingKey.signature(for: Data(exchangeHash)))
    )
    let keyExchangeResult = SSHCurve25519ClientKeyExchangeResult(
        keyExchangeAlgorithm: "curve25519-sha256",
        clientEphemeralPublicKey: Array(repeating: 0x33, count: 32),
        serverHostKey: hostKeyWriter.bytes,
        serverEphemeralPublicKey: Array(repeating: 0x44, count: 32),
        serverSignature: signatureWriter.bytes,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: exchangeHash,
        sessionIdentifier: exchangeHash
    )
    let transport = ProtocolClientMockSSHByteStreamTransport(
        receiveChunks: [
            SSHByteStreamChunk(
                bytes: Array("SSH-2.0-OpenSSH_9.9 test\r\n".utf8),
                endOfStream: false
            ),
            SSHByteStreamChunk(
                bytes: try SSHBinaryPacketSerializer().serialize(
                    payload: SSHTransportMessageSerializer().serialize(.newKeys(SSHNewKeysMessage()))
                ),
                endOfStream: false
            ),
        ]
    )
    let client = SSHTransportProtocolClient(transport: transport)

    _ = try await client.exchangeIdentifications()
    let activation = try await client.activateCurve25519Transport(
        negotiation: negotiation,
        keyExchangeResult: keyExchangeResult,
        hostKeyTrustPolicy: .acceptAnyVerifiedHostKey
    )
    try await client.send(
        message: .serviceRequest(
            SSHServiceRequestMessage(serviceName: "ssh-userauth")
        )
    )

    let sentPayloads = await transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: activation.negotiation.algorithms,
        keyMaterial: activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 1
    )
    parser.append(bytes: sentPayloads[2])
    let packet = try #require(try parser.nextPacket())

    #expect(sentPayloads.count == 3)
    #expect(
        try SSHTransportMessageParser().parse(packet.payload)
            == .serviceRequest(
                SSHServiceRequestMessage(serviceName: "ssh-userauth")
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func transportProtocolClientResetsSequenceNumbersAfterStrictNewKeysActivation() async throws {
    let fixture = try await makeActivatedTransportFixture(
        serverPayloadsAfterNewKeys: [
            SSHTransportMessageSerializer().serialize(
                .serviceAccept(
                    SSHServiceAcceptMessage(serviceName: "ssh-userauth")
                )
            )
        ],
        strictKeyExchange: true
    )

    let message = try await fixture.client.receiveMessage()
    try await fixture.client.send(
        message: .serviceRequest(
            SSHServiceRequestMessage(serviceName: "ssh-userauth")
        )
    )

    let sentPayloads = await fixture.transport.sentPayloads()
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: fixture.activation.negotiation.algorithms,
        keyMaterial: fixture.activation.transportKeyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 0
    )
    parser.append(bytes: sentPayloads[2])
    let packet = try #require(try parser.nextPacket())

    #expect(fixture.activation.negotiation.usesStrictKeyExchange == true)
    #expect(
        message == .serviceAccept(
            SSHServiceAcceptMessage(serviceName: "ssh-userauth")
        )
    )
    #expect(sentPayloads.count == 3)
    #expect(
        try SSHTransportMessageParser().parse(packet.payload)
            == .serviceRequest(
                SSHServiceRequestMessage(serviceName: "ssh-userauth")
            )
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
private func makeExpectedCurve25519ExchangeHash(
    clientIdentification: SSHIdentification,
    serverIdentification: SSHIdentification,
    clientKeyExchangeInitPayload: [UInt8],
    serverKeyExchangeInitPayload: [UInt8],
    serverHostKey: [UInt8],
    clientEphemeralPublicKey: [UInt8],
    serverEphemeralPublicKey: [UInt8],
    sharedSecret: SSHMPInt,
    hashAlgorithm: ExpectedTransportExchangeHashAlgorithm = .sha256
) -> [UInt8] {
    var writer = SSHWireWriter()
    writer.write(utf8: clientIdentification.rawValue)
    writer.write(utf8: serverIdentification.rawValue)
    writer.write(string: clientKeyExchangeInitPayload)
    writer.write(string: serverKeyExchangeInitPayload)
    writer.write(string: serverHostKey)
    writer.write(string: clientEphemeralPublicKey)
    writer.write(string: serverEphemeralPublicKey)
    writer.write(mpint: sharedSecret)
    return hashAlgorithm.hash(writer.bytes)
}

private func makeFixedScalarBytes(length: Int, scalar: UInt8) -> [UInt8] {
    Array(repeating: UInt8(0), count: length - 1) + [scalar]
}

private enum ExpectedTransportExchangeHashAlgorithm {
    case sha256
    case sha384

    func hash(_ bytes: [UInt8]) -> [UInt8] {
        switch self {
        case .sha256:
            return Array(SHA256.hash(data: bytes))
        case .sha384:
            return Array(SHA384.hash(data: bytes))
        }
    }
}
