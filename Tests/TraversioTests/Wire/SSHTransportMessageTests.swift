// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func transportMessageSerializerSerializesServiceRequest() throws {
    let serializer = SSHTransportMessageSerializer()

    let bytes = try serializer.serialize(
        .serviceRequest(
            SSHServiceRequestMessage(serviceName: "ssh-userauth")
        )
    )

    #expect(
        bytes == [
            0x05,
            0x00, 0x00, 0x00, 0x0c,
            0x73, 0x73, 0x68, 0x2d, 0x75, 0x73, 0x65, 0x72, 0x61, 0x75, 0x74, 0x68,
        ]
    )
}

@Test
func transportMessageParserRoundTripsDisconnect() throws {
    let serializer = SSHTransportMessageSerializer()
    let parser = SSHTransportMessageParser()
    let message = SSHTransportMessage.disconnect(
        SSHDisconnectMessage(
            reasonCode: .byApplication,
            description: "closing",
            languageTag: "en-AU"
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func transportMessageParserRoundTripsKeyExchangeInitWithEmptyLanguages() throws {
    let serializer = SSHTransportMessageSerializer()
    let parser = SSHTransportMessageParser()
    let message = try SSHTransportMessage.keyExchangeInit(
        SSHKeyExchangeInitMessage(
            cookie: Array(0x00...0x0f),
            keyExchangeAlgorithms: ["curve25519-sha256", "ecdh-sha2-nistp256"],
            serverHostKeyAlgorithms: ["ssh-ed25519", "rsa-sha2-512"],
            encryptionAlgorithmsClientToServer: ["aes128-ctr"],
            encryptionAlgorithmsServerToClient: ["aes128-ctr"],
            macAlgorithmsClientToServer: ["hmac-sha2-256"],
            macAlgorithmsServerToClient: ["hmac-sha2-256"],
            compressionAlgorithmsClientToServer: ["none"],
            compressionAlgorithmsServerToClient: ["none"],
            firstKeyExchangePacketFollows: true
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func transportMessageParserRoundTripsNewKeys() throws {
    let serializer = SSHTransportMessageSerializer()
    let parser = SSHTransportMessageParser()
    let message = SSHTransportMessage.newKeys(SSHNewKeysMessage())

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(bytes == [SSHTransportMessageID.newKeys.rawValue])
    #expect(decoded == message)
}

@Test
func transportMessageParserRoundTripsExtensionInfo() throws {
    let serializer = SSHTransportMessageSerializer()
    let parser = SSHTransportMessageParser()
    let message = SSHTransportMessage.extensionInfo(
        SSHExtensionInfoMessage(
            entries: [
                SSHExtensionInfoEntry(
                    name: "server-sig-algs",
                    value: Array("ssh-ed25519,rsa-sha2-512".utf8)
                ),
                SSHExtensionInfoEntry(
                    name: "publickey-hostbound@openssh.com",
                    value: Array("0".utf8)
                ),
            ]
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func transportMessageParserRoundTripsDebug() throws {
    let serializer = SSHTransportMessageSerializer()
    let parser = SSHTransportMessageParser()
    let message = SSHTransportMessage.debug(
        SSHDebugMessage(
            alwaysDisplay: false,
            message: "server debug",
            languageTag: "en-US"
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func transportMessageParserRoundTripsKeyExchangeECDHReply() throws {
    let serializer = SSHTransportMessageSerializer()
    let parser = SSHTransportMessageParser()
    let message = SSHTransportMessage.keyExchangeECDHReply(
        SSHKeyExchangeECDHReplyMessage(
            hostKey: [0x00, 0x01, 0x02],
            publicKey: Array(0x20...0x3f),
            signature: [0xaa, 0xbb, 0xcc]
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func transportMessageParserRejectsUnknownMessageType() throws {
    let parser = SSHTransportMessageParser()

    do {
        _ = try parser.parse([0xff])
        Issue.record("Expected unknown-message-type error")
    } catch {
        #expect(error as? SSHWireError == .unknownMessageType(0xff))
    }
}

@Test
func transportMessageParserRejectsTrailingBytes() throws {
    let serializer = SSHTransportMessageSerializer()
    let parser = SSHTransportMessageParser()
    let message = SSHTransportMessage.serviceAccept(
        SSHServiceAcceptMessage(serviceName: "ssh-userauth")
    )
    let bytes = try serializer.serialize(message) + [0x00]

    do {
        _ = try parser.parse(bytes)
        Issue.record("Expected trailing-message-bytes error")
    } catch {
        #expect(error as? SSHWireError == .trailingMessageBytes(1))
    }
}

@Test
func keyExchangeInitRejectsInvalidCookieLength() throws {
    do {
        _ = try SSHKeyExchangeInitMessage(
            cookie: [0x00, 0x01],
            keyExchangeAlgorithms: ["curve25519-sha256"],
            serverHostKeyAlgorithms: ["ssh-ed25519"],
            encryptionAlgorithmsClientToServer: ["aes128-ctr"],
            encryptionAlgorithmsServerToClient: ["aes128-ctr"],
            macAlgorithmsClientToServer: ["hmac-sha2-256"],
            macAlgorithmsServerToClient: ["hmac-sha2-256"],
            compressionAlgorithmsClientToServer: ["none"],
            compressionAlgorithmsServerToClient: ["none"]
        )
        Issue.record("Expected invalid-key-exchange-cookie-length error")
    } catch {
        #expect(error as? SSHWireError == .invalidKeyExchangeCookieLength(2))
    }
}

@Test
func keyExchangeInitRejectsEmptyRequiredNameList() throws {
    do {
        _ = try SSHKeyExchangeInitMessage(
            cookie: Array(0x00...0x0f),
            keyExchangeAlgorithms: [],
            serverHostKeyAlgorithms: ["ssh-ed25519"],
            encryptionAlgorithmsClientToServer: ["aes128-ctr"],
            encryptionAlgorithmsServerToClient: ["aes128-ctr"],
            macAlgorithmsClientToServer: ["hmac-sha2-256"],
            macAlgorithmsServerToClient: ["hmac-sha2-256"],
            compressionAlgorithmsClientToServer: ["none"],
            compressionAlgorithmsServerToClient: ["none"]
        )
        Issue.record("Expected empty-required-name-list error")
    } catch {
        #expect(error as? SSHWireError == .emptyRequiredNameList("kex_algorithms"))
    }
}
