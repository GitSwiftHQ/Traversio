// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func openSSHChaCha20Poly1305CryptorMatchesAsyncSSHVector() throws {
    let cryptor = try SSHChaChaPoly1305Cryptor(key: Array(0x00...0x3f))
    let packet: [UInt8] = [0x00, 0x00, 0x00, 0x0c, 0x06]
        + Array("hello".utf8)
        + [0x00, 0x00]

    let result = try cryptor.encrypt(packet: packet, sequenceNumber: 3)

    #expect(
        result.packet
            == [0xfb, 0x1a, 0x92, 0x86, 0x86, 0x2d, 0x79, 0xd7, 0x5e, 0x25, 0xa4, 0x71]
    )
    #expect(
        result.tag
            == [0x97, 0x3e, 0x30, 0x95, 0x5e, 0x7a, 0x81, 0xd0, 0x6d, 0x2f, 0x23, 0x76, 0xf7, 0x30, 0x69, 0x3f]
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecRoundTripsClientToServerPacket() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-ctr",
        encryptionAlgorithmServerToClient: "aes256-ctr",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-512",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )

    let bytes = try serializer.serialize(payload: [0x05, 0x00, 0x00, 0x00, 0x0c] + Array("ssh-userauth".utf8))
    parser.append(bytes: Array(bytes.prefix(11)))
    #expect(try parser.nextPacket() == nil)

    parser.append(bytes: Array(bytes.dropFirst(11)))
    let packet = try #require(try parser.nextPacket())

    #expect(
        packet.payload == [0x05, 0x00, 0x00, 0x00, 0x0c] + Array("ssh-userauth".utf8)
    )
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecRoundTripsPacketWithNonZeroSequenceNumber() throws {
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
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer,
        initialSequenceNumber: 3
    )

    let bytes = try serializer.serialize(payload: [0x15])
    parser.append(bytes: bytes)

    let packet = try #require(try parser.nextPacket())
    #expect(packet.payload == [0x15])
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecActivatesDelayedCompressionAfterAuthentication() throws {
    let payload = Array(repeating: UInt8(ascii: "z"), count: 512)
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-ctr",
        encryptionAlgorithmServerToClient: "aes128-ctr",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-256",
        compressionAlgorithmClientToServer: "zlib@openssh.com",
        compressionAlgorithmServerToClient: "zlib@openssh.com",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer,
        authenticationHasCompleted: false
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer,
        authenticationHasCompleted: false
    )

    let beforeAuthentication = try serializer.serialize(payload: payload)
    parser.append(bytes: beforeAuthentication)
    let beforeAuthenticationPacket = try #require(try parser.nextPacket())

    #expect(serializer.isCompressionActive == false)
    #expect(parser.isCompressionActive == false)
    #expect(beforeAuthenticationPacket.payload == payload)

    serializer.activateDelayedCompressionIfNeeded()
    parser.activateDelayedCompressionIfNeeded()

    #expect(serializer.isCompressionActive)
    #expect(parser.isCompressionActive)

    let afterAuthentication = try serializer.serialize(payload: payload)
    parser.append(bytes: afterAuthentication)
    let afterAuthenticationPacket = try #require(try parser.nextPacket())

    #expect(afterAuthenticationPacket.payload == payload)
    #expect(afterAuthentication.count < beforeAuthentication.count)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecUsesPlainZlibImmediatelyAfterKeyExchange() throws {
    let payload = Array(repeating: UInt8(ascii: "z"), count: 512)
    let compressedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-ctr",
        encryptionAlgorithmServerToClient: "aes128-ctr",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-256",
        compressionAlgorithmClientToServer: "zlib",
        compressionAlgorithmServerToClient: "zlib",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let uncompressedAlgorithms = SSHNegotiatedAlgorithms(
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
    let compressedKeyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: compressedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    let uncompressedKeyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: uncompressedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var compressedSerializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: compressedAlgorithms,
        keyMaterial: compressedKeyMaterial,
        direction: .clientToServer,
        authenticationHasCompleted: false
    )
    var compressedParser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: compressedAlgorithms,
        keyMaterial: compressedKeyMaterial,
        direction: .clientToServer,
        authenticationHasCompleted: false
    )
    var uncompressedSerializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: uncompressedAlgorithms,
        keyMaterial: uncompressedKeyMaterial,
        direction: .clientToServer
    )

    #expect(compressedSerializer.isCompressionActive)
    #expect(compressedParser.isCompressionActive)

    let compressedBytes = try compressedSerializer.serialize(payload: payload)
    let uncompressedBytes = try uncompressedSerializer.serialize(payload: payload)

    compressedParser.append(bytes: compressedBytes)
    let packet = try #require(try compressedParser.nextPacket())

    #expect(packet.payload == payload)
    #expect(compressedBytes.count < uncompressedBytes.count)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecRoundTripsOpenSSHUMACPacket() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-ctr",
        encryptionAlgorithmServerToClient: "aes256-ctr",
        macAlgorithmClientToServer: "umac-64@openssh.com",
        macAlgorithmServerToClient: "umac-128@openssh.com",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )

    let payload = [0x05, 0x00, 0x00, 0x00, 0x0c] + Array("ssh-userauth".utf8)
    let bytes = try serializer.serialize(payload: payload)

    parser.append(bytes: Array(bytes.prefix(9)))
    #expect(try parser.nextPacket() == nil)

    parser.append(bytes: Array(bytes.dropFirst(9)))
    let packet = try #require(try parser.nextPacket())

    #expect(packet.payload == payload)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecRoundTripsOpenSSHUMACEncryptThenMacPacket() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-ctr",
        encryptionAlgorithmServerToClient: "aes256-ctr",
        macAlgorithmClientToServer: "umac-64-etm@openssh.com",
        macAlgorithmServerToClient: "umac-128-etm@openssh.com",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )

    let payload: [UInt8] = [0x15]
    let bytes = try serializer.serialize(payload: payload)

    parser.append(bytes: Array(bytes.prefix(4)))
    #expect(try parser.nextPacket() == nil)

    parser.append(bytes: Array(bytes.dropFirst(4)))
    let packet = try #require(try parser.nextPacket())

    #expect(packet.payload == payload)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecRoundTripsOpenSSHAESGCMPacket() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-gcm@openssh.com",
        encryptionAlgorithmServerToClient: "aes256-gcm@openssh.com",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-512",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )

    let payload = [0x05, 0x00, 0x00, 0x00, 0x0c] + Array("ssh-userauth".utf8)
    let bytes = try serializer.serialize(payload: payload)
    let clearPacket = try SSHBinaryPacketSerializer(
        blockSize: 16,
        alignmentExcludedByteCount: 4
    ).serialize(payload: payload)

    #expect(Array(bytes.prefix(4)) == Array(clearPacket.prefix(4)))

    parser.append(bytes: Array(bytes.prefix(5)))
    #expect(try parser.nextPacket() == nil)

    parser.append(bytes: Array(bytes.dropFirst(5)))
    let packet = try #require(try parser.nextPacket())

    #expect(packet.payload == payload)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecRoundTripsOpenSSHChaCha20Poly1305Packet() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "chacha20-poly1305@openssh.com",
        encryptionAlgorithmServerToClient: "chacha20-poly1305@openssh.com",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-512",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )

    let payload = [0x05, 0x00, 0x00, 0x00, 0x0c] + Array("ssh-userauth".utf8)
    let bytes = try serializer.serialize(payload: payload)

    parser.append(bytes: Array(bytes.prefix(4)))
    #expect(try parser.nextPacket() == nil)

    parser.append(bytes: Array(bytes.dropFirst(4)))
    let packet = try #require(try parser.nextPacket())

    #expect(packet.payload == payload)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecRoundTripsShortOpenSSHChaCha20Poly1305Packet() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "chacha20-poly1305@openssh.com",
        encryptionAlgorithmServerToClient: "chacha20-poly1305@openssh.com",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-512",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .serverToClient
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .serverToClient
    )

    let bytes = try serializer.serialize(payload: [0x34])

    #expect(bytes.count == 28)

    parser.append(bytes: Array(bytes.prefix(4)))
    #expect(try parser.nextPacket() == nil)

    parser.append(bytes: Array(bytes.dropFirst(4)))
    let packet = try #require(try parser.nextPacket())

    #expect(packet.payload == [0x34])
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecRejectsTamperedMAC() throws {
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
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .serverToClient
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .serverToClient
    )
    var bytes = try serializer.serialize(payload: [0x06, 0x00, 0x00, 0x00, 0x0c] + Array("ssh-userauth".utf8))
    bytes[bytes.count - 1] ^= 0xff
    parser.append(bytes: bytes)

    do {
        _ = try parser.nextPacket()
        Issue.record("Expected invalid-MAC error")
    } catch {
        #expect(error as? SSHEncryptedBinaryPacketError == .invalidMAC)
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecRejectsTamperedOpenSSHAESGCMPacket() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-gcm@openssh.com",
        encryptionAlgorithmServerToClient: "aes128-gcm@openssh.com",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-256",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .serverToClient
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .serverToClient
    )
    var bytes = try serializer.serialize(payload: [0x06, 0x00, 0x00, 0x00, 0x0c] + Array("ssh-userauth".utf8))
    bytes[6] ^= 0xff
    parser.append(bytes: bytes)

    do {
        _ = try parser.nextPacket()
        Issue.record("Expected invalid-MAC error")
    } catch {
        #expect(error as? SSHEncryptedBinaryPacketError == .invalidMAC)
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecRejectsTamperedOpenSSHChaCha20Poly1305Packet() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "chacha20-poly1305@openssh.com",
        encryptionAlgorithmServerToClient: "chacha20-poly1305@openssh.com",
        macAlgorithmClientToServer: "hmac-sha2-256",
        macAlgorithmServerToClient: "hmac-sha2-512",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .serverToClient
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .serverToClient
    )
    var bytes = try serializer.serialize(payload: [0x06, 0x00, 0x00, 0x00, 0x0c] + Array("ssh-userauth".utf8))
    bytes[bytes.count - 1] ^= 0xff
    parser.append(bytes: bytes)

    do {
        _ = try parser.nextPacket()
        Issue.record("Expected invalid-MAC error")
    } catch {
        #expect(error as? SSHEncryptedBinaryPacketError == .invalidMAC)
    }
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecConsumesSequentialPacketsWithSharedCipherState() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes256-ctr",
        encryptionAlgorithmServerToClient: "aes256-ctr",
        macAlgorithmClientToServer: "hmac-sha2-512",
        macAlgorithmServerToClient: "hmac-sha2-512",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )

    let firstBytes = try serializer.serialize(payload: [0x15])
    let secondBytes = try serializer.serialize(payload: [0x06, 0x00, 0x00, 0x00, 0x04] + Array("test".utf8))
    parser.append(bytes: firstBytes + secondBytes)

    let firstPacket = try #require(try parser.nextPacket())
    let secondPacket = try #require(try parser.nextPacket())

    #expect(firstPacket.payload == [0x15])
    #expect(secondPacket.payload == [0x06, 0x00, 0x00, 0x00, 0x04] + Array("test".utf8))
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecRoundTripsOpenSSHEncryptThenMacPacket() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-ctr",
        encryptionAlgorithmServerToClient: "aes256-ctr",
        macAlgorithmClientToServer: "hmac-sha2-256-etm@openssh.com",
        macAlgorithmServerToClient: "hmac-sha2-512-etm@openssh.com",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .clientToServer
    )

    let payload = [0x05, 0x00, 0x00, 0x00, 0x0c] + Array("ssh-userauth".utf8)
    let bytes = try serializer.serialize(payload: payload)
    let clearPacket = try SSHBinaryPacketSerializer(
        blockSize: 16,
        alignmentExcludedByteCount: 4
    ).serialize(payload: payload)

    #expect(Array(bytes.prefix(4)) == Array(clearPacket.prefix(4)))

    parser.append(bytes: Array(bytes.prefix(3)))
    #expect(try parser.nextPacket() == nil)

    parser.append(bytes: Array(bytes.dropFirst(3)))
    let packet = try #require(try parser.nextPacket())

    #expect(packet.payload == payload)
}

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func encryptedPacketCodecRejectsTamperedEncryptThenMacCiphertext() throws {
    let negotiatedAlgorithms = SSHNegotiatedAlgorithms(
        keyExchangeAlgorithm: "curve25519-sha256",
        serverHostKeyAlgorithm: "ssh-ed25519",
        encryptionAlgorithmClientToServer: "aes128-ctr",
        encryptionAlgorithmServerToClient: "aes128-ctr",
        macAlgorithmClientToServer: "hmac-sha2-256-etm@openssh.com",
        macAlgorithmServerToClient: "hmac-sha2-256-etm@openssh.com",
        compressionAlgorithmClientToServer: "none",
        compressionAlgorithmServerToClient: "none",
        languageClientToServer: nil,
        languageServerToClient: nil
    )
    let keyMaterial = try SSHTransportKeyDeriver().deriveKeys(
        negotiatedAlgorithms: negotiatedAlgorithms,
        sharedSecret: SSHMPInt(unsignedMagnitude: Array(0x01...0x20)),
        exchangeHash: (0xa0...0xbf).map(UInt8.init),
        sessionIdentifier: (0xc0...0xdf).map(UInt8.init)
    )
    var serializer = try SSHOutboundEncryptedPacketSerializer(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .serverToClient
    )
    var parser = try SSHInboundEncryptedPacketParser(
        negotiatedAlgorithms: negotiatedAlgorithms,
        keyMaterial: keyMaterial,
        direction: .serverToClient
    )
    var bytes = try serializer.serialize(payload: [0x06, 0x00, 0x00, 0x00, 0x0c] + Array("ssh-userauth".utf8))
    bytes[6] ^= 0xff
    parser.append(bytes: bytes)

    do {
        _ = try parser.nextPacket()
        Issue.record("Expected invalid-MAC error")
    } catch {
        #expect(error as? SSHEncryptedBinaryPacketError == .invalidMAC)
    }
}
