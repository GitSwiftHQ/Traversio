// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
@Test
func userAuthenticationMessageSerializerSerializesPasswordRequest() throws {
    let serializer = SSHUserAuthenticationMessageSerializer()

    let bytes = try serializer.serialize(
        .request(
            SSHUserAuthenticationRequestMessage(
                username: "root",
                serviceName: "ssh-connection",
                method: .password(SSHPasswordAuthenticationRequest(password: "s3cr3t"))
            )
        )
    )

    #expect(
        bytes == [
            0x32,
            0x00, 0x00, 0x00, 0x04,
            0x72, 0x6f, 0x6f, 0x74,
            0x00, 0x00, 0x00, 0x0e,
            0x73, 0x73, 0x68, 0x2d, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
            0x00, 0x00, 0x00, 0x08,
            0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
            0x00,
            0x00, 0x00, 0x00, 0x06,
            0x73, 0x33, 0x63, 0x72, 0x33, 0x74,
        ]
    )
}

@Test
func userAuthenticationMessageParserRoundTripsPasswordChangeRequest() throws {
    let serializer = SSHUserAuthenticationMessageSerializer()
    let parser = SSHUserAuthenticationMessageParser()
    let message = SSHUserAuthenticationMessage.request(
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

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func userAuthenticationMessageParserRoundTripsPublicKeyRequest() throws {
    let serializer = SSHUserAuthenticationMessageSerializer()
    let parser = SSHUserAuthenticationMessageParser()
    let message = SSHUserAuthenticationMessage.request(
        SSHUserAuthenticationRequestMessage(
            username: "root",
            serviceName: "ssh-connection",
            method: .publicKey(
                SSHPublicKeyAuthenticationRequest(
                    algorithmName: "ssh-ed25519",
                    publicKey: [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8) + [
                        0x00, 0x00, 0x00, 0x20
                    ] + Array(0x01...0x20),
                    signature: [0x00, 0x00, 0x00, 0x0b] + Array("ssh-ed25519".utf8) + [
                        0x00, 0x00, 0x00, 0x40
                    ] + Array(repeating: 0xaa, count: 64)
                )
            )
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func userAuthenticationMessageParserRoundTripsKeyboardInteractiveRequest() throws {
    let serializer = SSHUserAuthenticationMessageSerializer()
    let parser = SSHUserAuthenticationMessageParser()
    let message = SSHUserAuthenticationMessage.request(
        SSHUserAuthenticationRequestMessage(
            username: "root",
            serviceName: "ssh-connection",
            method: .keyboardInteractive(
                SSHKeyboardInteractiveAuthenticationRequest(
                    languageTag: "",
                    submethods: ["pam", "otp"]
                )
            )
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func userAuthenticationRequestBuildsPublicKeySignatureData() throws {
    let request = SSHUserAuthenticationRequestMessage(
        username: "root",
        serviceName: "ssh-connection",
        method: .publicKey(
            SSHPublicKeyAuthenticationRequest(
                algorithmName: "ssh-ed25519",
                publicKey: [0xaa, 0xbb, 0xcc],
                signature: nil
            )
        )
    )

    let bytes = try request.publicKeySignatureData(
        sessionIdentifier: [0x10, 0x20, 0x30, 0x40]
    )

    #expect(
        bytes == [
            0x00, 0x00, 0x00, 0x04,
            0x10, 0x20, 0x30, 0x40,
            0x32,
            0x00, 0x00, 0x00, 0x04,
            0x72, 0x6f, 0x6f, 0x74,
            0x00, 0x00, 0x00, 0x0e,
            0x73, 0x73, 0x68, 0x2d, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
            0x00, 0x00, 0x00, 0x09,
            0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x6b, 0x65, 0x79,
            0x01,
            0x00, 0x00, 0x00, 0x0b,
            0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39,
            0x00, 0x00, 0x00, 0x03,
            0xaa, 0xbb, 0xcc,
        ]
    )
}

@Test
func userAuthenticationRequestRejectsPublicKeySignatureDataForNonPublicKeyMethod() throws {
    let request = SSHUserAuthenticationRequestMessage(
        username: "root",
        serviceName: "ssh-connection",
        method: .password(SSHPasswordAuthenticationRequest(password: "s3cr3t"))
    )

    do {
        _ = try request.publicKeySignatureData(sessionIdentifier: [0x10, 0x20])
        Issue.record("Expected public-key-signature-data-requires-public-key-method error")
    } catch {
        #expect(
            error as? SSHUserAuthenticationMessageError
                == .publicKeySignatureDataRequiresPublicKeyMethod
        )
    }
}

@Test
func userAuthenticationMessageParserRoundTripsPublicKeyOK() throws {
    let serializer = SSHUserAuthenticationMessageSerializer()
    let message = SSHPublicKeyAuthenticationOKMessage(
        algorithmName: "ssh-ed25519",
        publicKey: [0xaa, 0xbb, 0xcc]
    )

    let bytes = serializer.serializePublicKeyOK(message)
    let decoded = try SSHUserAuthenticationMessageParser().parsePublicKeyOK(bytes)

    #expect(decoded == message)
}

@Test
func userAuthenticationMessageParserRoundTripsKeyboardInteractiveInfoRequest() throws {
    let serializer = SSHUserAuthenticationMessageSerializer()
    let message = SSHKeyboardInteractiveInformationRequestMessage(
        name: "Password Authentication",
        instruction: "Enter your password",
        languageTag: "en-US",
        prompts: [
            SSHKeyboardInteractivePromptMessage(
                prompt: "Password: ",
                shouldEcho: false
            ),
            SSHKeyboardInteractivePromptMessage(
                prompt: "OTP: ",
                shouldEcho: true
            ),
        ]
    )

    let bytes = serializer.serializeKeyboardInteractiveInfoRequest(message)
    let decoded = try SSHUserAuthenticationMessageParser().parseKeyboardInteractiveInfoRequest(bytes)

    #expect(decoded == message)
}

@Test
func userAuthenticationMessageParserRoundTripsKeyboardInteractiveInfoResponse() throws {
    let serializer = SSHUserAuthenticationMessageSerializer()
    let message = SSHKeyboardInteractiveInformationResponseMessage(
        responses: ["s3cr3t", "123456"]
    )

    let bytes = serializer.serializeKeyboardInteractiveInfoResponse(message)
    let decoded = try SSHUserAuthenticationMessageParser().parseKeyboardInteractiveInfoResponse(bytes)

    #expect(decoded == message)
}

@Test
func userAuthenticationMessageParserRoundTripsFailure() throws {
    let serializer = SSHUserAuthenticationMessageSerializer()
    let parser = SSHUserAuthenticationMessageParser()
    let message = SSHUserAuthenticationMessage.failure(
        SSHUserAuthenticationFailureMessage(
            authenticationsThatCanContinue: ["publickey", "password"],
            partialSuccess: false
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func userAuthenticationMessageParserParsesPasswordChangeRequest() throws {
    let serializer = SSHUserAuthenticationMessageSerializer()
    let message = SSHUserAuthenticationMessage.passwordChangeRequest(
        SSHUserAuthenticationPasswordChangeRequestMessage(
            prompt: "Password expired",
            languageTag: "en-AU"
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try SSHUserAuthenticationMessageParser().parsePasswordChangeRequest(bytes)

    #expect(
        decoded
            == SSHUserAuthenticationPasswordChangeRequestMessage(
                prompt: "Password expired",
                languageTag: "en-AU"
            )
    )
}

@Test
func userAuthenticationMessageParserRejectsUnsupportedRequestMethod() throws {
    var writer = SSHWireWriter()
    writer.write(byte: SSHUserAuthenticationMessageID.request.rawValue)
    writer.write(utf8: "root")
    writer.write(utf8: "ssh-connection")
    writer.write(utf8: "otp")

    do {
        _ = try SSHUserAuthenticationMessageParser().parse(writer.bytes)
        Issue.record("Expected unsupported-authentication-method error")
    } catch {
        #expect(
            error as? SSHUserAuthenticationMessageError
                == .unsupportedAuthenticationMethod("otp")
        )
    }
}
