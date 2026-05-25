// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

struct SSHUserAuthenticationMessageSerializer: Sendable {
    func serialize(_ message: SSHUserAuthenticationMessage) throws -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(byte: message.messageID.rawValue)

        switch message {
        case let .request(payload):
            writer.write(utf8: payload.username)
            writer.write(utf8: payload.serviceName)
            writer.write(utf8: payload.method.methodName)

            switch payload.method {
            case .none:
                break
            case let .password(request):
                writer.write(boolean: request.isPasswordChange)
                writer.write(utf8: request.oldPassword)
                if let newPassword = request.newPassword {
                    writer.write(utf8: newPassword)
                }
            case let .publicKey(request):
                writer.write(boolean: request.hasSignature)
                writer.write(utf8: request.algorithmName)
                writer.write(string: request.publicKey)
                if let signature = request.signature {
                    writer.write(string: signature)
                }
            case let .keyboardInteractive(request):
                writer.write(utf8: request.languageTag)
                writer.write(utf8: Self.serializeKeyboardInteractiveSubmethods(request.submethods))
            }
        case let .failure(payload):
            try writer.write(nameList: payload.authenticationsThatCanContinue)
            writer.write(boolean: payload.partialSuccess)
        case .success:
            break
        case let .banner(payload):
            writer.write(utf8: payload.message)
            writer.write(utf8: payload.languageTag)
        case let .passwordChangeRequest(payload):
            writer.write(utf8: payload.prompt)
            writer.write(utf8: payload.languageTag)
        }

        return writer.bytes
    }

    func serializePublicKeyOK(_ message: SSHPublicKeyAuthenticationOKMessage) -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(byte: SSHUserAuthenticationMessageID.passwordChangeRequest.rawValue)
        writer.write(utf8: message.algorithmName)
        writer.write(string: message.publicKey)
        return writer.bytes
    }

    func serializeKeyboardInteractiveInfoRequest(
        _ message: SSHKeyboardInteractiveInformationRequestMessage
    ) -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(byte: SSHUserAuthenticationMessageID.passwordChangeRequest.rawValue)
        writer.write(utf8: message.name)
        writer.write(utf8: message.instruction)
        writer.write(utf8: message.languageTag)
        writer.write(uint32: UInt32(message.prompts.count))
        for prompt in message.prompts {
            writer.write(utf8: prompt.prompt)
            writer.write(boolean: prompt.shouldEcho)
        }
        return writer.bytes
    }

    func serializeKeyboardInteractiveInfoResponse(
        _ message: SSHKeyboardInteractiveInformationResponseMessage
    ) -> [UInt8] {
        var writer = SSHWireWriter()
        writer.write(byte: 61)
        writer.write(uint32: UInt32(message.responses.count))
        for response in message.responses {
            writer.write(utf8: response)
        }
        return writer.bytes
    }

    private static func serializeKeyboardInteractiveSubmethods(_ submethods: [String]) -> String {
        submethods.joined(separator: ",")
    }
}

struct SSHUserAuthenticationMessageParser: Sendable {
    func parse(_ bytes: [UInt8]) throws -> SSHUserAuthenticationMessage {
        var reader = SSHWireReader(bytes: bytes)
        let rawMessageType = try reader.readByte()

        guard let messageID = SSHUserAuthenticationMessageID(rawValue: rawMessageType) else {
            throw SSHWireError.unknownMessageType(rawMessageType)
        }

        let message: SSHUserAuthenticationMessage
        switch messageID {
        case .request:
            let username = try reader.readUTF8String()
            let serviceName = try reader.readUTF8String()
            let methodName = try reader.readUTF8String()

            let method: SSHUserAuthenticationRequestMethod
            switch methodName {
            case "none":
                method = .none
            case "password":
                let isPasswordChange = try reader.readBoolean()
                let oldPassword = try reader.readUTF8String()
                if isPasswordChange {
                    method = .password(
                        SSHPasswordAuthenticationRequest(
                            oldPassword: oldPassword,
                            newPassword: try reader.readUTF8String()
                        )
                    )
                } else {
                    method = .password(
                        SSHPasswordAuthenticationRequest(password: oldPassword)
                    )
                }
            case "publickey":
                let hasSignature = try reader.readBoolean()
                let algorithmName = try reader.readUTF8String()
                let publicKey = try reader.readString()
                let signature = hasSignature ? try reader.readString() : nil
                method = .publicKey(
                    SSHPublicKeyAuthenticationRequest(
                        algorithmName: algorithmName,
                        publicKey: publicKey,
                        signature: signature
                    )
                )
            case "keyboard-interactive":
                method = .keyboardInteractive(
                    SSHKeyboardInteractiveAuthenticationRequest(
                        languageTag: try reader.readUTF8String(),
                        submethods: try Self.parseKeyboardInteractiveSubmethods(
                            reader.readUTF8String()
                        )
                    )
                )
            default:
                throw SSHUserAuthenticationMessageError.unsupportedAuthenticationMethod(methodName)
            }

            message = .request(
                SSHUserAuthenticationRequestMessage(
                    username: username,
                    serviceName: serviceName,
                    method: method
                )
            )
        case .failure:
            message = try .failure(
                SSHUserAuthenticationFailureMessage(
                    authenticationsThatCanContinue: reader.readNameList(),
                    partialSuccess: reader.readBoolean()
                )
            )
        case .success:
            message = .success(SSHUserAuthenticationSuccessMessage())
        case .banner:
            message = try .banner(
                SSHUserAuthenticationBannerMessage(
                    message: reader.readUTF8String(),
                    languageTag: reader.readUTF8String()
                )
            )
        case .passwordChangeRequest:
            message = try .passwordChangeRequest(
                SSHUserAuthenticationPasswordChangeRequestMessage(
                    prompt: reader.readUTF8String(),
                    languageTag: reader.readUTF8String()
                )
            )
        }

        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }

        return message
    }

    func parsePublicKeyOK(_ bytes: [UInt8]) throws -> SSHPublicKeyAuthenticationOKMessage {
        var reader = SSHWireReader(bytes: bytes)
        let rawMessageType = try reader.readByte()

        guard rawMessageType == SSHUserAuthenticationMessageID.passwordChangeRequest.rawValue else {
            throw SSHUserAuthenticationMessageError.unexpectedMethodSpecificMessageID(
                expected: SSHUserAuthenticationMessageID.passwordChangeRequest.rawValue,
                received: rawMessageType
            )
        }

        let message = try SSHPublicKeyAuthenticationOKMessage(
            algorithmName: reader.readUTF8String(),
            publicKey: reader.readString()
        )

        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }

        return message
    }

    func parseKeyboardInteractiveInfoRequest(
        _ bytes: [UInt8]
    ) throws -> SSHKeyboardInteractiveInformationRequestMessage {
        var reader = SSHWireReader(bytes: bytes)
        let rawMessageType = try reader.readByte()

        guard rawMessageType == SSHUserAuthenticationMessageID.passwordChangeRequest.rawValue else {
            throw SSHUserAuthenticationMessageError.unexpectedMethodSpecificMessageID(
                expected: SSHUserAuthenticationMessageID.passwordChangeRequest.rawValue,
                received: rawMessageType
            )
        }

        let name = try reader.readUTF8String()
        let instruction = try reader.readUTF8String()
        let languageTag = try reader.readUTF8String()
        let promptCount = try Int(reader.readUInt32())
        var prompts: [SSHKeyboardInteractivePromptMessage] = []
        prompts.reserveCapacity(promptCount)

        for _ in 0..<promptCount {
            prompts.append(
                SSHKeyboardInteractivePromptMessage(
                    prompt: try reader.readUTF8String(),
                    shouldEcho: try reader.readBoolean()
                )
            )
        }

        let message = SSHKeyboardInteractiveInformationRequestMessage(
            name: name,
            instruction: instruction,
            languageTag: languageTag,
            prompts: prompts
        )

        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }

        return message
    }

    func parseKeyboardInteractiveInfoResponse(
        _ bytes: [UInt8]
    ) throws -> SSHKeyboardInteractiveInformationResponseMessage {
        var reader = SSHWireReader(bytes: bytes)
        let rawMessageType = try reader.readByte()

        guard rawMessageType == 61 else {
            throw SSHUserAuthenticationMessageError.unexpectedMethodSpecificMessageID(
                expected: 61,
                received: rawMessageType
            )
        }

        let responseCount = try Int(reader.readUInt32())
        var responses: [String] = []
        responses.reserveCapacity(responseCount)

        for _ in 0..<responseCount {
            responses.append(try reader.readUTF8String())
        }

        let message = SSHKeyboardInteractiveInformationResponseMessage(responses: responses)

        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }

        return message
    }

    func parsePasswordChangeRequest(
        _ bytes: [UInt8]
    ) throws -> SSHUserAuthenticationPasswordChangeRequestMessage {
        var reader = SSHWireReader(bytes: bytes)
        let rawMessageType = try reader.readByte()

        guard rawMessageType == SSHUserAuthenticationMessageID.passwordChangeRequest.rawValue else {
            throw SSHUserAuthenticationMessageError.unexpectedMethodSpecificMessageID(
                expected: SSHUserAuthenticationMessageID.passwordChangeRequest.rawValue,
                received: rawMessageType
            )
        }

        let message = try SSHUserAuthenticationPasswordChangeRequestMessage(
            prompt: reader.readUTF8String(),
            languageTag: reader.readUTF8String()
        )

        guard reader.isAtEnd else {
            throw SSHWireError.trailingMessageBytes(reader.remainingByteCount)
        }

        return message
    }

    private static func parseKeyboardInteractiveSubmethods(_ value: String) throws -> [String] {
        guard !value.isEmpty else {
            return []
        }

        let submethods = value.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard !submethods.contains(where: \.isEmpty) else {
            throw SSHWireError.invalidNameList
        }
        return submethods
    }
}
