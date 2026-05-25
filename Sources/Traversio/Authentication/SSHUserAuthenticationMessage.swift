// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package enum SSHUserAuthenticationMessageID: UInt8, Equatable, Sendable {
    case request = 50
    case failure = 51
    case success = 52
    case banner = 53
    case passwordChangeRequest = 60
}

enum SSHUserAuthenticationMessageError: Error, Equatable, Sendable {
    case unsupportedAuthenticationMethod(String)
    case publicKeySignatureDataRequiresPublicKeyMethod
    case unexpectedMethodSpecificMessageID(expected: UInt8, received: UInt8)
}

enum SSHUserAuthenticationError: Error, Equatable, Sendable {
    case confidentialTransportRequired
    case sessionIdentifierRequired
    case publicKeyConfirmationMismatch
    case unexpectedServiceAccept(expected: String, received: String)
    case unexpectedTransportMessage(SSHTransportMessageID)
    case unexpectedAuthenticationMessage(SSHUserAuthenticationMessageID)
    case unexpectedPostAuthenticationMessage(UInt8)
}

struct SSHPasswordAuthenticationRequest: Equatable, Sendable {
    let oldPassword: String
    let newPassword: String?

    init(password: String) {
        self.oldPassword = password
        self.newPassword = nil
    }

    init(oldPassword: String, newPassword: String) {
        self.oldPassword = oldPassword
        self.newPassword = newPassword
    }

    var isPasswordChange: Bool {
        self.newPassword != nil
    }
}

package struct SSHPublicKeyAuthenticationRequest: Equatable, Sendable {
    package let algorithmName: String
    package let publicKey: [UInt8]
    package let signature: [UInt8]?

    package var hasSignature: Bool {
        self.signature != nil
    }

    package func withSignature(_ signature: [UInt8]) -> SSHPublicKeyAuthenticationRequest {
        SSHPublicKeyAuthenticationRequest(
            algorithmName: self.algorithmName,
            publicKey: self.publicKey,
            signature: signature
        )
    }
}

struct SSHPublicKeyAuthenticationOKMessage: Equatable, Sendable {
    let algorithmName: String
    let publicKey: [UInt8]
}

struct SSHKeyboardInteractiveAuthenticationRequest: Equatable, Sendable {
    let languageTag: String
    let submethods: [String]
}

struct SSHKeyboardInteractivePromptMessage: Equatable, Sendable {
    let prompt: String
    let shouldEcho: Bool
}

struct SSHKeyboardInteractiveInformationRequestMessage: Equatable, Sendable {
    let name: String
    let instruction: String
    let languageTag: String
    let prompts: [SSHKeyboardInteractivePromptMessage]
}

struct SSHKeyboardInteractiveInformationResponseMessage: Equatable, Sendable {
    let responses: [String]
}

enum SSHUserAuthenticationRequestMethod: Equatable, Sendable {
    case none
    case password(SSHPasswordAuthenticationRequest)
    case publicKey(SSHPublicKeyAuthenticationRequest)
    case keyboardInteractive(SSHKeyboardInteractiveAuthenticationRequest)

    var methodName: String {
        switch self {
        case .none:
            return "none"
        case .password:
            return "password"
        case .publicKey:
            return "publickey"
        case .keyboardInteractive:
            return "keyboard-interactive"
        }
    }
}

struct SSHUserAuthenticationRequestMessage: Equatable, Sendable {
    let username: String
    let serviceName: String
    let method: SSHUserAuthenticationRequestMethod
}

package struct SSHUserAuthenticationFailureMessage: Equatable, Sendable {
    package let authenticationsThatCanContinue: [String]
    package let partialSuccess: Bool
}

package struct SSHUserAuthenticationSuccessMessage: Equatable, Sendable {
    package init() {}
}

package struct SSHUserAuthenticationBannerMessage: Equatable, Sendable {
    package let message: String
    package let languageTag: String
}

package struct SSHUserAuthenticationPasswordChangeRequestMessage: Equatable, Sendable {
    package let prompt: String
    package let languageTag: String
}

enum SSHUserAuthenticationMessage: Equatable, Sendable {
    case request(SSHUserAuthenticationRequestMessage)
    case failure(SSHUserAuthenticationFailureMessage)
    case success(SSHUserAuthenticationSuccessMessage)
    case banner(SSHUserAuthenticationBannerMessage)
    case passwordChangeRequest(SSHUserAuthenticationPasswordChangeRequestMessage)

    var messageID: SSHUserAuthenticationMessageID {
        switch self {
        case .request:
            return .request
        case .failure:
            return .failure
        case .success:
            return .success
        case .banner:
            return .banner
        case .passwordChangeRequest:
            return .passwordChangeRequest
        }
    }
}

package struct SSHPasswordAuthenticationResult: Equatable, Sendable {
    package let username: String
    package let serviceName: String
    package let banners: [SSHUserAuthenticationBannerMessage]
    package let outcome: SSHPasswordAuthenticationOutcome
}

package enum SSHPasswordAuthenticationOutcome: Equatable, Sendable {
    case success(SSHUserAuthenticationSuccessMessage)
    case failure(SSHUserAuthenticationFailureMessage)
    case passwordChangeRequired(SSHUserAuthenticationPasswordChangeRequestMessage)
}

package struct SSHPublicKeyAuthenticationResult: Equatable, Sendable {
    package let username: String
    package let serviceName: String
    package let algorithmName: String
    package let banners: [SSHUserAuthenticationBannerMessage]
    package let outcome: SSHPublicKeyAuthenticationOutcome
}

package enum SSHPublicKeyAuthenticationOutcome: Equatable, Sendable {
    case success(SSHUserAuthenticationSuccessMessage)
    case failure(SSHUserAuthenticationFailureMessage)
}

package struct SSHKeyboardInteractiveAuthenticationResult: Equatable, Sendable {
    package let username: String
    package let serviceName: String
    package let submethods: [String]
    package let banners: [SSHUserAuthenticationBannerMessage]
    package let outcome: SSHKeyboardInteractiveAuthenticationOutcome
}

package enum SSHKeyboardInteractiveAuthenticationOutcome: Equatable, Sendable {
    case success(SSHUserAuthenticationSuccessMessage)
    case failure(SSHUserAuthenticationFailureMessage)
}

extension SSHUserAuthenticationRequestMessage {
    func publicKeySignatureData(sessionIdentifier: [UInt8]) throws -> [UInt8] {
        guard case let .publicKey(request) = self.method else {
            throw SSHUserAuthenticationMessageError.publicKeySignatureDataRequiresPublicKeyMethod
        }

        var writer = SSHWireWriter()
        writer.write(string: sessionIdentifier)
        writer.write(byte: SSHUserAuthenticationMessageID.request.rawValue)
        writer.write(utf8: self.username)
        writer.write(utf8: self.serviceName)
        writer.write(utf8: self.method.methodName)
        writer.write(boolean: true)
        writer.write(utf8: request.algorithmName)
        writer.write(string: request.publicKey)
        return writer.bytes
    }
}
