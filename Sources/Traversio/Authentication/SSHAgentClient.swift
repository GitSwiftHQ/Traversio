// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Darwin
import Foundation

/// One public key identity advertised by an SSH agent.
public struct SSHAgentIdentity: Equatable, Sendable {
    /// SSH public key bytes.
    public let publicKey: [UInt8]
    /// OpenSSH key comment.
    public let comment: String
    /// SSH key type name.
    public let keyType: String
    /// Authentication signature algorithms supported for this identity.
    public let supportedAuthenticationAlgorithmNames: [String]
    /// Creates an SSHAgentIdentity.

    public init(
        publicKey: [UInt8],
        comment: String,
        keyType: String,
        supportedAuthenticationAlgorithmNames: [String]
    ) {
        self.publicKey = publicKey
        self.comment = comment
        self.keyType = keyType
        self.supportedAuthenticationAlgorithmNames = supportedAuthenticationAlgorithmNames
    }
}

/// Errors raised while talking to an SSH agent socket.
public enum SSHAgentClientError: Error, Equatable, Sendable {
    /// Missing Socket Path.
    case missingSocketPath
    /// Invalid Socket Path.
    case invalidSocketPath
    /// Socket Operation Failed.
    case socketOperationFailed(String)
    /// Invalid Message Length.
    case invalidMessageLength(UInt32)
    /// Agent Failure.
    case agentFailure
    /// Unexpected Message.
    case unexpectedMessage(expected: UInt8, received: UInt8)
    /// Trailing Message Bytes.
    case trailingMessageBytes(Int)
    /// Invalid Identity public key.
    case invalidIdentityPublicKey
}

/// Minimal SSH agent client for listing identities and signing auth requests.
///
/// By default the client uses `SSH_AUTH_SOCK`. Pass `socketPath` to target a
/// specific agent.
///
/// Example:
///
/// ```swift
/// let agent = try SSHAgentClient()
/// let identity = try await agent.identities().first!
/// let auth = agent.authenticationMethod(for: identity)
/// ```
public actor SSHAgentClient {
    private static let maximumMessageLength: UInt32 = 256 * 1024
    private static let requestIdentitiesMessageID: UInt8 = 11
    private static let identitiesAnswerMessageID: UInt8 = 12
    private static let signRequestMessageID: UInt8 = 13
    private static let signResponseMessageID: UInt8 = 14
    private static let failureMessageID: UInt8 = 5
    private static let rsaSHA256AgentFlag: UInt32 = 2
    private static let rsaSHA512AgentFlag: UInt32 = 4

    private let socketPath: String

    /// Creates an SSHAgentClient.
    public init(socketPath: String? = nil) throws {
        if let socketPath, !socketPath.isEmpty {
            self.socketPath = socketPath
            return
        }

        guard let environmentPath = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"],
              !environmentPath.isEmpty else {
            throw SSHAgentClientError.missingSocketPath
        }

        self.socketPath = environmentPath
    }

    /// Lists public key identities currently available from the agent.
    public func identities() async throws -> [SSHAgentIdentity] {
        let response = try await self.sendAgentRequest(
            messageID: Self.requestIdentitiesMessageID
        ) { _ in }
        var reader = SSHWireReader(bytes: response)
        let messageID = try reader.readByte()
        try self.requireMessageID(
            messageID,
            expected: Self.identitiesAnswerMessageID
        )

        let identityCount = try reader.readUInt32()
        var identities: [SSHAgentIdentity] = []
        identities.reserveCapacity(Int(identityCount))

        for _ in 0..<identityCount {
            let publicKey = try reader.readString()
            let comment = try reader.readUTF8String()
            let keyType = try Self.publicKeyType(from: publicKey)
            identities.append(
                SSHAgentIdentity(
                    publicKey: publicKey,
                    comment: comment,
                    keyType: keyType,
                    supportedAuthenticationAlgorithmNames: Self.authenticationAlgorithmNames(
                        forKeyType: keyType
                    )
                )
            )
        }

        try self.requireEndOfMessage(reader)
        return identities
    }

    /// Builds an `SSHAuthenticationMethod.publicKey` value backed by this agent.
    public nonisolated func authenticationMethod(
        for identity: SSHAgentIdentity
    ) -> SSHAuthenticationMethod {
        .publicKey(
            algorithmNames: identity.supportedAuthenticationAlgorithmNames,
            publicKey: identity.publicKey,
            signatureProvider: { request in
                try await self.sign(identity: identity, request: request)
            }
        )
    }

    /// Signs a Traversio public-key authentication request with an agent
    /// identity.
    public func sign(
        identity: SSHAgentIdentity,
        request: SSHPublicKeyAuthenticationSigningRequest
    ) async throws -> [UInt8] {
        try await self.sign(
            identity: identity,
            data: request.signatureData,
            algorithmName: request.algorithmName
        )
    }

    /// Signs arbitrary SSH authentication data with an agent identity.
    public func sign(
        identity: SSHAgentIdentity,
        data: [UInt8],
        algorithmName: String
    ) async throws -> [UInt8] {
        let response = try await self.sendAgentRequest(
            messageID: Self.signRequestMessageID
        ) { writer in
            writer.write(string: identity.publicKey)
            writer.write(string: data)
            writer.write(uint32: Self.signingFlags(for: algorithmName))
        }

        var reader = SSHWireReader(bytes: response)
        let messageID = try reader.readByte()
        try self.requireMessageID(
            messageID,
            expected: Self.signResponseMessageID
        )
        let signature = try reader.readString()
        try self.requireEndOfMessage(reader)
        return signature
    }

    private func sendAgentRequest(
        messageID: UInt8,
        build: @escaping @Sendable (inout SSHWireWriter) throws -> Void
    ) async throws -> [UInt8] {
        var payloadWriter = SSHWireWriter()
        payloadWriter.write(byte: messageID)
        try build(&payloadWriter)

        var frameWriter = SSHWireWriter()
        frameWriter.write(uint32: UInt32(payloadWriter.bytes.count))
        frameWriter.write(rawBytes: payloadWriter.bytes)

        let socketPath = self.socketPath
        let frame = frameWriter.bytes
        return try await Task.detached {
            try Self.performAgentTransaction(
                socketPath: socketPath,
                frame: frame
            )
        }.value
    }

    private nonisolated static func performAgentTransaction(
        socketPath: String,
        frame: [UInt8]
    ) throws -> [UInt8] {
        let socketDescriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketDescriptor >= 0 else {
            throw SSHAgentClientError.socketOperationFailed(
                "socket failed: \(self.posixDescription(errno))"
            )
        }
        defer {
            Darwin.close(socketDescriptor)
        }

        var address = sockaddr_un()
        let addressLength = try self.configureUnixSocketAddress(
            &address,
            path: socketPath
        )
        try self.connect(socketDescriptor, to: address, length: addressLength)
        try self.writeAll(frame, to: socketDescriptor)

        let lengthBytes = try self.readExactByteCount(
            4,
            from: socketDescriptor
        )
        let length = lengthBytes.reduce(into: UInt32.zero) { value, byte in
            value = (value << 8) | UInt32(byte)
        }

        guard length <= self.maximumMessageLength else {
            throw SSHAgentClientError.invalidMessageLength(length)
        }

        return try self.readExactByteCount(
            Int(length),
            from: socketDescriptor
        )
    }

    private nonisolated static func configureUnixSocketAddress(
        _ address: inout sockaddr_un,
        path: String
    ) throws -> socklen_t {
        let pathBytes = Array(path.utf8)
        let maximumPathByteCount = MemoryLayout.size(ofValue: address.sun_path)
        guard pathBytes.count < maximumPathByteCount else {
            throw SSHAgentClientError.invalidSocketPath
        }

        address.sun_family = sa_family_t(AF_UNIX)
        let pathOffset = MemoryLayout.offset(of: \sockaddr_un.sun_path) ?? 0
        let addressLength = pathOffset + pathBytes.count + 1
        address.sun_len = UInt8(addressLength)

        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: pathBytes)
            buffer[pathBytes.count] = 0
        }

        return socklen_t(addressLength)
    }

    private nonisolated static func connect(
        _ socketDescriptor: Int32,
        to address: sockaddr_un,
        length: socklen_t
    ) throws {
        var address = address
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddressPointer in
                Darwin.connect(socketDescriptor, socketAddressPointer, length)
            }
        }
        guard result == 0 else {
            throw SSHAgentClientError.socketOperationFailed(
                "connect failed: \(self.posixDescription(errno))"
            )
        }
    }

    private nonisolated static func writeAll(
        _ bytes: [UInt8],
        to socketDescriptor: Int32
    ) throws {
        var offset = 0
        while offset < bytes.count {
            let writtenCount = bytes.withUnsafeBytes { buffer in
                Darwin.write(
                    socketDescriptor,
                    buffer.baseAddress!.advanced(by: offset),
                    bytes.count - offset
                )
            }

            if writtenCount < 0 {
                if errno == EINTR {
                    continue
                }
                throw SSHAgentClientError.socketOperationFailed(
                    "write failed: \(self.posixDescription(errno))"
                )
            }

            offset += writtenCount
        }
    }

    private nonisolated static func readExactByteCount(
        _ byteCount: Int,
        from socketDescriptor: Int32
    ) throws -> [UInt8] {
        var bytes = Array(repeating: UInt8(0), count: byteCount)
        var offset = 0

        while offset < byteCount {
            let receivedCount = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(
                    socketDescriptor,
                    buffer.baseAddress!.advanced(by: offset),
                    byteCount - offset
                )
            }

            if receivedCount == 0 {
                throw SSHTransportError.emptyReceive
            }
            if receivedCount < 0 {
                if errno == EINTR {
                    continue
                }
                throw SSHAgentClientError.socketOperationFailed(
                    "read failed: \(self.posixDescription(errno))"
                )
            }

            offset += receivedCount
        }

        return bytes
    }

    private nonisolated static func posixDescription(_ errorCode: Int32) -> String {
        if let posixCode = POSIXErrorCode(rawValue: errorCode) {
            return "\(posixCode.rawValue) (\(posixCode))"
        }
        return "\(errorCode)"
    }

    private nonisolated func requireMessageID(
        _ received: UInt8,
        expected: UInt8
    ) throws {
        if received == Self.failureMessageID {
            throw SSHAgentClientError.agentFailure
        }
        guard received == expected else {
            throw SSHAgentClientError.unexpectedMessage(
                expected: expected,
                received: received
            )
        }
    }

    private nonisolated func requireEndOfMessage(
        _ reader: SSHWireReader
    ) throws {
        guard reader.isAtEnd else {
            throw SSHAgentClientError.trailingMessageBytes(
                reader.remainingByteCount
            )
        }
    }

    private nonisolated static func publicKeyType(from publicKey: [UInt8]) throws -> String {
        var reader = SSHWireReader(bytes: publicKey)
        do {
            return try reader.readUTF8String()
        } catch {
            throw SSHAgentClientError.invalidIdentityPublicKey
        }
    }

    private nonisolated static func authenticationAlgorithmNames(
        forKeyType keyType: String
    ) -> [String] {
        switch keyType {
        case "ssh-rsa":
            return ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
        default:
            return [keyType]
        }
    }

    private nonisolated static func signingFlags(for algorithmName: String) -> UInt32 {
        switch algorithmName {
        case "rsa-sha2-256":
            return Self.rsaSHA256AgentFlag
        case "rsa-sha2-512":
            return Self.rsaSHA512AgentFlag
        default:
            return 0
        }
    }
}
