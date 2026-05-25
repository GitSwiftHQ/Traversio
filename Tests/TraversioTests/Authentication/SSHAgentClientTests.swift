// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Darwin
import Testing
@testable import Traversio

@Test
func sshAgentClientListsIdentitiesAndSignsWithEd25519AgentKey() async throws {
    let privateKey = try SSHEd25519PrivateKey(rawRepresentation: Array(0x01...0x20))
    let publicKey = try privateKey.makeRequest(algorithmName: "ssh-ed25519").publicKey
    let signatureBlob = makeAgentSignatureBlob(
        algorithmName: "ssh-ed25519",
        signature: [0xaa, 0xbb, 0xcc]
    )
    let server = try await FakeSSHAgentServer.start(
        publicKey: publicKey,
        comment: "agent-ed25519",
        signatureBlob: signatureBlob
    )
    defer { server.stop() }

    let agent = try SSHAgentClient(socketPath: server.socketPath)
    let identities = try await agent.identities()
    let identity = try #require(identities.first)

    #expect(identities.count == 1)
    #expect(identity.publicKey == publicKey)
    #expect(identity.comment == "agent-ed25519")
    #expect(identity.keyType == "ssh-ed25519")
    #expect(identity.supportedAuthenticationAlgorithmNames == ["ssh-ed25519"])

    let signature = try await agent.sign(
        identity: identity,
        data: [0x01, 0x02, 0x03],
        algorithmName: "ssh-ed25519"
    )

    #expect(signature == signatureBlob)
    let signRequests = server.signRequests()
    let signRequest = try #require(signRequests.first)
    #expect(signRequest.publicKey == publicKey)
    #expect(signRequest.data == [0x01, 0x02, 0x03])
    #expect(signRequest.flags == 0)
}

@Test
func sshAgentClientMapsRSAAuthenticationAlgorithmsToAgentSignatureFlags() async throws {
    let privateKey = try SSHRSAPrivateKey.generate(bitCount: 1024)
    let publicKey = try privateKey.makeRequest(algorithmName: "rsa-sha2-512").publicKey
    let signatureBlob = makeAgentSignatureBlob(
        algorithmName: "rsa-sha2-512",
        signature: [0xde, 0xad, 0xbe, 0xef]
    )
    let server = try await FakeSSHAgentServer.start(
        publicKey: publicKey,
        comment: "agent-rsa",
        signatureBlob: signatureBlob
    )
    defer { server.stop() }

    let agent = try SSHAgentClient(socketPath: server.socketPath)
    let identities = try await agent.identities()
    let identity = try #require(identities.first)

    #expect(identity.keyType == "ssh-rsa")
    #expect(
        identity.supportedAuthenticationAlgorithmNames
            == ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
    )

    let signature = try await agent.sign(
        identity: identity,
        data: [0x42],
        algorithmName: "rsa-sha2-512"
    )

    #expect(signature == signatureBlob)
    let signRequest = try #require(server.signRequests().first)
    #expect(signRequest.flags == 4)
}

@Test
func sshClientAuthenticatesWithSSHAgentIdentity() async throws {
    let privateKey = try SSHEd25519PrivateKey(rawRepresentation: Array(0x01...0x20))
    let unsignedRequest = try privateKey.makeRequest(algorithmName: "ssh-ed25519")
    let signatureBlob = makeAgentSignatureBlob(
        algorithmName: "ssh-ed25519",
        signature: [0xca, 0xfe]
    )
    let agentServer = try await FakeSSHAgentServer.start(
        publicKey: unsignedRequest.publicKey,
        comment: "agent-auth",
        signatureBlob: signatureBlob
    )
    defer { agentServer.stop() }

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
    let transport = try makeConnectionFixtureTransport(
        serverPayloadsAfterNewKeys: [
            serviceAcceptPayload,
            publicKeyOKPayload,
            successPayload,
        ]
    )
    let agent = try SSHAgentClient(socketPath: agentServer.socketPath)
    let identity = try #require(try await agent.identities().first)
    let configuration = SSHClientConfiguration(
        host: "example.com",
        username: "root",
        authentication: agent.authenticationMethod(for: identity),
        hostKeyPolicy: .acceptAnyVerifiedHostKey
    )

    let metadata: SSHConnectionMetadata = try await SSHClient.withConnection(
        configuration: configuration,
        transportRunner: { _, handler in
            try await handler(transport)
        }
    ) { connection in
        connection.metadata
    }

    #expect(metadata.username == "root")
    let signRequest = try #require(agentServer.signRequests().first)
    #expect(signRequest.publicKey == unsignedRequest.publicKey)
    #expect(!signRequest.data.isEmpty)
    #expect(signRequest.flags == 0)
}

private struct FakeSSHAgentSignRequest: Equatable, Sendable {
    let publicKey: [UInt8]
    let data: [UInt8]
    let flags: UInt32
}

private final class FakeSSHAgentServer: @unchecked Sendable {
    // Sendable invariant: descriptor lifecycle, stop state, and request storage are protected by `lock`.
    let socketPath: String
    private let socketDescriptor: Int32
    private let queue: DispatchQueue
    private let lock = NSLock()
    private let publicKey: [UInt8]
    private let comment: String
    private let signatureBlob: [UInt8]
    private var didStop = false
    private var recordedSignRequests: [FakeSSHAgentSignRequest] = []

    private init(
        socketPath: String,
        socketDescriptor: Int32,
        queue: DispatchQueue,
        publicKey: [UInt8],
        comment: String,
        signatureBlob: [UInt8]
    ) {
        self.socketPath = socketPath
        self.socketDescriptor = socketDescriptor
        self.queue = queue
        self.publicKey = publicKey
        self.comment = comment
        self.signatureBlob = signatureBlob
    }

    static func start(
        publicKey: [UInt8],
        comment: String,
        signatureBlob: [UInt8]
    ) async throws -> FakeSSHAgentServer {
        let socketPath = "/tmp/traversio-agent-\(UUID().uuidString).sock"
        try? FileManager.default.removeItem(atPath: socketPath)

        let socketDescriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketDescriptor >= 0 else {
            throw SSHAgentClientError.socketOperationFailed(
                "socket failed: \(Self.posixDescription(errno))"
            )
        }

        do {
            var address = sockaddr_un()
            let addressLength = try Self.configureUnixSocketAddress(
                &address,
                path: socketPath
            )
            try Self.bind(socketDescriptor, to: address, length: addressLength)
            guard Darwin.listen(socketDescriptor, 8) == 0 else {
                throw SSHAgentClientError.socketOperationFailed(
                    "listen failed: \(Self.posixDescription(errno))"
                )
            }
        } catch {
            Darwin.close(socketDescriptor)
            try? FileManager.default.removeItem(atPath: socketPath)
            throw error
        }

        let queue = DispatchQueue(
            label: "TraversioTests.FakeSSHAgentServer.\(UUID().uuidString)"
        )
        let server = FakeSSHAgentServer(
            socketPath: socketPath,
            socketDescriptor: socketDescriptor,
            queue: queue,
            publicKey: publicKey,
            comment: comment,
            signatureBlob: signatureBlob
        )
        server.start()
        return server
    }

    func start() {
        self.queue.async { [weak self] in
            self?.acceptLoop()
        }
    }

    func stop() {
        self.lock.lock()
        guard !self.didStop else {
            self.lock.unlock()
            return
        }
        self.didStop = true
        let socketDescriptor = self.socketDescriptor
        self.lock.unlock()

        Darwin.shutdown(socketDescriptor, SHUT_RDWR)
        Darwin.close(socketDescriptor)
        try? FileManager.default.removeItem(atPath: self.socketPath)
    }

    func signRequests() -> [FakeSSHAgentSignRequest] {
        self.lock.lock()
        let requests = self.recordedSignRequests
        self.lock.unlock()
        return requests
    }

    private func acceptLoop() {
        while !self.isStopped() {
            let clientDescriptor = Darwin.accept(self.socketDescriptor, nil, nil)
            if clientDescriptor < 0 {
                continue
            }

            self.handle(clientDescriptor)
        }
    }

    private func isStopped() -> Bool {
        self.lock.lock()
        let value = self.didStop
        self.lock.unlock()
        return value
    }

    private func handle(_ clientDescriptor: Int32) {
        defer {
            Darwin.close(clientDescriptor)
        }

        do {
            let lengthBytes = try Self.readExactByteCount(4, from: clientDescriptor)
            let length = lengthBytes.reduce(into: UInt32.zero) { value, byte in
                value = (value << 8) | UInt32(byte)
            }
            let payload = try Self.readExactByteCount(Int(length), from: clientDescriptor)
            let response = try self.responsePayload(for: payload)
            try Self.writeFrame(payload: response, to: clientDescriptor)
        } catch {
            try? Self.writeFrame(payload: [5], to: clientDescriptor)
        }
    }

    private static func writeFrame(payload: [UInt8], to socketDescriptor: Int32) throws {
        var writer = SSHWireWriter()
        writer.write(uint32: UInt32(payload.count))
        writer.write(rawBytes: payload)
        try self.writeAll(writer.bytes, to: socketDescriptor)
    }

    private func responsePayload(for payload: [UInt8]) throws -> [UInt8] {
        var reader = SSHWireReader(bytes: payload)
        let messageID = try reader.readByte()

        switch messageID {
        case 11:
            var writer = SSHWireWriter()
            writer.write(byte: 12)
            writer.write(uint32: 1)
            writer.write(string: self.publicKey)
            writer.write(utf8: self.comment)
            return writer.bytes
        case 13:
            let publicKey = try reader.readString()
            let data = try reader.readString()
            let flags = try reader.readUInt32()
            self.record(
                FakeSSHAgentSignRequest(
                    publicKey: publicKey,
                    data: data,
                    flags: flags
                )
            )

            var writer = SSHWireWriter()
            writer.write(byte: 14)
            writer.write(string: self.signatureBlob)
            return writer.bytes
        default:
            return [5]
        }
    }

    private func record(_ request: FakeSSHAgentSignRequest) {
        self.lock.lock()
        self.recordedSignRequests.append(request)
        self.lock.unlock()
    }

    private static func configureUnixSocketAddress(
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

    private static func bind(
        _ socketDescriptor: Int32,
        to address: sockaddr_un,
        length: socklen_t
    ) throws {
        var address = address
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddressPointer in
                Darwin.bind(socketDescriptor, socketAddressPointer, length)
            }
        }
        guard result == 0 else {
            throw SSHAgentClientError.socketOperationFailed(
                "bind failed: \(self.posixDescription(errno))"
            )
        }
    }

    private static func readExactByteCount(
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

    private static func writeAll(_ bytes: [UInt8], to socketDescriptor: Int32) throws {
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

    private static func posixDescription(_ errorCode: Int32) -> String {
        if let posixCode = POSIXErrorCode(rawValue: errorCode) {
            return "\(posixCode.rawValue) (\(posixCode))"
        }
        return "\(errorCode)"
    }
}

private func makeAgentSignatureBlob(
    algorithmName: String,
    signature: [UInt8]
) -> [UInt8] {
    var writer = SSHWireWriter()
    writer.write(utf8: algorithmName)
    writer.write(string: signature)
    return writer.bytes
}
