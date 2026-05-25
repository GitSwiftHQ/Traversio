// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

/// File data received by the single-file SCP helper.
public struct SSHSCPReceivedFile: Equatable, Sendable {
    /// remote path.
    public let remotePath: String
    /// File Name.
    public let fileName: String
    /// Permissions.
    public let permissions: UInt16
    /// byte count.
    public let byteCount: UInt64
    /// Contents.
    public let contents: [UInt8]
    /// Remote process exit status, when reported.
    public let exitStatus: UInt32?
    /// Creates an SSHSCPReceivedFile.

    public init(
        remotePath: String,
        fileName: String,
        permissions: UInt16,
        byteCount: UInt64,
        contents: [UInt8],
        exitStatus: UInt32?
    ) {
        self.remotePath = remotePath
        self.fileName = fileName
        self.permissions = permissions
        self.byteCount = byteCount
        self.contents = contents
        self.exitStatus = exitStatus
    }
}

/// Summary returned by single-file SCP send and download/upload helpers.
public struct SSHSCPTransferResult: Equatable, Sendable {
    /// remote path.
    public let remotePath: String
    /// File Name.
    public let fileName: String
    /// byte count.
    public let byteCount: UInt64
    /// Remote process exit status, when reported.
    public let exitStatus: UInt32?
    /// Creates an SSHSCPTransferResult.

    public init(
        remotePath: String,
        fileName: String,
        byteCount: UInt64,
        exitStatus: UInt32?
    ) {
        self.remotePath = remotePath
        self.fileName = fileName
        self.byteCount = byteCount
        self.exitStatus = exitStatus
    }
}

/// Defaults used by the single-file SCP helpers.
public enum SSHSCPTransferDefaults {
    /// Maximum Buffered File byte count.
    public static let maximumBufferedFileByteCount = 64 * 1024 * 1024
}

/// Errors raised by Traversio's single-file SCP compatibility helpers.
public enum SSHSCPTransferError: Error, Equatable, Sendable {
    /// Invalid remote path.
    case invalidRemotePath(String)
    /// Invalid File Name.
    case invalidFileName(String)
    /// Invalid Permissions.
    case invalidPermissions(UInt16)
    /// Invalid Maximum File Size.
    case invalidMaximumFileSize(Int)
    /// Malformed Control Message.
    case malformedControlMessage(String)
    /// Unexpected Control Message.
    case unexpectedControlMessage(String)
    /// Unsupported Directory Record.
    case unsupportedDirectoryRecord(String)
    /// Remote Error.
    case remoteError(message: String, fatal: Bool)
    /// File Too Large.
    case fileTooLarge(byteCount: UInt64, maximumByteCount: Int)
    /// byte count Overflow.
    case byteCountOverflow(UInt64)
    /// Premature End of Stream.
    case prematureEndOfStream(expectedByteCount: Int, receivedByteCount: Int)
    /// Remote Exit Status.
    case remoteExitStatus(UInt32, standardError: [UInt8])
}

extension SSHConnection {
    /// Receives one remote file by running the server's `scp -f` command.
    ///
    /// SCP support is provided for compatibility. Prefer SFTP for new file
    /// transfer features.
    public func receiveSCPFile(
        _ remotePath: String,
        maximumFileSize: Int = SSHSCPTransferDefaults.maximumBufferedFileByteCount
    ) async throws -> SSHSCPReceivedFile {
        try SSHSCPProtocol.validateMaximumFileSize(maximumFileSize)
        let command = try SSHSCPProtocol.makeReceiveCommand(remotePath: remotePath)
        let session = try await self.openExec(command)

        do {
            var reader = SSHSCPProtocolReader()
            try await session.write([SSHSCPProtocol.okByte])

            let header: SSHSCPFileHeader
            while true {
                let line = try await reader.readControlLine(from: session)
                switch try SSHSCPProtocol.parseControlRecord(line) {
                case let .file(fileHeader):
                    header = fileHeader
                    break
                case .timestamp:
                    try await session.write([SSHSCPProtocol.okByte])
                    continue
                case let .directory(record):
                    throw SSHSCPTransferError.unsupportedDirectoryRecord(record)
                case .endDirectory:
                    throw SSHSCPTransferError.unexpectedControlMessage("E")
                }
                break
            }

            guard header.byteCount <= UInt64(maximumFileSize) else {
                throw SSHSCPTransferError.fileTooLarge(
                    byteCount: header.byteCount,
                    maximumByteCount: maximumFileSize
                )
            }
            guard let expectedByteCount = Int(exactly: header.byteCount) else {
                throw SSHSCPTransferError.byteCountOverflow(header.byteCount)
            }

            try await session.write([SSHSCPProtocol.okByte])
            let contents = try await reader.readBytes(
                count: expectedByteCount,
                from: session
            )
            try await reader.readOK(from: session)
            try await session.write([SSHSCPProtocol.okByte])
            let completion = try await reader.finish(from: session)

            return SSHSCPReceivedFile(
                remotePath: remotePath,
                fileName: header.fileName,
                permissions: header.permissions,
                byteCount: header.byteCount,
                contents: contents,
                exitStatus: completion.exitStatus
            )
        } catch {
            await SSHSCPProtocol.bestEffortClose(session)
            throw error
        }
    }

    /// Sends one in-memory file by running the server's `scp -t` command.
    public func sendSCPFile(
        _ contents: [UInt8],
        remotePath: String,
        fileName: String? = nil,
        permissions: UInt16 = 0o644
    ) async throws -> SSHSCPTransferResult {
        let command = try SSHSCPProtocol.makeSendCommand(remotePath: remotePath)
        let resolvedFileName = try SSHSCPProtocol.resolveFileName(
            remotePath: remotePath,
            explicitFileName: fileName
        )
        try SSHSCPProtocol.validatePermissions(permissions)
        let session = try await self.openExec(command)

        do {
            var reader = SSHSCPProtocolReader()
            try await reader.readOK(from: session)

            let header = SSHSCPProtocol.makeFileHeader(
                fileName: resolvedFileName,
                permissions: permissions,
                byteCount: UInt64(contents.count)
            )
            try await session.write(header)
            try await reader.readOK(from: session)
            try await session.write(contents)
            try await session.write([SSHSCPProtocol.okByte])
            try await reader.readOK(from: session)
            try await session.sendEOF()
            let completion = try await reader.finish(from: session)

            return SSHSCPTransferResult(
                remotePath: remotePath,
                fileName: resolvedFileName,
                byteCount: UInt64(contents.count),
                exitStatus: completion.exitStatus
            )
        } catch {
            await SSHSCPProtocol.bestEffortClose(session)
            throw error
        }
    }

    /// Downloads one remote SCP file directly to a local file URL.
    public func downloadSCPFile(
        _ remotePath: String,
        to localURL: URL,
        maximumFileSize: Int = SSHSCPTransferDefaults.maximumBufferedFileByteCount
    ) async throws -> SSHSCPTransferResult {
        try SSHSCPProtocol.validateMaximumFileSize(maximumFileSize)
        let file = try await self.receiveSCPFile(
            remotePath,
            maximumFileSize: maximumFileSize
        )
        try Data(file.contents).write(to: localURL, options: .atomic)
        return SSHSCPTransferResult(
            remotePath: remotePath,
            fileName: file.fileName,
            byteCount: file.byteCount,
            exitStatus: file.exitStatus
        )
    }

    /// Uploads one local file URL using SCP compatibility mode.
    public func uploadSCPFile(
        from localURL: URL,
        to remotePath: String,
        fileName: String? = nil,
        permissions: UInt16? = nil
    ) async throws -> SSHSCPTransferResult {
        let data = try Data(contentsOf: localURL)
        let mode = permissions ?? SSHSCPProtocol.localFilePermissions(at: localURL)
        let resolvedFileName = fileName ?? localURL.lastPathComponent
        return try await self.sendSCPFile(
            Array(data),
            remotePath: remotePath,
            fileName: resolvedFileName,
            permissions: mode
        )
    }
}

struct SSHSCPFileHeader: Equatable, Sendable {
    let permissions: UInt16
    let byteCount: UInt64
    let fileName: String
}

struct SSHSCPTransferCompletion: Equatable, Sendable {
    let exitStatus: UInt32?
    let standardError: [UInt8]
}

enum SSHSCPControlRecord: Equatable, Sendable {
    case file(SSHSCPFileHeader)
    case directory(String)
    case endDirectory
    case timestamp
}

enum SSHSCPProtocol {
    static let okByte: UInt8 = 0
    private static let warningByte: UInt8 = 1
    private static let fatalByte: UInt8 = 2

    static func makeReceiveCommand(remotePath: String) throws -> String {
        try "scp -f -- \(Self.shellQuotedRemotePath(remotePath))"
    }

    static func makeSendCommand(remotePath: String) throws -> String {
        try "scp -t -- \(Self.shellQuotedRemotePath(remotePath))"
    }

    static func makeFileHeader(
        fileName: String,
        permissions: UInt16,
        byteCount: UInt64
    ) -> String {
        "C\(String(format: "%04o", permissions)) \(byteCount) \(fileName)\n"
    }

    static func parseControlRecord(_ line: [UInt8]) throws -> SSHSCPControlRecord {
        guard let marker = line.first else {
            throw SSHSCPTransferError.malformedControlMessage("")
        }

        switch marker {
        case Self.warningByte, Self.fatalByte:
            throw SSHSCPTransferError.remoteError(
                message: String(decoding: line.dropFirst(), as: UTF8.self),
                fatal: marker == Self.fatalByte
            )
        case UInt8(ascii: "C"):
            return try .file(Self.parseFileHeader(line))
        case UInt8(ascii: "D"):
            return .directory(String(decoding: line, as: UTF8.self))
        case UInt8(ascii: "E"):
            guard line.count == 1 else {
                throw SSHSCPTransferError.malformedControlMessage(
                    String(decoding: line, as: UTF8.self)
                )
            }
            return .endDirectory
        case UInt8(ascii: "T"):
            return .timestamp
        default:
            throw SSHSCPTransferError.unexpectedControlMessage(
                String(decoding: line, as: UTF8.self)
            )
        }
    }

    static func resolveFileName(
        remotePath: String,
        explicitFileName: String?
    ) throws -> String {
        if let explicitFileName {
            try Self.validateFileName(explicitFileName)
            return explicitFileName
        }

        var path = remotePath
        while path.last == "/" {
            path.removeLast()
        }

        guard let fileName = path.split(separator: "/").last.map(String.init) else {
            throw SSHSCPTransferError.invalidRemotePath(remotePath)
        }
        try Self.validateFileName(fileName)
        return fileName
    }

    static func validatePermissions(_ permissions: UInt16) throws {
        guard permissions <= 0o7777 else {
            throw SSHSCPTransferError.invalidPermissions(permissions)
        }
    }

    static func validateMaximumFileSize(_ maximumFileSize: Int) throws {
        guard maximumFileSize >= 0 else {
            throw SSHSCPTransferError.invalidMaximumFileSize(maximumFileSize)
        }
    }

    static func localFilePermissions(at url: URL) -> UInt16 {
        let attributes = try? FileManager.default.attributesOfItem(
            atPath: url.path
        )
        let rawPermissions = (attributes?[.posixPermissions] as? NSNumber)?.uint16Value
        return (rawPermissions ?? 0o644) & 0o7777
    }

    static func bestEffortClose(_ session: SSHSession) async {
        do {
            try await session.close()
        } catch {
        }
    }

    private static func shellQuotedRemotePath(_ remotePath: String) throws -> String {
        try Self.validateRemotePath(remotePath)
        return "'\(remotePath.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    private static func validateRemotePath(_ remotePath: String) throws {
        guard !remotePath.isEmpty,
              !remotePath.utf8.contains(0),
              !remotePath.utf8.contains(UInt8(ascii: "\n")),
              !remotePath.utf8.contains(UInt8(ascii: "\r")) else {
            throw SSHSCPTransferError.invalidRemotePath(remotePath)
        }
    }

    private static func validateFileName(_ fileName: String) throws {
        guard !fileName.isEmpty,
              !fileName.contains("/"),
              !fileName.utf8.contains(0),
              !fileName.utf8.contains(UInt8(ascii: "\n")),
              !fileName.utf8.contains(UInt8(ascii: "\r")) else {
            throw SSHSCPTransferError.invalidFileName(fileName)
        }
    }

    private static func parseFileHeader(_ line: [UInt8]) throws -> SSHSCPFileHeader {
        let text = String(decoding: line, as: UTF8.self)
        let body = text.dropFirst()
        guard let firstSpace = body.firstIndex(of: " ") else {
            throw SSHSCPTransferError.malformedControlMessage(text)
        }
        let modeText = body[..<firstSpace]
        let sizeAndName = body[body.index(after: firstSpace)...]
        guard let secondSpace = sizeAndName.firstIndex(of: " ") else {
            throw SSHSCPTransferError.malformedControlMessage(text)
        }
        let sizeText = sizeAndName[..<secondSpace]
        let fileName = String(sizeAndName[sizeAndName.index(after: secondSpace)...])

        guard let permissions = UInt16(modeText, radix: 8) else {
            throw SSHSCPTransferError.malformedControlMessage(text)
        }
        guard let byteCount = UInt64(sizeText) else {
            throw SSHSCPTransferError.malformedControlMessage(text)
        }
        try Self.validatePermissions(permissions)
        try Self.validateFileName(fileName)

        return SSHSCPFileHeader(
            permissions: permissions,
            byteCount: byteCount,
            fileName: fileName
        )
    }
}

struct SSHSCPProtocolReader {
    private var stdoutBuffer: [UInt8] = []
    private var stdoutOffset = 0
    private var standardError: [UInt8] = []
    private var exitStatus: UInt32?

    mutating func readOK(from session: SSHSession) async throws {
        let status = try await self.readByte(from: session)
        switch status {
        case SSHSCPProtocol.okByte:
            return
        case 1, 2:
            let message = try await self.readLineFragment(from: session)
            throw SSHSCPTransferError.remoteError(
                message: message,
                fatal: status == 2
            )
        default:
            throw SSHSCPTransferError.unexpectedControlMessage(
                String(decoding: [status], as: UTF8.self)
            )
        }
    }

    mutating func readControlLine(from session: SSHSession) async throws -> [UInt8] {
        let first = try await self.readByte(from: session)
        var line = [first]

        while true {
            let byte = try await self.readByte(from: session)
            guard byte != UInt8(ascii: "\n") else {
                return line
            }
            line.append(byte)
        }
    }

    mutating func readBytes(count: Int, from session: SSHSession) async throws -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(count)

        while bytes.count < count {
            let available = self.stdoutBuffer.count - self.stdoutOffset
            if available == 0 {
                try await self.refill(
                    from: session,
                    expectedByteCount: count,
                    receivedByteCount: bytes.count
                )
                continue
            }

            let remaining = count - bytes.count
            let chunkCount = min(available, remaining)
            let start = self.stdoutOffset
            let end = start + chunkCount
            bytes.append(contentsOf: self.stdoutBuffer[start..<end])
            self.stdoutOffset = end
            self.compactBufferIfNeeded()
        }

        return bytes
    }

    mutating func finish(from session: SSHSession) async throws -> SSHSCPTransferCompletion {
        while let event = try await session.nextEvent() {
            try self.handle(event)
        }

        let remainingOutput = self.stdoutBuffer.count - self.stdoutOffset
        if remainingOutput > 0 {
            let start = self.stdoutOffset
            let message = String(decoding: self.stdoutBuffer[start...], as: UTF8.self)
            throw SSHSCPTransferError.unexpectedControlMessage(message)
        }

        if let exitStatus, exitStatus != 0 {
            throw SSHSCPTransferError.remoteExitStatus(
                exitStatus,
                standardError: self.standardError
            )
        }

        return SSHSCPTransferCompletion(
            exitStatus: self.exitStatus,
            standardError: self.standardError
        )
    }

    private mutating func readByte(from session: SSHSession) async throws -> UInt8 {
        while self.stdoutOffset >= self.stdoutBuffer.count {
            try await self.refill(
                from: session,
                expectedByteCount: 1,
                receivedByteCount: 0
            )
        }

        let byte = self.stdoutBuffer[self.stdoutOffset]
        self.stdoutOffset += 1
        self.compactBufferIfNeeded()
        return byte
    }

    private mutating func readLineFragment(from session: SSHSession) async throws -> String {
        var bytes: [UInt8] = []
        while true {
            let byte = try await self.readByte(from: session)
            guard byte != UInt8(ascii: "\n") else {
                return String(decoding: bytes, as: UTF8.self)
            }
            bytes.append(byte)
        }
    }

    private mutating func refill(
        from session: SSHSession,
        expectedByteCount: Int,
        receivedByteCount: Int
    ) async throws {
        guard let event = try await session.nextEvent() else {
            throw SSHSCPTransferError.prematureEndOfStream(
                expectedByteCount: expectedByteCount,
                receivedByteCount: receivedByteCount
            )
        }
        try self.handle(event)
    }

    private mutating func handle(_ event: SSHSessionEvent) throws {
        switch event {
        case let .standardOutput(bytes):
            if self.stdoutOffset >= self.stdoutBuffer.count {
                self.stdoutBuffer = bytes
                self.stdoutOffset = 0
            } else {
                self.stdoutBuffer.append(contentsOf: bytes)
            }
        case let .standardError(bytes):
            self.standardError.append(contentsOf: bytes)
        case let .exitStatus(status):
            self.exitStatus = status
        case let .exitSignal(signal):
            throw SSHSCPTransferError.unexpectedControlMessage(signal.signal.rawValue)
        case .endOfFile:
            break
        }
    }

    private mutating func compactBufferIfNeeded() {
        guard self.stdoutOffset > 4096,
              self.stdoutOffset * 2 >= self.stdoutBuffer.count else {
            return
        }

        self.stdoutBuffer.removeFirst(self.stdoutOffset)
        self.stdoutOffset = 0
    }
}
