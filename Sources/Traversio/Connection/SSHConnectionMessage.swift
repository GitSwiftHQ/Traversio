// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

struct SSHChannelOpenFailureReasonCode: RawRepresentable, Equatable, Hashable, Sendable {
    let rawValue: UInt32

    init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    static let administrativelyProhibited = Self(rawValue: 1)
    static let connectFailed = Self(rawValue: 2)
    static let unknownChannelType = Self(rawValue: 3)
    static let resourceShortage = Self(rawValue: 4)
}

package enum SSHConnectionMessageID: UInt8, Equatable, Sendable {
    case globalRequest = 80
    case requestSuccess = 81
    case requestFailure = 82
    case channelOpen = 90
    case channelOpenConfirmation = 91
    case channelOpenFailure = 92
    case channelWindowAdjust = 93
    case channelData = 94
    case channelExtendedData = 95
    case channelEOF = 96
    case channelClose = 97
    case channelRequest = 98
    case channelSuccess = 99
    case channelFailure = 100
}

enum SSHConnectionError: Error, Equatable, Sendable {
    case authenticatedConnectionRequired
    case unexpectedConnectionMessage(expected: SSHConnectionMessageID, received: SSHConnectionMessageID)
    case channelOpenFailure(SSHChannelOpenFailureMessage)
    case channelRequestFailed(channelID: UInt32, requestType: String)
    case globalRequestFailed(requestType: String)
    case invalidGlobalRequestResponse(requestType: String)
    case unexpectedChannelMessage(expected: UInt32, received: UInt32)
    case unknownChannel(channelID: UInt32)
    case channelReceiveWindowExceeded(channelID: UInt32, received: UInt32, remaining: UInt32)
    case channelReceiveWindowOverflow(channelID: UInt32, current: UInt32, adjustment: UInt32)
    case channelSendWindowOverflow(channelID: UInt32, current: UInt32, adjustment: UInt32)
    case channelClosedBeforeSending(channelID: UInt32, unsentByteCount: UInt32)
    case channelClosedBeforeReceiving(channelID: UInt32)
    case concurrentChannelWrite(channelID: UInt32)
    case incompatibleSessionOutputConsumer(
        channelID: UInt32,
        activeConsumer: SSHSessionOutputBufferingMode,
        requestedConsumer: SSHSessionOutputBufferingMode
    )
    case invalidChannelRequest(String)
    case invalidGlobalRequest(String)
    case invalidChannelOpen(String)
    case invalidTCPIPPort(UInt32)
    case invalidPseudoTerminalModes
}

struct SSHGlobalRequestMessage: Equatable, Sendable {
    let requestName: String
    let wantReply: Bool
    let requestData: [UInt8]
}

struct SSHGlobalRequestSuccessMessage: Equatable, Sendable {
    let responseData: [UInt8]
}

struct SSHGlobalRequestFailureMessage: Equatable, Sendable {
    init() {}
}

struct SSHChannelOpenMessage: Equatable, Sendable {
    let channelType: String
    let senderChannel: UInt32
    let initialWindowSize: UInt32
    let maximumPacketSize: UInt32
    let channelTypeData: [UInt8]
}

struct SSHChannelOpenConfirmationMessage: Equatable, Sendable {
    let recipientChannel: UInt32
    let senderChannel: UInt32
    let initialWindowSize: UInt32
    let maximumPacketSize: UInt32
    let channelTypeData: [UInt8]
}

struct SSHChannelOpenFailureMessage: Equatable, Sendable {
    let recipientChannel: UInt32
    let reasonCode: SSHChannelOpenFailureReasonCode
    let description: String
    let languageTag: String
}

struct SSHChannelWindowAdjustMessage: Equatable, Sendable {
    let recipientChannel: UInt32
    let bytesToAdd: UInt32
}

struct SSHChannelDataMessage: Equatable, Sendable {
    let recipientChannel: UInt32
    let data: [UInt8]
}

struct SSHChannelExtendedDataMessage: Equatable, Sendable {
    let recipientChannel: UInt32
    let dataTypeCode: UInt32
    let data: [UInt8]

    static let standardErrorDataTypeCode: UInt32 = 1
}

struct SSHChannelEOFMessage: Equatable, Sendable {
    let recipientChannel: UInt32
}

struct SSHChannelCloseMessage: Equatable, Sendable {
    let recipientChannel: UInt32
}

struct SSHChannelRequestMessage: Equatable, Sendable {
    let recipientChannel: UInt32
    let requestType: String
    let wantReply: Bool
    let requestData: [UInt8]
}

struct SSHChannelSuccessMessage: Equatable, Sendable {
    let recipientChannel: UInt32
}

struct SSHChannelFailureMessage: Equatable, Sendable {
    let recipientChannel: UInt32
}

enum SSHConnectionMessage: Equatable, Sendable {
    case globalRequest(SSHGlobalRequestMessage)
    case requestSuccess(SSHGlobalRequestSuccessMessage)
    case requestFailure(SSHGlobalRequestFailureMessage)
    case channelOpen(SSHChannelOpenMessage)
    case channelOpenConfirmation(SSHChannelOpenConfirmationMessage)
    case channelOpenFailure(SSHChannelOpenFailureMessage)
    case channelWindowAdjust(SSHChannelWindowAdjustMessage)
    case channelData(SSHChannelDataMessage)
    case channelExtendedData(SSHChannelExtendedDataMessage)
    case channelEOF(SSHChannelEOFMessage)
    case channelClose(SSHChannelCloseMessage)
    case channelRequest(SSHChannelRequestMessage)
    case channelSuccess(SSHChannelSuccessMessage)
    case channelFailure(SSHChannelFailureMessage)

    var messageID: SSHConnectionMessageID {
        switch self {
        case .globalRequest:
            return .globalRequest
        case .requestSuccess:
            return .requestSuccess
        case .requestFailure:
            return .requestFailure
        case .channelOpen:
            return .channelOpen
        case .channelOpenConfirmation:
            return .channelOpenConfirmation
        case .channelOpenFailure:
            return .channelOpenFailure
        case .channelWindowAdjust:
            return .channelWindowAdjust
        case .channelData:
            return .channelData
        case .channelExtendedData:
            return .channelExtendedData
        case .channelEOF:
            return .channelEOF
        case .channelClose:
            return .channelClose
        case .channelRequest:
            return .channelRequest
        case .channelSuccess:
            return .channelSuccess
        case .channelFailure:
            return .channelFailure
        }
    }
}

package struct SSHChannel: Equatable, Sendable {
    package let localChannelID: UInt32
    package let remoteChannelID: UInt32
    package let localInitialWindowSize: UInt32
    package let localMaximumPacketSize: UInt32
    package let remoteInitialWindowSize: UInt32
    package let remoteMaximumPacketSize: UInt32
}

struct SSHSessionTranscript: Equatable, Sendable {
    let channel: SSHChannel
    let standardOutput: [UInt8]
    let standardError: [UInt8]
    let exitStatus: UInt32?
    let exitSignal: SSHSessionExitSignal?
    let didReceiveEOF: Bool
}

/// Exit-signal details reported by the server for a session channel.
public struct SSHSessionExitSignal: Equatable, Hashable, Sendable {
    /// Signal.
    public let signal: SSHSessionSignal
    /// Did Core Dump.
    public let didCoreDump: Bool
    /// Error Message.
    public let errorMessage: String?
    /// Server-provided language tag.
    public let languageTag: String?
    /// Creates an SSHSessionExitSignal.

    public init(
        signal: SSHSessionSignal,
        didCoreDump: Bool,
        errorMessage: String? = nil,
        languageTag: String? = nil
    ) {
        self.signal = signal
        self.didCoreDump = didCoreDump
        self.errorMessage = errorMessage
        self.languageTag = languageTag
    }
}

/// Structured output and terminal events from an SSH session channel.
public enum SSHSessionEvent: Equatable, Sendable {
    /// Standard Output.
    case standardOutput([UInt8])
    /// Standard Error.
    case standardError([UInt8])
    /// Exit Status.
    case exitStatus(UInt32)
    /// Exit Signal.
    case exitSignal(SSHSessionExitSignal)
    /// End of File.
    case endOfFile
}

/// Structured data events from TCP/IP and streamlocal channels.
public enum SSHTCPIPChannelEvent: Equatable, Sendable {
    /// Data.
    case data([UInt8])
    /// End of File.
    case endOfFile
}

struct SSHPseudoTerminalWindowChange: Equatable, Sendable {
    let characterWidth: UInt32
    let characterHeight: UInt32
    let pixelWidth: UInt32
    let pixelHeight: UInt32
}

/// Environment variable requested before starting an exec, shell, or subsystem.
public struct SSHSessionEnvironmentVariable: Equatable, Hashable, Sendable {
    /// Name.
    public let name: String
    /// Value.
    public let value: String
    /// Creates an SSHSessionEnvironmentVariable.

    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }
}

/// RFC 4254 signal name sent to a remote session.
public struct SSHSessionSignal: RawRepresentable, Equatable, Hashable, Sendable {
    /// Raw Value.
    public let rawValue: String

    /// Creates an SSHSessionSignal.
    public init(rawValue: String) {
        self.rawValue = rawValue
    }
/// Abort.

    /// Abort.
    public static let abort = Self(rawValue: "ABRT")
    /// Alarm.
    public static let alarm = Self(rawValue: "ALRM")
    /// Floating Point Exception.
    public static let floatingPointException = Self(rawValue: "FPE")
    /// Hangup.
    public static let hangup = Self(rawValue: "HUP")
    /// Illegal Instruction.
    public static let illegalInstruction = Self(rawValue: "ILL")
    /// Interrupt.
    public static let interrupt = Self(rawValue: "INT")
    /// Kill.
    public static let kill = Self(rawValue: "KILL")
    /// Broken Pipe.
    public static let brokenPipe = Self(rawValue: "PIPE")
    /// Quit.
    public static let quit = Self(rawValue: "QUIT")
    /// Segmentation Violation.
    public static let segmentationViolation = Self(rawValue: "SEGV")
    /// Terminate.
    public static let terminate = Self(rawValue: "TERM")
    /// User1.
    public static let user1 = Self(rawValue: "USR1")
    /// User2.
    public static let user2 = Self(rawValue: "USR2")
}

struct SSHSessionHandle: Sendable {
    let channel: SSHChannel
    private let client: SSHTransportProtocolClient

    init(client: SSHTransportProtocolClient, channel: SSHChannel) {
        self.client = client
        self.channel = channel
    }

    func write(_ bytes: [UInt8], respectCancellation: Bool = true) async throws {
        try await self.client.writeChannelData(
            bytes,
            forLocalChannelID: self.channel.localChannelID,
            respectCancellation: respectCancellation,
            respectTransportSendCancellation: respectCancellation
        )
    }

    func writeStandardError(_ bytes: [UInt8], respectCancellation: Bool = true) async throws {
        try await self.client.writeChannelExtendedData(
            bytes,
            dataTypeCode: SSHChannelExtendedDataMessage.standardErrorDataTypeCode,
            forLocalChannelID: self.channel.localChannelID,
            respectCancellation: respectCancellation,
            respectTransportSendCancellation: respectCancellation
        )
    }

    func sendEOF(respectCancellation: Bool = true) async throws {
        try await self.client.sendChannelEOF(
            forLocalChannelID: self.channel.localChannelID,
            respectCancellation: respectCancellation
        )
    }

    func close() async throws {
        try await self.client.closeChannel(forLocalChannelID: self.channel.localChannelID)
    }

    func bestEffortCloseIgnoringCancellation() async {
        try? await self.client.closeChannel(
            forLocalChannelID: self.channel.localChannelID,
            respectCancellation: false
        )
    }

    func sendSignal(_ signal: SSHSessionSignal) async throws {
        try await self.client.sendSignal(
            signal,
            forLocalChannelID: self.channel.localChannelID
        )
    }

    func resizePseudoTerminal(
        characterWidth: UInt32,
        characterHeight: UInt32,
        pixelWidth: UInt32,
        pixelHeight: UInt32
    ) async throws {
        try await self.client.resizePseudoTerminal(
            SSHPseudoTerminalWindowChange(
                characterWidth: characterWidth,
                characterHeight: characterHeight,
                pixelWidth: pixelWidth,
                pixelHeight: pixelHeight
            ),
            forLocalChannelID: self.channel.localChannelID
        )
    }

    func channelWindowSnapshot() async throws -> SSHChannelWindowSnapshot {
        try await self.client.channelWindowSnapshot(
            forLocalChannelID: self.channel.localChannelID
        )
    }

    func adjustReceiveWindow(
        by byteCount: UInt32,
        respectCancellation: Bool = true
    ) async throws -> SSHChannelWindowSnapshot {
        try await self.client.adjustReceiveWindow(
            by: byteCount,
            forLocalChannelID: self.channel.localChannelID,
            respectCancellation: respectCancellation
        )
    }

    func readStandardOutputChunk(respectCancellation: Bool = true) async throws -> [UInt8]? {
        try await self.client.readChannelStandardOutputChunk(
            forLocalChannelID: self.channel.localChannelID,
            respectCancellation: respectCancellation
        )
    }

    func readEvent(respectCancellation: Bool = true) async throws -> SSHSessionEvent? {
        try await self.client.readSessionEvent(
            forLocalChannelID: self.channel.localChannelID,
            respectCancellation: respectCancellation
        )
    }

    func collectOutputUntilClose() async throws -> SSHSessionTranscript {
        try await self.client.collectSessionTranscript(
            forLocalChannelID: self.channel.localChannelID
        )
    }

    func diagnosticsSnapshot() async -> SSHTransportProtocolDiagnosticsSnapshot {
        await self.client.diagnosticsSnapshot()
    }
}

struct SSHTCPIPForwardingRequest: Equatable, Hashable, Sendable {
    let addressToBind: String
    let portToBind: UInt16
}

struct SSHStreamLocalForwardingRequest: Equatable, Hashable, Sendable {
    let socketPath: String
}

struct SSHForwardedTCPIPChannelOpenRequest: Equatable, Sendable {
    let listeningAddress: String
    let listeningPort: UInt16
    let originatorAddress: String
    let originatorPort: UInt16
}

struct SSHForwardedStreamLocalChannelOpenRequest: Equatable, Sendable {
    let socketPath: String
}

struct SSHDirectTCPIPChannelOpenRequest: Equatable, Sendable {
    let hostToConnect: String
    let portToConnect: UInt16
    let originatorAddress: String
    let originatorPort: UInt16
}

struct SSHDirectStreamLocalChannelOpenRequest: Equatable, Sendable {
    let socketPath: String
    let originatorAddress: String
    let originatorPort: UInt16
}

struct SSHTCPIPChannelTranscript: Equatable, Sendable {
    let channel: SSHChannel
    let data: [UInt8]
    let didReceiveEOF: Bool
}

struct SSHTCPIPChannelHandle: Sendable {
    let channel: SSHChannel
    private let sessionHandle: SSHSessionHandle

    init(sessionHandle: SSHSessionHandle) {
        self.channel = sessionHandle.channel
        self.sessionHandle = sessionHandle
    }

    func write(_ bytes: [UInt8], respectCancellation: Bool = true) async throws {
        try await self.sessionHandle.write(bytes, respectCancellation: respectCancellation)
    }

    func sendEOF(respectCancellation: Bool = true) async throws {
        try await self.sessionHandle.sendEOF(respectCancellation: respectCancellation)
    }

    func close() async throws {
        try await self.sessionHandle.close()
    }

    func bestEffortCloseIgnoringCancellation() async {
        await self.sessionHandle.bestEffortCloseIgnoringCancellation()
    }

    func readChunk(respectCancellation: Bool = true) async throws -> [UInt8]? {
        try await self.sessionHandle.readStandardOutputChunk(
            respectCancellation: respectCancellation
        )
    }

    func channelWindowSnapshot() async throws -> SSHChannelWindowSnapshot {
        try await self.sessionHandle.channelWindowSnapshot()
    }

    func adjustReceiveWindow(
        by byteCount: UInt32,
        respectCancellation: Bool = true
    ) async throws -> SSHChannelWindowSnapshot {
        try await self.sessionHandle.adjustReceiveWindow(
            by: byteCount,
            respectCancellation: respectCancellation
        )
    }

    func collectDataUntilClose() async throws -> SSHTCPIPChannelTranscript {
        let transcript = try await self.sessionHandle.collectOutputUntilClose()
        return SSHTCPIPChannelTranscript(
            channel: transcript.channel,
            data: transcript.standardOutput,
            didReceiveEOF: transcript.didReceiveEOF
        )
    }

    func readEvent(respectCancellation: Bool = true) async throws -> SSHTCPIPChannelEvent? {
        while let event = try await self.sessionHandle.readEvent(
            respectCancellation: respectCancellation
        ) {
            switch event {
            case let .standardOutput(bytes):
                return .data(bytes)
            case .endOfFile:
                return .endOfFile
            case .standardError, .exitStatus, .exitSignal:
                continue
            }
        }

        return nil
    }

    func diagnosticsSnapshot() async -> SSHTransportProtocolDiagnosticsSnapshot {
        await self.sessionHandle.diagnosticsSnapshot()
    }
}

/// Pseudo-terminal settings for an interactive shell.
public struct SSHPseudoTerminalRequest: Equatable, Sendable {
    /// Terminal Type.
    public let terminalType: String
    /// Character Width.
    public let characterWidth: UInt32
    /// Character Height.
    public let characterHeight: UInt32
    /// Pixel Width.
    public let pixelWidth: UInt32
    /// Pixel Height.
    public let pixelHeight: UInt32
    /// Encoded Terminal Modes.
    public let encodedTerminalModes: [UInt8]
    /// Creates an SSHPseudoTerminalRequest.

    public init(
        terminalType: String,
        characterWidth: UInt32,
        characterHeight: UInt32,
        pixelWidth: UInt32,
        pixelHeight: UInt32,
        encodedTerminalModes: [UInt8]
    ) {
        self.terminalType = terminalType
        self.characterWidth = characterWidth
        self.characterHeight = characterHeight
        self.pixelWidth = pixelWidth
        self.pixelHeight = pixelHeight
        self.encodedTerminalModes = encodedTerminalModes
    }
    /// Default.

    public static let `default` = Self(
        terminalType: "xterm-256color",
        characterWidth: 80,
        characterHeight: 24,
        pixelWidth: 0,
        pixelHeight: 0,
        encodedTerminalModes: [0]
    )
}

package struct SSHSessionExecResult: Equatable, Sendable {
    package let channel: SSHChannel
    package let standardOutput: [UInt8]
    package let standardError: [UInt8]
    package let exitStatus: UInt32?
    package let exitSignal: SSHSessionExitSignal?
    package let didReceiveEOF: Bool
}

package struct SSHSessionShellCaptureResult: Equatable, Sendable {
    package let channel: SSHChannel
    package let standardOutput: [UInt8]
    package let standardError: [UInt8]
    package let exitStatus: UInt32?
    package let exitSignal: SSHSessionExitSignal?
    package let didReceiveEOF: Bool
}

extension SSHSessionExecResult {
    init(transcript: SSHSessionTranscript) {
        self.init(
            channel: transcript.channel,
            standardOutput: transcript.standardOutput,
            standardError: transcript.standardError,
            exitStatus: transcript.exitStatus,
            exitSignal: transcript.exitSignal,
            didReceiveEOF: transcript.didReceiveEOF
        )
    }
}

extension SSHSessionShellCaptureResult {
    init(transcript: SSHSessionTranscript) {
        self.init(
            channel: transcript.channel,
            standardOutput: transcript.standardOutput,
            standardError: transcript.standardError,
            exitStatus: transcript.exitStatus,
            exitSignal: transcript.exitSignal,
            didReceiveEOF: transcript.didReceiveEOF
        )
    }
}
