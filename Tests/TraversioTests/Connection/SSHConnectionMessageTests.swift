// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func connectionMessageParserRoundTripsChannelOpen() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let message = SSHConnectionMessage.channelOpen(
        SSHChannelOpenMessage(
            channelType: "session",
            senderChannel: 7,
            initialWindowSize: 1_048_576,
            maximumPacketSize: 32_768,
            channelTypeData: []
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)

    #expect(decoded == message)
}

@Test
func connectionMessageParserRoundTripsTCPIPForwardGlobalRequest() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()
    let message = forwardingCoder.makeForwardRequest(
        request: SSHTCPIPForwardingRequest(
            addressToBind: "127.0.0.1",
            portToBind: 8080
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let request = try #require({
        if case let .globalRequest(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(
        try forwardingCoder.parseForwardRequest(from: request)
            == SSHTCPIPForwardingRequest(addressToBind: "127.0.0.1", portToBind: 8080)
    )
}

@Test
func connectionMessageParserRoundTripsCancelTCPIPForwardGlobalRequest() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()
    let message = forwardingCoder.makeCancelForwardRequest(
        request: SSHTCPIPForwardingRequest(
            addressToBind: "localhost",
            portToBind: 0
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let request = try #require({
        if case let .globalRequest(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(
        try forwardingCoder.parseCancelForwardRequest(from: request)
            == SSHTCPIPForwardingRequest(addressToBind: "localhost", portToBind: 0)
    )
}

@Test
func connectionMessageParserRoundTripsStreamLocalForwardGlobalRequest() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()
    let message = forwardingCoder.makeStreamLocalForwardRequest(
        request: SSHStreamLocalForwardingRequest(
            socketPath: "/tmp/traversio.sock"
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let request = try #require({
        if case let .globalRequest(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(
        try forwardingCoder.parseStreamLocalForwardRequest(from: request)
            == SSHStreamLocalForwardingRequest(socketPath: "/tmp/traversio.sock")
    )
}

@Test
func connectionMessageParserRoundTripsCancelStreamLocalForwardGlobalRequest() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()
    let message = forwardingCoder.makeCancelStreamLocalForwardRequest(
        request: SSHStreamLocalForwardingRequest(
            socketPath: "/tmp/traversio.sock"
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let request = try #require({
        if case let .globalRequest(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(
        try forwardingCoder.parseCancelStreamLocalForwardRequest(from: request)
            == SSHStreamLocalForwardingRequest(socketPath: "/tmp/traversio.sock")
    )
}

@Test
func connectionMessageParserRoundTripsDirectTCPIPChannelOpen() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()
    let message = forwardingCoder.makeDirectTCPIPChannelOpen(
        senderChannel: 9,
        initialWindowSize: 1_048_576,
        maximumPacketSize: 32_768,
        request: SSHDirectTCPIPChannelOpenRequest(
            hostToConnect: "db.internal",
            portToConnect: 5432,
            originatorAddress: "127.0.0.1",
            originatorPort: 61001
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let open = try #require({
        if case let .channelOpen(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(
        try forwardingCoder.parseDirectTCPIPChannelOpen(from: open)
            == SSHDirectTCPIPChannelOpenRequest(
                hostToConnect: "db.internal",
                portToConnect: 5432,
                originatorAddress: "127.0.0.1",
                originatorPort: 61001
            )
    )
}

@Test
func connectionMessageParserRoundTripsDirectStreamLocalChannelOpen() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()
    let message = forwardingCoder.makeDirectStreamLocalChannelOpen(
        senderChannel: 9,
        initialWindowSize: 1_048_576,
        maximumPacketSize: 32_768,
        request: SSHDirectStreamLocalChannelOpenRequest(
            socketPath: "/run/postgresql/.s.PGSQL.5432",
            originatorAddress: "127.0.0.1",
            originatorPort: 61001
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let open = try #require({
        if case let .channelOpen(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(
        try forwardingCoder.parseDirectStreamLocalChannelOpen(from: open)
            == SSHDirectStreamLocalChannelOpenRequest(
                socketPath: "/run/postgresql/.s.PGSQL.5432",
                originatorAddress: "127.0.0.1",
                originatorPort: 61001
            )
    )
}

@Test
func connectionMessageParserRoundTripsForwardedTCPIPChannelOpen() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()
    let message = forwardingCoder.makeForwardedTCPIPChannelOpen(
        senderChannel: 12,
        initialWindowSize: 1_048_576,
        maximumPacketSize: 32_768,
        request: SSHForwardedTCPIPChannelOpenRequest(
            listeningAddress: "0.0.0.0",
            listeningPort: 2222,
            originatorAddress: "198.51.100.7",
            originatorPort: 43120
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let open = try #require({
        if case let .channelOpen(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(
        try forwardingCoder.parseForwardedTCPIPChannelOpen(from: open)
            == SSHForwardedTCPIPChannelOpenRequest(
                listeningAddress: "0.0.0.0",
                listeningPort: 2222,
                originatorAddress: "198.51.100.7",
                originatorPort: 43120
            )
    )
}

@Test
func connectionMessageParserRoundTripsForwardedStreamLocalChannelOpen() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let forwardingCoder = SSHTCPIPForwardingRequestCoder()
    let message = forwardingCoder.makeForwardedStreamLocalChannelOpen(
        senderChannel: 12,
        initialWindowSize: 1_048_576,
        maximumPacketSize: 32_768,
        request: SSHForwardedStreamLocalChannelOpenRequest(
            socketPath: "/tmp/traversio.sock"
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let open = try #require({
        if case let .channelOpen(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(
        try forwardingCoder.parseForwardedStreamLocalChannelOpen(from: open)
            == SSHForwardedStreamLocalChannelOpenRequest(
                socketPath: "/tmp/traversio.sock"
            )
    )
}

@Test
func connectionMessageParserRoundTripsExecChannelRequest() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let requestCoder = SSHSessionRequestCoder()
    let message = requestCoder.makeExecRequest(
        recipientChannel: 3,
        command: "uname -a"
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let request = try #require({
        if case let .channelRequest(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(try requestCoder.parseExecCommand(from: request) == "uname -a")
}

@Test
func connectionMessageParserRoundTripsPseudoTerminalRequest() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let requestCoder = SSHSessionRequestCoder()
    let message = try requestCoder.makePseudoTerminalRequest(
        recipientChannel: 5,
        request: SSHPseudoTerminalRequest(
            terminalType: "xterm-256color",
            characterWidth: 132,
            characterHeight: 43,
            pixelWidth: 0,
            pixelHeight: 0,
            encodedTerminalModes: [0]
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let request = try #require({
        if case let .channelRequest(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(
        try requestCoder.parsePseudoTerminalRequest(from: request)
            == SSHPseudoTerminalRequest(
                terminalType: "xterm-256color",
                characterWidth: 132,
                characterHeight: 43,
                pixelWidth: 0,
                pixelHeight: 0,
                encodedTerminalModes: [0]
            )
    )
}

@Test
func connectionMessageParserRoundTripsShellRequest() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let requestCoder = SSHSessionRequestCoder()
    let message = requestCoder.makeShellRequest(recipientChannel: 3)

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let request = try #require({
        if case let .channelRequest(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    try requestCoder.parseShellRequest(from: request)
}

@Test
func connectionMessageParserRoundTripsEnvironmentRequest() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let requestCoder = SSHSessionRequestCoder()
    let environmentVariable = SSHSessionEnvironmentVariable(
        name: "LANG",
        value: "en_US.UTF-8"
    )
    let message = requestCoder.makeEnvironmentRequest(
        recipientChannel: 6,
        environmentVariable: environmentVariable
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let request = try #require({
        if case let .channelRequest(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(try requestCoder.parseEnvironmentRequest(from: request) == environmentVariable)
}

@Test
func connectionMessageParserRoundTripsSubsystemRequest() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let requestCoder = SSHSessionRequestCoder()
    let message = requestCoder.makeSubsystemRequest(
        recipientChannel: 7,
        subsystem: "sftp"
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let request = try #require({
        if case let .channelRequest(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(try requestCoder.parseSubsystemRequest(from: request) == "sftp")
}

@Test
func connectionMessageParserRoundTripsExitStatusRequest() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let requestCoder = SSHSessionRequestCoder()
    let message = requestCoder.makeExitStatusRequest(
        recipientChannel: 9,
        exitStatus: 23
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let request = try #require({
        if case let .channelRequest(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(try requestCoder.parseExitStatus(from: request) == 23)
}

@Test
func connectionMessageParserRoundTripsWindowChangeRequest() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let requestCoder = SSHSessionRequestCoder()
    let message = requestCoder.makeWindowChangeRequest(
        recipientChannel: 11,
        windowChange: SSHPseudoTerminalWindowChange(
            characterWidth: 132,
            characterHeight: 43,
            pixelWidth: 1440,
            pixelHeight: 900
        )
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let request = try #require({
        if case let .channelRequest(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(!request.wantReply)
    #expect(
        try requestCoder.parseWindowChangeRequest(from: request)
            == SSHPseudoTerminalWindowChange(
                characterWidth: 132,
                characterHeight: 43,
                pixelWidth: 1440,
                pixelHeight: 900
            )
    )
}

@Test
func connectionMessageParserRoundTripsSignalRequest() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let requestCoder = SSHSessionRequestCoder()
    let message = requestCoder.makeSignalRequest(
        recipientChannel: 13,
        signal: .terminate
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let request = try #require({
        if case let .channelRequest(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(!request.wantReply)
    #expect(try requestCoder.parseSignalRequest(from: request) == .terminate)
}

@Test
func connectionMessageParserRoundTripsExitSignalRequest() throws {
    let serializer = SSHConnectionMessageSerializer()
    let parser = SSHConnectionMessageParser()
    let requestCoder = SSHSessionRequestCoder()
    let exitSignal = SSHSessionExitSignal(
        signal: .segmentationViolation,
        didCoreDump: true,
        errorMessage: "segfault",
        languageTag: "en-US"
    )
    let message = requestCoder.makeExitSignalRequest(
        recipientChannel: 17,
        exitSignal: exitSignal
    )

    let bytes = try serializer.serialize(message)
    let decoded = try parser.parse(bytes)
    let request = try #require({
        if case let .channelRequest(value) = decoded {
            return value
        }
        return nil
    }())

    #expect(decoded == message)
    #expect(!request.wantReply)
    #expect(try requestCoder.parseExitSignal(from: request) == exitSignal)
}

@Test
func sessionRequestCoderRejectsPseudoTerminalRequestWithoutTerminator() throws {
    let request = SSHChannelRequestMessage(
        recipientChannel: 1,
        requestType: "pty-req",
        wantReply: true,
        requestData: {
            var writer = SSHWireWriter()
            writer.write(utf8: "xterm")
            writer.write(uint32: 80)
            writer.write(uint32: 24)
            writer.write(uint32: 0)
            writer.write(uint32: 0)
            writer.write(string: [0x01, 0x02])
            return writer.bytes
        }()
    )

    do {
        _ = try SSHSessionRequestCoder().parsePseudoTerminalRequest(from: request)
        Issue.record("Expected invalid-pseudo-terminal-modes error")
    } catch {
        #expect(error as? SSHConnectionError == .invalidPseudoTerminalModes)
    }
}

@Test
func sessionRequestCoderRejectsWrongRequestType() throws {
    let request = SSHChannelRequestMessage(
        recipientChannel: 1,
        requestType: "shell",
        wantReply: true,
        requestData: []
    )

    do {
        _ = try SSHSessionRequestCoder().parseExecCommand(from: request)
        Issue.record("Expected invalid-channel-request error")
    } catch {
        #expect(error as? SSHConnectionError == .invalidChannelRequest("shell"))
    }
}

@Test
func tcpipForwardingRequestCoderRejectsOutOfRangePort() throws {
    let request = SSHGlobalRequestMessage(
        requestName: "tcpip-forward",
        wantReply: true,
        requestData: {
            var writer = SSHWireWriter()
            writer.write(utf8: "127.0.0.1")
            writer.write(uint32: 70_000)
            return writer.bytes
        }()
    )

    do {
        _ = try SSHTCPIPForwardingRequestCoder().parseForwardRequest(from: request)
        Issue.record("Expected invalid-tcpip-port error")
    } catch {
        #expect(error as? SSHConnectionError == .invalidTCPIPPort(70_000))
    }
}
