// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func identificationSerializesWithCRLF() throws {
    let identification = try SSHIdentification(
        softwareVersion: "Traversio_1.0.3",
        comments: "dev build"
    )

    #expect(identification.rawValue == "SSH-2.0-Traversio_1.0.3 dev build")
    #expect(
        identification.serializedBytes() ==
            Array("SSH-2.0-Traversio_1.0.3 dev build\r\n".utf8)
    )
}

@Test
func identificationParserAcceptsChunkedClientBannerWithPreludeLines() throws {
    var parser = SSHIdentificationParser(role: .client)
    parser.append(bytes: Array("notice\r\nSSH-2.0-".utf8))

    #expect(try parser.nextIdentification() == nil)

    parser.append(bytes: Array("OpenSSH_9.9 comment\r\n".utf8))
    let parsedIdentification = try parser.nextIdentification()
    let identification = try #require(parsedIdentification)

    #expect(identification.protocolVersion == "2.0")
    #expect(identification.softwareVersion == "OpenSSH_9.9")
    #expect(identification.comments == "comment")
}

@Test
func identificationParserAcceptsCompatibilityVersion199() throws {
    var parser = SSHIdentificationParser(role: .client)
    parser.append(bytes: Array("SSH-1.99-OpenSSH_3.9\r\n".utf8))

    let parsedIdentification = try parser.nextIdentification()
    let identification = try #require(parsedIdentification)
    #expect(identification.protocolVersion == "1.99")
}

@Test
func serverIdentificationParserRejectsPreludeLines() throws {
    var parser = SSHIdentificationParser(role: .server)
    parser.append(bytes: Array("notice\r\n".utf8))

    do {
        _ = try parser.nextIdentification()
        Issue.record("Expected unexpected pre-identification line error")
    } catch {
        #expect(error as? SSHWireError == .unexpectedPreIdentificationLine)
    }
}

@Test
func identificationRejectsUnsupportedProtocolVersion() throws {
    do {
        _ = try SSHIdentification(rawValue: "SSH-1.5-legacy")
        Issue.record("Expected unsupported protocol version error")
    } catch {
        #expect(error as? SSHWireError == .unsupportedProtocolVersion("1.5"))
    }
}

@Test
func identificationRejectsOverlongLines() throws {
    var parser = SSHIdentificationParser(role: .client)
    let longSoftwareVersion = String(repeating: "a", count: 250)
    parser.append(bytes: Array("SSH-2.0-\(longSoftwareVersion)\r\n".utf8))

    do {
        _ = try parser.nextIdentification()
        Issue.record("Expected identification-too-long error")
    } catch {
        #expect(error as? SSHWireError == .identificationTooLong)
    }
}
