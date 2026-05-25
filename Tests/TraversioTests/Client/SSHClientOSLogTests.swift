// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import OSLog
import Testing
@testable import Traversio

@Test
func sshOSLogMetadataDescriptionSortsKeysDeterministically() {
    let description = sshOSLogMetadataDescription(
        [
            "endpointPort": "22",
            "code": "transportError",
            "endpointHost": "example.com",
        ]
    )

    #expect(
        description ==
            "code=transportError endpointHost=example.com endpointPort=22"
    )
}

@Test
func sshOSLogMessageAppendsSortedMetadata() {
    let event = SSHClientLogEvent(
        level: .error,
        category: .connection,
        message: "SSH connection setup failed.",
        metadata: [
            "stage": "transport",
            "code": "transportError",
        ]
    )

    #expect(
        sshOSLogMessage(for: event) ==
            "[connection] SSH connection setup failed. code=transportError stage=transport"
    )
}

@Test
func sshClientLogEventFormattedLineQuotesMessageAndMetadata() {
    let event = SSHClientLogEvent(
        timestamp: Date(timeIntervalSince1970: 1_712_345_678.25),
        level: .warning,
        category: .connection,
        message: "Connection failed before banner",
        metadata: [
            "endpointHost": "example.com",
            "remoteIdentification": "SSH-2.0-OpenSSH_9.9 test",
        ]
    )

    #expect(
        event.formattedLine
            == "timestamp=\"2024-04-05T19:34:38.250Z\" level=warning category=connection message=\"Connection failed before banner\" endpointHost=\"example.com\" remoteIdentification=\"SSH-2.0-OpenSSH_9.9 test\""
    )
}

@Test
func sshDiagnosticQuotedEscapesControlCharacters() {
    #expect(
        sshDiagnosticQuoted("line 1\nline \"2\"\r")
            == "\"line 1\\nline \\\"2\\\"\\r\""
    )
}

@available(macOS 11.0, iOS 14.0, tvOS 14.0, watchOS 7.0, visionOS 1.0, *)
@Test
func sshOSLogTypeMapsLibraryLevelsToExpectedOSLogLevels() {
    #expect(sshOSLogType(for: .debug) == .debug)
    #expect(sshOSLogType(for: .info) == .info)
    #expect(sshOSLogType(for: .notice) == .default)
    #expect(sshOSLogType(for: .warning) == .error)
    #expect(sshOSLogType(for: .error) == .fault)
}

@available(macOS 11.0, iOS 14.0, tvOS 14.0, watchOS 7.0, visionOS 1.0, *)
@Test
func sshClientLogHandlerOSLogFactoryBuildsHandler() {
    let handler = SSHClientLogHandler.osLog(
        Logger(subsystem: "com.example.traversio-tests", category: "ssh"),
        minimumLevel: .debug
    )

    handler.emit(
        level: .info,
        category: .connection,
        message: "SSH connection established.",
        metadata: [
            "endpointHost": "example.com",
            "endpointPort": "22",
        ]
    )
}
