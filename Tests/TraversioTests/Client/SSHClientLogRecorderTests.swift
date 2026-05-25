// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
import Testing
@testable import Traversio

@Test
func sshClientLogRecorderRetainsRecentEventsAndCountsDroppedEntries() {
    let recorder = SSHClientLogRecorder(maximumEventCount: 2)

    recorder.record(
        SSHClientLogEvent(
            timestamp: Date(timeIntervalSince1970: 10),
            level: .info,
            category: .connection,
            message: "first"
        )
    )
    recorder.record(
        SSHClientLogEvent(
            timestamp: Date(timeIntervalSince1970: 11),
            level: .warning,
            category: .session,
            message: "second"
        )
    )
    recorder.record(
        SSHClientLogEvent(
            timestamp: Date(timeIntervalSince1970: 12),
            level: .error,
            category: .sftp,
            message: "third"
        )
    )

    let snapshot = recorder.snapshot()
    #expect(snapshot.maximumEventCount == 2)
    #expect(snapshot.droppedEventCount == 1)
    #expect(snapshot.events.count == 2)
    #expect(snapshot.events[0].message == "second")
    #expect(snapshot.events[1].message == "third")
    #expect(snapshot.formattedText.contains("dropped-log-events: 1"))
    #expect(snapshot.formattedText.contains("message=\"second\""))
    #expect(snapshot.formattedText.contains("message=\"third\""))
}

@Test
func sshClientLogHandlerRecorderFactoryRespectsMinimumLevelAndBuildsDiagnosticExport() throws {
    let recorder = SSHClientLogRecorder(maximumEventCount: 4)
    let handler = SSHClientLogHandler.recorder(recorder, minimumLevel: .info)

    handler.emit(
        level: .debug,
        category: .transport,
        message: "debug should be filtered"
    )
    handler.emit(
        level: .info,
        category: .connection,
        message: "Starting SSH connection setup.",
        metadata: [
            "endpointHost": "example.com",
            "endpointPort": "22",
        ]
    )

    let failure = SSHConnectionFailure(
        stage: .transport,
        code: .timeout,
        message: "Timed out after 5.000s while waiting for SSH connection setup to complete.",
        diagnostics: SSHConnectionFailureDiagnostics(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "deploy",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: nil,
            preIdentificationLines: [],
            callbackFailure: nil,
            keepaliveIntervalNanoseconds: nil,
            keepaliveReplyTimeoutNanoseconds: nil,
            responseTimeoutNanoseconds: nil,
            negotiatedAlgorithms: nil,
            didReceiveServerExtensionInfo: false,
            serverExtensionNames: [],
            serverSignatureAlgorithms: nil,
            remoteDisconnect: nil,
            remoteDebugMessages: []
        )
    )

    let report = try #require(
        recorder.diagnosticReport(for: SSHClientError.connectionFailed(failure))
    )

    let snapshot = recorder.snapshot()
    #expect(snapshot.events.count == 1)
    #expect(snapshot.events[0].message == "Starting SSH connection setup.")
    #expect(report.contains("SSH connection failure"))
    #expect(report.contains("stage: transport"))
    #expect(report.contains("message=\"Starting SSH connection setup.\""))
    #expect(report.contains("endpointHost=\"example.com\""))
    #expect(report.contains("endpointPort=\"22\""))
    #expect(report.contains("debug should be filtered") == false)
}

@Test
func sshClientLogRecorderBuildsScopeEndedSupportExportWithStateLogs() throws {
    let recorder = SSHClientLogRecorder(maximumEventCount: 4)
    let handler = recorder.logHandler(minimumLevel: .info)

    handler.emit(
        level: .warning,
        category: .connection,
        message: "SSH connection state changed.",
        metadata: [
            "connectionState": "lost",
            "stateTrigger": "background-failure",
            "detail": "secret=background-secret",
        ]
    )

    let report = try #require(
        recorder.diagnosticReport(for: SSHClientError.connectionScopeEnded)
    )

    #expect(report.contains("SSH client error"))
    #expect(report.contains("case: connectionScopeEnded"))
    #expect(report.contains("message: The SSH connection scope ended"))
    #expect(report.contains("message=\"SSH connection state changed.\""))
    #expect(report.contains("connectionState=\"lost\""))
    #expect(report.contains("stateTrigger=\"background-failure\""))
    #expect(report.contains("background-secret") == false)
    #expect(report.contains("detail=\"secret=<redacted>\""))
}

@Test
func sshClientLogRecorderBuildsAuthenticationSupportExport() throws {
    let report = try #require(
        SSHClientLogRecorder()
            .diagnosticReport(
                for: SSHClientError.authenticationRejected(
                    methodName: "password",
                    availableMethods: ["publickey", "keyboard-interactive"],
                    partialSuccess: true,
                    banners: [
                        SSHAuthenticationBanner(
                            message: "token=auth-token",
                            languageTag: "secret=auth-language-secret"
                        )
                    ]
                )
            )
    )

    #expect(report.contains("SSH client error"))
    #expect(report.contains("case: authenticationRejected"))
    #expect(report.contains("authentication-method: password"))
    #expect(report.contains("available-methods: publickey,keyboard-interactive"))
    #expect(report.contains("partial-success: true"))
    #expect(report.contains("auth-token") == false)
    #expect(report.contains("auth-language-secret") == false)
    #expect(
        report.contains(
            "authentication-banner[0]: languageTag=secret=<redacted> message=token=<redacted>"
        )
    )
}

@Test
func sshClientLogRecorderBuildsPasswordChangeSupportExportWithRedactedServerText() throws {
    let report = try #require(
        SSHClientLogRecorder()
            .diagnosticReport(
                for: SSHClientError.passwordChangeRequired(
                    prompt: "password=expired-password",
                    languageTag: "token=password-change-language-token",
                    banners: [
                        SSHAuthenticationBanner(
                            message: "credential=password-change-banner",
                            languageTag: "secret=password-change-banner-language"
                        )
                    ]
                )
            )
    )

    #expect(report.contains("SSH client error"))
    #expect(report.contains("case: passwordChangeRequired"))
    #expect(report.contains("expired-password") == false)
    #expect(report.contains("password-change-language-token") == false)
    #expect(report.contains("password-change-banner") == false)
    #expect(report.contains("password-change-banner-language") == false)
    #expect(report.contains("password-change-prompt: password=<redacted>"))
    #expect(report.contains("password-change-language-tag: token=<redacted>"))
    #expect(
        report.contains(
            "authentication-banner[0]: languageTag=secret=<redacted> message=credential=<redacted>"
        )
    )
}

@Test
func sshClientLogRecorderClearDropsRetainedEventsAndResetDropCount() {
    let recorder = SSHClientLogRecorder(maximumEventCount: 1)

    recorder.record(
        SSHClientLogEvent(
            level: .info,
            category: .connection,
            message: "first"
        )
    )
    recorder.record(
        SSHClientLogEvent(
            level: .warning,
            category: .connection,
            message: "second"
        )
    )

    recorder.clear()

    let snapshot = recorder.snapshot()
    #expect(snapshot.events.isEmpty)
    #expect(snapshot.droppedEventCount == 0)
    #expect(snapshot.formattedText.isEmpty)
    #expect(recorder.diagnosticReport() == nil)
}
