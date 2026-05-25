// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test
func diagnosticLogExportRedactsSensitiveMetadataAndInlineValues() {
    let event = SSHClientLogEvent(
        level: .error,
        category: .connection,
        message: "Proxy failed password=hunter2 token=token-123 authorization: Bearer abc",
        metadata: [
            "endpointHost": "example.com",
            "password": "hunter2",
            "proxyAuthorization": "Basic dXNlcjpzZWNyZXQ=",
            "description": "secret=server-secret private_key=raw-key",
        ]
    )

    let formattedLine = event.formattedLine
    let osLogMessage = sshOSLogMessage(for: event)

    #expect(event.metadata["password"] == "<redacted>")
    #expect(event.metadata["proxyAuthorization"] == "<redacted>")
    #expect(event.metadata["endpointHost"] == "example.com")
    #expect(formattedLine.contains("endpointHost=\"example.com\""))
    #expect(osLogMessage.contains("endpointHost=example.com"))
    for sensitiveValue in [
        "hunter2",
        "token-123",
        "Bearer abc",
        "dXNlcjpzZWNyZXQ=",
        "server-secret",
        "raw-key",
    ] {
        #expect(!formattedLine.contains(sensitiveValue))
        #expect(!osLogMessage.contains(sensitiveValue))
    }
    #expect(formattedLine.contains("<redacted>"))
    #expect(osLogMessage.contains("<redacted>"))
}

@Test
func diagnosticReportsRedactRemoteAndSFTPStatusSensitiveValues() {
    let connectionFailure = SSHConnectionFailure(
        stage: .identification,
        code: .remoteDisconnect,
        message: "connection rejected password=hunter2",
        diagnostics: SSHConnectionFailureDiagnostics(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "deploy",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: ["token=pre-ident-token"],
            callbackFailure: nil,
            keepaliveIntervalNanoseconds: nil,
            keepaliveReplyTimeoutNanoseconds: nil,
            responseTimeoutNanoseconds: nil,
            negotiatedAlgorithms: nil,
            didReceiveServerExtensionInfo: false,
            serverExtensionNames: [],
            serverSignatureAlgorithms: nil,
            remoteDisconnect: SSHRemoteDisconnect(
                reasonCode: 11,
                description: "secret=remote-secret",
                languageTag: "token=remote-disconnect-language-token"
            ),
            remoteDebugMessages: [
                SSHRemoteDebugMessage(
                    alwaysDisplay: true,
                    message: "private_key=remote-key",
                    languageTag: "secret=remote-debug-language-secret"
                )
            ]
        )
    )
    let operationFailure = SSHOperationFailure(
        scope: .sftp,
        code: .requestFailed,
        message: "SFTP failed token=sftp-token",
        diagnostics: SSHOperationFailureDiagnostics(
            endpointHost: "storage.internal",
            endpointPort: 22,
            username: "deploy",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            keepaliveIntervalNanoseconds: nil,
            keepaliveReplyTimeoutNanoseconds: nil,
            responseTimeoutNanoseconds: nil,
            negotiatedAlgorithms: nil,
            didReceiveServerExtensionInfo: false,
            serverExtensionNames: [],
            remoteDisconnect: nil,
            remoteDebugMessages: [],
            localChannelID: 7,
            remoteChannelID: 42,
            requestType: "stat",
            sftpStatus: SSHSFTPStatusDetails(
                statusCode: .failure,
                message: "credential=sftp-credential",
                languageTag: "token=sftp-language-token"
            )
        )
    )

    let report = "\(connectionFailure.diagnosticReport)\n\(operationFailure.diagnosticReport)"
    for sensitiveValue in [
        "hunter2",
        "pre-ident-token",
        "remote-secret",
        "remote-disconnect-language-token",
        "remote-key",
        "remote-debug-language-secret",
        "sftp-token",
        "sftp-credential",
        "sftp-language-token",
    ] {
        #expect(report.contains(sensitiveValue) == false)
    }
    #expect(report.contains("password=<redacted>"))
    #expect(report.contains("token=<redacted>"))
    #expect(report.contains("remote-disconnect-language-tag: token=<redacted>"))
    #expect(report.contains("languageTag=secret=<redacted>"))
    #expect(report.contains("sftp-status-message: credential=<redacted>"))
    #expect(report.contains("sftp-status-language-tag: token=<redacted>"))
}

@Test
func connectionFailureDiagnosticReportIncludesNegotiatedAlgorithmsAndRemoteDebugMessages() {
    let failure = SSHConnectionFailure(
        stage: .authentication,
        code: .remoteDisconnect,
        message: "The server disconnected during connection setup with reason code 7: ssh-userauth disabled",
        diagnostics: SSHConnectionFailureDiagnostics(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: ["NOTICE ssh service"],
            callbackFailure: nil,
            keepaliveIntervalNanoseconds: 10_000_000_000,
            keepaliveReplyTimeoutNanoseconds: 10_000_000_000,
            responseTimeoutNanoseconds: nil,
            negotiatedAlgorithms: SSHNegotiatedTransportAlgorithms(
                keyExchangeAlgorithm: "curve25519-sha256",
                serverHostKeyAlgorithm: "ssh-ed25519",
                encryptionAlgorithmClientToServer: "aes128-ctr",
                encryptionAlgorithmServerToClient: "chacha20-poly1305@openssh.com",
                macAlgorithmClientToServer: "hmac-sha2-256",
                macAlgorithmServerToClient: "hmac-sha2-512-etm@openssh.com",
                compressionAlgorithmClientToServer: "zlib@openssh.com",
                compressionAlgorithmServerToClient: "zlib@openssh.com",
                usesStrictKeyExchange: true
            ),
            didReceiveServerExtensionInfo: true,
            serverExtensionNames: ["delay-compression", "server-sig-algs"],
            serverSignatureAlgorithms: ["ssh-ed25519", "rsa-sha2-512"],
            remoteDisconnect: SSHRemoteDisconnect(
                reasonCode: 7,
                description: "ssh-userauth disabled",
                languageTag: "en-US"
            ),
            remoteDebugMessages: [
                SSHRemoteDebugMessage(
                    alwaysDisplay: false,
                    message: "auth service disabled",
                    languageTag: "en-US"
                )
            ]
        )
    )

    let report = failure.diagnosticReport
    #expect(report.contains("SSH connection failure"))
    #expect(report.contains("stage: authentication"))
    #expect(report.contains("keepalive-interval: 10s"))
    #expect(report.contains("keepalive-reply-timeout: 10s"))
    #expect(report.contains("response-timeout: disabled"))
    #expect(report.contains("compression-client-to-server: zlib@openssh.com"))
    #expect(report.contains("effective-integrity-server-to-client: implicit"))
    #expect(report.contains("server-extension-names: delay-compression,server-sig-algs"))
    #expect(report.contains("remote-debug-message[0]: alwaysDisplay=false"))
}

@Test
func operationFailureDiagnosticReportIncludesChannelAndSFTPStatusDetails() {
    let failure = SSHOperationFailure(
        scope: .sftp,
        code: .requestFailed,
        message: "The server rejected the SFTP request.",
        diagnostics: SSHOperationFailureDiagnostics(
            endpointHost: "storage.internal",
            endpointPort: 22,
            username: "deploy",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            keepaliveIntervalNanoseconds: nil,
            keepaliveReplyTimeoutNanoseconds: nil,
            responseTimeoutNanoseconds: 5_000_000_000,
            negotiatedAlgorithms: nil,
            didReceiveServerExtensionInfo: false,
            serverExtensionNames: [],
            remoteDisconnect: nil,
            remoteDebugMessages: [],
            localChannelID: 7,
            remoteChannelID: 42,
            requestType: "stat",
            sftpStatus: SSHSFTPStatusDetails(
                statusCode: .failure,
                message: "failure",
                languageTag: "en-US"
            )
        )
    )

    let report = failure.diagnosticReport
    #expect(report.contains("SSH operation failure"))
    #expect(report.contains("scope: sftp"))
    #expect(report.contains("keepalive-interval: disabled"))
    #expect(report.contains("keepalive-reply-timeout: disabled"))
    #expect(report.contains("response-timeout: 5s"))
    #expect(report.contains("local-channel-id: 7"))
    #expect(report.contains("remote-channel-id: 42"))
    #expect(report.contains("request-type: stat"))
    #expect(report.contains("sftp-status-code: 4"))
    #expect(report.contains("sftp-status-name: SSH_FX_FAILURE"))
    #expect(report.contains("sftp-status-message: failure"))
}

@Test
func sftpStatusDetailsExposeTypedStatusCodeAndStandardName() {
    let knownStatus = SSHSFTPStatusDetails(
        statusCode: .permissionDenied,
        message: "denied",
        languageTag: "en-US"
    )

    #expect(knownStatus.code == 3)
    #expect(knownStatus.statusCode == .permissionDenied)
    #expect(knownStatus.standardName == "SSH_FX_PERMISSION_DENIED")

    let extensionStatus = SSHSFTPStatusDetails(
        code: 100,
        message: "server extension status",
        languageTag: nil
    )

    #expect(extensionStatus.statusCode == SSHSFTPStatusCode(rawValue: 100))
    #expect(extensionStatus.standardName == nil)
}
