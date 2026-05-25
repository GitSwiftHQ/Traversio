// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation
@testable import Traversio

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, visionOS 1.0, *)
func makePublicSFTPClient(
    from client: SSHTransportProtocolClient
) async throws -> SFTPClient {
    let connection = SSHConnection(
        metadata: SSHConnectionMetadata(
            endpointHost: "example.com",
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-OpenSSH_9.9 test",
            preIdentificationLines: [],
            hostKeyAlgorithm: "ssh-ed25519",
            hostKeyFingerprintSHA256: "fingerprint",
            hostKeyTrustMethod: .acceptAnyVerifiedHostKey
        ),
        client: client,
        lifetime: SSHConnectionLifetime(),
        logHandler: .disabled
    )
    return try await connection.openSFTP()
}
