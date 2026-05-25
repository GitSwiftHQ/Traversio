// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package enum SSHTransportError: Error, Equatable, Sendable {
    case invalidPort(UInt16)
    case invalidProxyConfiguration(String)
    case invalidSOCKSConfiguration(String)
    case proxyHandshakeFailed(String)
    case socksHandshakeFailed(String)
    case unsupportedTransportBackend(String)
    case transportClosed
    case emptyReceive
    case endOfStreamBeforeIdentification
    case versionExchangeRequired
    case endOfStreamBeforePacket
    case unexpectedTransportMessage(expected: SSHTransportMessageID, received: SSHTransportMessageID)
    case strictKeyExchangeViolation(String)
    case unsupportedEndpoint(String)
    case listenerDidNotReportPort
    case internalInvariantBroken(String)
}
