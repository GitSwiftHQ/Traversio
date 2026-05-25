// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

package struct SSHTransportProtocolRekeyMetricsSnapshot: Equatable, Sendable {
    package let completedRemoteRekeyCount: UInt64
    package let completedLocalRekeyCount: UInt64
    package let outboundEncryptedPacketCountSinceLastKeyExchange: UInt64
    package let inboundEncryptedPacketCountSinceLastKeyExchange: UInt64
    package let isTransportRekeyInProgress: Bool
}

package struct SSHTransportProtocolRuntimeStateSnapshot: Equatable, Sendable {
    package let setupPhase: SSHTransportProtocolSetupPhase
    package let managedSessionCount: Int
    package let pendingManagedSessionCount: Int
    package let pendingChannelOpenResponseCount: Int
    package let pendingChannelRequestReplyCount: Int
    package let pendingPreManagedSessionMessageCount: Int
    package let pendingGlobalRequestReplyCount: Int
    package let deferredConnectionMessageCount: Int
    package let pendingConnectionMessageAfterTransportRekeyCount: Int
    package let activeConnectionMessageWaiterCount: Int
    package let activeGlobalRequestReplyWaiterCount: Int
    package let inboundPacketReceiveTurnWaiterCount: Int
    package let outboundPacketSendWaiterCount: Int
    package let connectionMessageWaiterProgressWaiterCount: Int
    package let transportRekeyWaiterCount: Int
    package let isReceivingInboundPacket: Bool
    package let isSendingOutboundPacket: Bool
    package let isTransportRekeyInProgress: Bool
}
