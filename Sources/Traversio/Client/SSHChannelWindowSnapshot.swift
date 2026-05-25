// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

/// Receive and send window counters for one SSH channel.
///
/// This is mainly a diagnostic and advanced flow-control surface.
public struct SSHChannelWindowSnapshot: Equatable, Sendable {
    /// Local Channel ID.
    public let localChannelID: UInt32
    /// Remote Channel ID.
    public let remoteChannelID: UInt32
    /// Receive Window byte count.
    public let receiveWindowByteCount: UInt32
    /// Receive Initial Window byte count.
    public let receiveInitialWindowByteCount: UInt32
    /// Send Window byte count.
    public let sendWindowByteCount: UInt32
    /// Send Initial Window byte count.
    public let sendInitialWindowByteCount: UInt32
    /// Send Maximum Packet byte count.
    public let sendMaximumPacketByteCount: UInt32
    /// Creates an SSHChannelWindowSnapshot.

    public init(
        localChannelID: UInt32,
        remoteChannelID: UInt32,
        receiveWindowByteCount: UInt32,
        receiveInitialWindowByteCount: UInt32,
        sendWindowByteCount: UInt32,
        sendInitialWindowByteCount: UInt32,
        sendMaximumPacketByteCount: UInt32
    ) {
        self.localChannelID = localChannelID
        self.remoteChannelID = remoteChannelID
        self.receiveWindowByteCount = receiveWindowByteCount
        self.receiveInitialWindowByteCount = receiveInitialWindowByteCount
        self.sendWindowByteCount = sendWindowByteCount
        self.sendInitialWindowByteCount = sendInitialWindowByteCount
        self.sendMaximumPacketByteCount = sendMaximumPacketByteCount
    }
}
