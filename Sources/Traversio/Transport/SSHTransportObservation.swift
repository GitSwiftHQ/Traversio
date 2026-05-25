// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

package enum SSHTransportObservedState: String, Equatable, Sendable {
    case setup
    case waiting
    case preparing
    case ready
    case failed
    case cancelled
}

package enum SSHTransportNetworkPathStatus: String, Equatable, Sendable {
    case satisfied
    case unsatisfied
    case requiresConnection
}

package enum SSHTransportNetworkInterface: String, Equatable, Sendable {
    case wifi
    case cellular
    case wiredEthernet
    case loopback
    case other
}

package struct SSHTransportNetworkPath: Equatable, Sendable {
    package let status: SSHTransportNetworkPathStatus
    package let availableInterfaces: [SSHTransportNetworkInterface]
    package let isExpensive: Bool
    package let isConstrained: Bool
    package let supportsIPv4: Bool
    package let supportsIPv6: Bool

    package init(
        status: SSHTransportNetworkPathStatus,
        availableInterfaces: [SSHTransportNetworkInterface],
        isExpensive: Bool,
        isConstrained: Bool,
        supportsIPv4: Bool,
        supportsIPv6: Bool
    ) {
        self.status = status
        self.availableInterfaces = availableInterfaces
        self.isExpensive = isExpensive
        self.isConstrained = isConstrained
        self.supportsIPv4 = supportsIPv4
        self.supportsIPv6 = supportsIPv6
    }
}

package enum SSHTransportObservationEvent: Equatable, Sendable {
    case stateChanged(state: SSHTransportObservedState, detail: String?)
    case networkPathChanged(SSHTransportNetworkPath)
    case viabilityChanged(Bool)
    case betterPathAvailable(Bool)
}
