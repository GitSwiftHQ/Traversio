// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

struct SSHForwardingFlowGraph: Equatable, Sendable {
    struct EdgeID: Hashable, Comparable, Sendable, CustomStringConvertible {
        let rawValue: Int

        var description: String {
            "forwarding-edge-\(self.rawValue)"
        }

        static func < (lhs: EdgeID, rhs: EdgeID) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }

    let kind: SSHForwardingFlowKind
    let transportBackendPreference: SSHTCPTransportBackendPreference
    let modernTransportAvailable: Bool
    let edges: [SSHForwardingFlowEdge]

    init(
        kind: SSHForwardingFlowKind,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic
    ) {
        self.init(
            kind: kind,
            transportBackendPreference: transportBackendPreference,
            modernTransportAvailable: SSHTCPTransportFlowPolicy.isModernNetworkConnectionAvailable
        )
    }

    init(
        kind: SSHForwardingFlowKind,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic,
        modernTransportAvailable: Bool
    ) {
        self.kind = kind
        self.transportBackendPreference = transportBackendPreference
        self.modernTransportAvailable = modernTransportAvailable
        self.edges = Self.buildEdges(
            kind: kind,
            transportBackendPreference: transportBackendPreference,
            modernTransportAvailable: modernTransportAvailable
        )
    }

    var parentConnectionEdgeID: EdgeID {
        self.edges[0].id
    }

    var childBeforeParentTeardownOrder: [EdgeID] {
        self.edges.reversed().map(\.id)
    }

    var localListenerTransportPolicy: SSHTCPTransportFlowPolicy? {
        self.transportPolicy(for: .localTCPListener)
    }

    var bridgeLocalTransportPolicy: SSHTCPTransportFlowPolicy? {
        self.transportPolicy(for: .bridgeLocalTCPTransport)
    }

    func edge(id: EdgeID) -> SSHForwardingFlowEdge? {
        self.edges.first { $0.id == id }
    }

    func edge(withResourceKind resourceKind: SSHForwardingFlowResourceKind) -> SSHForwardingFlowEdge? {
        self.edges.first { $0.resource.kind == resourceKind }
    }

    private func transportPolicy(
        for resourceKind: SSHForwardingFlowResourceKind
    ) -> SSHTCPTransportFlowPolicy? {
        guard let edge = self.edge(withResourceKind: resourceKind) else {
            return nil
        }

        switch edge.resource {
        case let .localTCPListener(policy), let .bridgeLocalTCPTransport(policy):
            return policy
        case .parentSSHConnection,
             .localTCPListenerTask,
             .remoteTCPListener,
             .remoteStreamLocalListener,
             .remoteAcceptLoopTask,
             .connectionClosureMonitorTask,
             .fallbackLivenessTask,
             .acceptedLocalTCPConnection,
             .acceptedForwardedTCPIPChannel,
             .socks5Negotiation,
             .directTCPIPChannel,
             .bridgeTask,
             .callerBody:
            return nil
        }
    }

    private static func buildEdges(
        kind: SSHForwardingFlowKind,
        transportBackendPreference: SSHTCPTransportBackendPreference,
        modernTransportAvailable: Bool
    ) -> [SSHForwardingFlowEdge] {
        var builder = SSHForwardingFlowGraphBuilder()
        let parentConnectionID = builder.append(
            resource: .parentSSHConnection,
            parentID: nil,
            owner: .publicSSHConnection
        )

        switch kind {
        case .localTCP:
            self.appendLocalTCPListenerFlow(
                builder: &builder,
                parentConnectionID: parentConnectionID,
                transportBackendPreference: transportBackendPreference,
                modernTransportAvailable: modernTransportAvailable,
                includeSOCKSNegotiation: false
            )
        case .dynamicSOCKS5:
            self.appendLocalTCPListenerFlow(
                builder: &builder,
                parentConnectionID: parentConnectionID,
                transportBackendPreference: transportBackendPreference,
                modernTransportAvailable: modernTransportAvailable,
                includeSOCKSNegotiation: true
            )
        case .remoteTCPListener:
            self.appendRemoteListenerFlow(
                builder: &builder,
                parentConnectionID: parentConnectionID,
                listenerResource: .remoteTCPListener,
                includeAcceptLoop: false
            )
        case .remoteStreamLocalListener:
            self.appendRemoteListenerFlow(
                builder: &builder,
                parentConnectionID: parentConnectionID,
                listenerResource: .remoteStreamLocalListener,
                includeAcceptLoop: false
            )
        case .remoteTCPBridge:
            self.appendRemoteListenerFlow(
                builder: &builder,
                parentConnectionID: parentConnectionID,
                listenerResource: .remoteTCPListener,
                includeAcceptLoop: true,
                transportBackendPreference: transportBackendPreference,
                modernTransportAvailable: modernTransportAvailable
            )
        }

        return builder.edges
    }

    private static func appendLocalTCPListenerFlow(
        builder: inout SSHForwardingFlowGraphBuilder,
        parentConnectionID: EdgeID,
        transportBackendPreference: SSHTCPTransportBackendPreference,
        modernTransportAvailable: Bool,
        includeSOCKSNegotiation: Bool
    ) {
        let listenerID = builder.append(
            resource: .localTCPListener(
                SSHTCPTransportFlowPolicy.resolve(
                    role: .lifecycleControlledListener,
                    preference: transportBackendPreference,
                    modernAvailable: modernTransportAvailable
                )
            ),
            parentID: parentConnectionID,
            owner: .forwardingScope
        )
        builder.append(
            resource: .connectionClosureMonitorTask,
            parentID: parentConnectionID,
            owner: .forwardingScope
        )
        builder.append(
            resource: .fallbackLivenessTask,
            parentID: parentConnectionID,
            owner: .forwardingScope
        )
        let listenerTaskID = builder.append(
            resource: .localTCPListenerTask,
            parentID: listenerID,
            owner: .forwardingScope
        )
        let acceptedConnectionID = builder.append(
            resource: .acceptedLocalTCPConnection,
            parentID: listenerTaskID,
            owner: .acceptedConnectionTask
        )
        let directChannelParentID: EdgeID
        if includeSOCKSNegotiation {
            directChannelParentID = builder.append(
                resource: .socks5Negotiation,
                parentID: acceptedConnectionID,
                owner: .acceptedConnectionTask
            )
        } else {
            directChannelParentID = acceptedConnectionID
        }
        let directChannelID = builder.append(
            resource: .directTCPIPChannel(parentConnectionEdgeID: parentConnectionID),
            parentID: directChannelParentID,
            owner: .acceptedConnectionTask
        )
        builder.append(
            resource: .bridgeTask,
            parentID: directChannelID,
            owner: .acceptedConnectionTask
        )
        builder.append(
            resource: .callerBody,
            parentID: listenerID,
            owner: .callerBody
        )
    }

    private static func appendRemoteListenerFlow(
        builder: inout SSHForwardingFlowGraphBuilder,
        parentConnectionID: EdgeID,
        listenerResource: SSHForwardingFlowResource,
        includeAcceptLoop: Bool,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic,
        modernTransportAvailable: Bool = false
    ) {
        let listenerID = builder.append(
            resource: listenerResource,
            parentID: parentConnectionID,
            owner: .forwardingScope
        )
        builder.append(
            resource: .connectionClosureMonitorTask,
            parentID: parentConnectionID,
            owner: .forwardingScope
        )
        builder.append(
            resource: .fallbackLivenessTask,
            parentID: parentConnectionID,
            owner: .forwardingScope
        )

        guard includeAcceptLoop else {
            builder.append(
                resource: .callerBody,
                parentID: listenerID,
                owner: .callerBody
            )
            return
        }

        let acceptLoopID = builder.append(
            resource: .remoteAcceptLoopTask,
            parentID: listenerID,
            owner: .forwardingScope
        )
        let acceptedChannelID = builder.append(
            resource: .acceptedForwardedTCPIPChannel(parentConnectionEdgeID: parentConnectionID),
            parentID: acceptLoopID,
            owner: .acceptedConnectionTask
        )
        let localTransportID = builder.append(
            resource: .bridgeLocalTCPTransport(
                SSHTCPTransportFlowPolicy.resolve(
                    role: .scopedConnection,
                    preference: transportBackendPreference,
                    modernAvailable: modernTransportAvailable
                )
            ),
            parentID: acceptedChannelID,
            owner: .acceptedConnectionTask
        )
        builder.append(
            resource: .bridgeTask,
            parentID: localTransportID,
            owner: .acceptedConnectionTask
        )
        builder.append(
            resource: .callerBody,
            parentID: listenerID,
            owner: .callerBody
        )
    }
}

enum SSHForwardingFlowKind: Equatable, Sendable {
    case localTCP
    case dynamicSOCKS5
    case remoteTCPListener
    case remoteTCPBridge
    case remoteStreamLocalListener
}

struct SSHForwardingFlowEdge: Equatable, Sendable {
    let id: SSHForwardingFlowGraph.EdgeID
    let resource: SSHForwardingFlowResource
    let parentID: SSHForwardingFlowGraph.EdgeID?
    let owner: SSHForwardingFlowOwner
}

enum SSHForwardingFlowOwner: Equatable, Sendable {
    case publicSSHConnection
    case forwardingScope
    case acceptedConnectionTask
    case callerBody
}

enum SSHForwardingFlowResource: Equatable, Sendable {
    case parentSSHConnection
    case localTCPListener(SSHTCPTransportFlowPolicy)
    case localTCPListenerTask
    case remoteTCPListener
    case remoteStreamLocalListener
    case remoteAcceptLoopTask
    case connectionClosureMonitorTask
    case fallbackLivenessTask
    case acceptedLocalTCPConnection
    case acceptedForwardedTCPIPChannel(parentConnectionEdgeID: SSHForwardingFlowGraph.EdgeID)
    case socks5Negotiation
    case directTCPIPChannel(parentConnectionEdgeID: SSHForwardingFlowGraph.EdgeID)
    case bridgeLocalTCPTransport(SSHTCPTransportFlowPolicy)
    case bridgeTask
    case callerBody

    var kind: SSHForwardingFlowResourceKind {
        switch self {
        case .parentSSHConnection:
            .parentSSHConnection
        case .localTCPListener:
            .localTCPListener
        case .localTCPListenerTask:
            .localTCPListenerTask
        case .remoteTCPListener:
            .remoteTCPListener
        case .remoteStreamLocalListener:
            .remoteStreamLocalListener
        case .remoteAcceptLoopTask:
            .remoteAcceptLoopTask
        case .connectionClosureMonitorTask:
            .connectionClosureMonitorTask
        case .fallbackLivenessTask:
            .fallbackLivenessTask
        case .acceptedLocalTCPConnection:
            .acceptedLocalTCPConnection
        case .acceptedForwardedTCPIPChannel:
            .acceptedForwardedTCPIPChannel
        case .socks5Negotiation:
            .socks5Negotiation
        case .directTCPIPChannel:
            .directTCPIPChannel
        case .bridgeLocalTCPTransport:
            .bridgeLocalTCPTransport
        case .bridgeTask:
            .bridgeTask
        case .callerBody:
            .callerBody
        }
    }
}

enum SSHForwardingFlowResourceKind: Equatable, Sendable {
    case parentSSHConnection
    case localTCPListener
    case localTCPListenerTask
    case remoteTCPListener
    case remoteStreamLocalListener
    case remoteAcceptLoopTask
    case connectionClosureMonitorTask
    case fallbackLivenessTask
    case acceptedLocalTCPConnection
    case acceptedForwardedTCPIPChannel
    case socks5Negotiation
    case directTCPIPChannel
    case bridgeLocalTCPTransport
    case bridgeTask
    case callerBody
}

private struct SSHForwardingFlowGraphBuilder {
    private(set) var edges: [SSHForwardingFlowEdge] = []

    @discardableResult
    mutating func append(
        resource: SSHForwardingFlowResource,
        parentID: SSHForwardingFlowGraph.EdgeID?,
        owner: SSHForwardingFlowOwner
    ) -> SSHForwardingFlowGraph.EdgeID {
        let id = SSHForwardingFlowGraph.EdgeID(rawValue: self.edges.count)
        self.edges.append(
            SSHForwardingFlowEdge(
                id: id,
                resource: resource,
                parentID: parentID,
                owner: owner
            )
        )
        return id
    }
}
