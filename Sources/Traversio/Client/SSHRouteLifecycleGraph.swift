struct SSHRouteLifecycleGraph: Sendable {
    struct EdgeID: Hashable, Comparable, Sendable, CustomStringConvertible {
        let rawValue: Int

        var description: String {
            "edge-\(rawValue)"
        }

        static func < (lhs: EdgeID, rhs: EdgeID) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }

    let plan: SSHRoutePlan
    let edges: [SSHRouteLifecycleEdge]

    init(plan: SSHRoutePlan) {
        self.plan = plan
        self.edges = Self.buildEdges(for: plan)
    }

    var rootEdge: SSHRouteLifecycleEdge {
        edges[0]
    }

    var finalEdge: SSHRouteLifecycleEdge {
        edges[edges.count - 1]
    }

    func edge(id: EdgeID) -> SSHRouteLifecycleEdge? {
        edges.first { $0.id == id }
    }

    func childBeforeParentTeardownOrder() -> [SSHRouteLifecycleEdge] {
        edges.reversed()
    }

    func sshHopEdgeID(ordinal: Int) -> EdgeID? {
        self.edges.first { edge in
            if case let .sshHop(edgeOrdinal, _) = edge.role {
                return edgeOrdinal == ordinal
            }
            return false
        }?.id
    }

    var finalSSHEdgeID: EdgeID {
        self.finalEdge.id
    }

    func transportEdgeID(forConnectionEdgeID edgeID: EdgeID) -> EdgeID? {
        guard let parentID = self.edge(id: edgeID)?.parentID,
              let parentEdge = self.edge(id: parentID)
        else {
            return nil
        }

        switch parentEdge.role {
        case .tcpRoot, .directTCPIP:
            return parentID
        case .sshHop, .finalSSH:
            return nil
        }
    }

    func externallyClosedFinalEdgeIDs() -> [EdgeID] {
        var edgeIDs = [self.finalSSHEdgeID]
        if let transportEdgeID = self.transportEdgeID(forConnectionEdgeID: self.finalSSHEdgeID) {
            edgeIDs.append(transportEdgeID)
        }
        return edgeIDs
    }

    private static func buildEdges(for plan: SSHRoutePlan) -> [SSHRouteLifecycleEdge] {
        var builder = SSHRouteLifecycleGraphBuilder()

        let rootID = builder.append(
            role: .tcpRoot(endpoint: plan.rootEndpoint, connectionProxy: plan.connectionProxy),
            parentID: nil,
            owner: .routeScope,
            requirements: .routeRoot
        )

        var upstreamConnectionID: EdgeID?

        for (index, hop) in plan.proxyJumpHosts.enumerated() {
            let hopOrdinal = index + 1
            let hopEndpoint = SSHSocketEndpoint(host: hop.host, port: hop.port)
            let parentID: EdgeID

            if let upstreamConnectionID {
                parentID = builder.append(
                    role: .directTCPIP(ordinal: hopOrdinal, endpoint: hopEndpoint),
                    parentID: upstreamConnectionID,
                    owner: .parentSSHConnection,
                    requirements: .channel
                )
            } else {
                parentID = rootID
            }

            upstreamConnectionID = builder.append(
                role: .sshHop(ordinal: hopOrdinal, endpoint: hopEndpoint),
                parentID: parentID,
                owner: .routeScope,
                requirements: .sshConnection
            )
        }

        let finalParentID: EdgeID
        if let upstreamConnectionID {
            finalParentID = builder.append(
                role: .directTCPIP(ordinal: plan.proxyJumpHosts.count + 1, endpoint: plan.finalEndpoint),
                parentID: upstreamConnectionID,
                owner: .parentSSHConnection,
                requirements: .channel
            )
        } else {
            finalParentID = rootID
        }

        _ = builder.append(
            role: .finalSSH(endpoint: plan.finalEndpoint),
            parentID: finalParentID,
            owner: .publicConnection,
            requirements: .publicConnection
        )

        return builder.edges
    }
}

struct SSHRouteLifecycleEdge: Equatable, Sendable {
    let id: SSHRouteLifecycleGraph.EdgeID
    let role: SSHRouteLifecycleEdgeRole
    let parentID: SSHRouteLifecycleGraph.EdgeID?
    let owner: SSHRouteLifecycleEdgeOwner
    let requirements: SSHRouteLifecycleRequirements
}

enum SSHRouteLifecycleEdgeRole: Equatable, Sendable {
    case tcpRoot(endpoint: SSHSocketEndpoint, connectionProxy: SSHConnectionProxy?)
    case sshHop(ordinal: Int, endpoint: SSHSocketEndpoint)
    case directTCPIP(ordinal: Int, endpoint: SSHSocketEndpoint)
    case finalSSH(endpoint: SSHSocketEndpoint)
}

enum SSHRouteLifecycleEdgeOwner: Equatable, Sendable {
    case routeScope
    case parentSSHConnection
    case publicConnection
}

enum SSHRouteLifecycleEdgeState: Equatable, Sendable {
    case planned
    case acquiring
    case acquired
    case publicConnection
    case closing
    case aborting
    case closed
    case failed
}

struct SSHRouteLifecycleSnapshot: Equatable, Sendable {
    let edgeStates: [SSHRouteLifecycleGraph.EdgeID: SSHRouteLifecycleEdgeState]
    let acquiredConnectionEdgeIDs: [SSHRouteLifecycleGraph.EdgeID]
    let teardownOrder: [SSHRouteLifecycleGraph.EdgeID]
}

struct SSHRouteLifecycleRequirements: Equatable, Sendable {
    let needsDeterministicAbort: Bool
    let allowsGracefulDisconnect: Bool
    let mayBeStructuredNetworkScopeRoot: Bool

    static let routeRoot = SSHRouteLifecycleRequirements(
        needsDeterministicAbort: true,
        allowsGracefulDisconnect: false,
        mayBeStructuredNetworkScopeRoot: true
    )

    static let sshConnection = SSHRouteLifecycleRequirements(
        needsDeterministicAbort: true,
        allowsGracefulDisconnect: true,
        mayBeStructuredNetworkScopeRoot: false
    )

    static let channel = SSHRouteLifecycleRequirements(
        needsDeterministicAbort: true,
        allowsGracefulDisconnect: false,
        mayBeStructuredNetworkScopeRoot: false
    )

    static let publicConnection = SSHRouteLifecycleRequirements(
        needsDeterministicAbort: true,
        allowsGracefulDisconnect: true,
        mayBeStructuredNetworkScopeRoot: false
    )
}

private struct SSHRouteLifecycleGraphBuilder {
    private(set) var edges: [SSHRouteLifecycleEdge] = []

    mutating func append(
        role: SSHRouteLifecycleEdgeRole,
        parentID: SSHRouteLifecycleGraph.EdgeID?,
        owner: SSHRouteLifecycleEdgeOwner,
        requirements: SSHRouteLifecycleRequirements
    ) -> SSHRouteLifecycleGraph.EdgeID {
        let id = SSHRouteLifecycleGraph.EdgeID(rawValue: edges.count)
        edges.append(
            SSHRouteLifecycleEdge(
                id: id,
                role: role,
                parentID: parentID,
                owner: owner,
                requirements: requirements
            )
        )
        return id
    }
}
