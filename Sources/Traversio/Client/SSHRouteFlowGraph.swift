struct SSHRouteFlowGraph: Sendable {
    let routeGraph: SSHRouteLifecycleGraph
    let rootTransportRole: SSHTCPTransportFlowRole
    let transportBackendPreference: SSHTCPTransportBackendPreference
    let modernTransportAvailable: Bool
    let edges: [SSHRouteFlowEdge]

    init(
        routeGraph: SSHRouteLifecycleGraph,
        rootTransportRole: SSHTCPTransportFlowRole = .routeRootConnection,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic
    ) {
        self.init(
            routeGraph: routeGraph,
            rootTransportRole: rootTransportRole,
            transportBackendPreference: transportBackendPreference,
            modernTransportAvailable: SSHTCPTransportFlowPolicy.isModernNetworkConnectionAvailable
        )
    }

    init(
        routeGraph: SSHRouteLifecycleGraph,
        rootTransportRole: SSHTCPTransportFlowRole = .routeRootConnection,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic,
        modernTransportAvailable: Bool
    ) {
        self.routeGraph = routeGraph
        self.rootTransportRole = rootTransportRole
        self.transportBackendPreference = transportBackendPreference
        self.modernTransportAvailable = modernTransportAvailable
        self.edges = Self.buildEdges(
            routeGraph: routeGraph,
            rootTransportRole: rootTransportRole,
            transportBackendPreference: transportBackendPreference,
            modernTransportAvailable: modernTransportAvailable
        )
    }

    func edge(id: SSHRouteLifecycleGraph.EdgeID) -> SSHRouteFlowEdge? {
        self.edges.first { $0.id == id }
    }

    var rootTransportEdge: SSHRouteFlowEdge {
        self.edges[0]
    }

    var rootTransportPolicy: SSHTCPTransportFlowPolicy {
        guard case let .tcpTransport(policy) = self.rootTransportEdge.resource else {
            preconditionFailure("Route root edge is not a TCP transport edge")
        }

        return policy
    }

    var edgesNeedingStructuredRouteOwner: [SSHRouteFlowEdge] {
        self.edges.filter { edge in
            guard case let .tcpTransport(policy) = edge.resource else {
                return false
            }

            return policy.needsStructuredRouteOwnerForDeterministicAbort
        }
    }

    private static func buildEdges(
        routeGraph: SSHRouteLifecycleGraph,
        rootTransportRole: SSHTCPTransportFlowRole,
        transportBackendPreference: SSHTCPTransportBackendPreference,
        modernTransportAvailable: Bool
    ) -> [SSHRouteFlowEdge] {
        routeGraph.edges.map { edge in
            SSHRouteFlowEdge(
                lifecycleEdge: edge,
                resource: self.resource(
                    for: edge,
                    routeGraph: routeGraph,
                    rootTransportRole: rootTransportRole,
                    transportBackendPreference: transportBackendPreference,
                    modernTransportAvailable: modernTransportAvailable
                )
            )
        }
    }

    private static func resource(
        for edge: SSHRouteLifecycleEdge,
        routeGraph: SSHRouteLifecycleGraph,
        rootTransportRole: SSHTCPTransportFlowRole,
        transportBackendPreference: SSHTCPTransportBackendPreference,
        modernTransportAvailable: Bool
    ) -> SSHRouteFlowResource {
        switch edge.role {
        case .tcpRoot:
            return .tcpTransport(
                SSHTCPTransportFlowPolicy.resolve(
                    role: rootTransportRole,
                    preference: transportBackendPreference,
                    modernAvailable: modernTransportAvailable
                )
            )
        case .directTCPIP:
            return .sshChannel(
                parentConnectionEdgeID: edge.parentID
            )
        case .sshHop, .finalSSH:
            return .sshConnection(
                transportEdgeID: routeGraph.transportEdgeID(
                    forConnectionEdgeID: edge.id
                )
            )
        }
    }
}

struct SSHRouteFlowEdge: Equatable, Sendable {
    let lifecycleEdge: SSHRouteLifecycleEdge
    let resource: SSHRouteFlowResource

    var id: SSHRouteLifecycleGraph.EdgeID {
        self.lifecycleEdge.id
    }

    var role: SSHRouteLifecycleEdgeRole {
        self.lifecycleEdge.role
    }

    var parentID: SSHRouteLifecycleGraph.EdgeID? {
        self.lifecycleEdge.parentID
    }

    var owner: SSHRouteLifecycleEdgeOwner {
        self.lifecycleEdge.owner
    }

    var requirements: SSHRouteLifecycleRequirements {
        self.lifecycleEdge.requirements
    }
}

enum SSHRouteFlowResource: Equatable, Sendable {
    case tcpTransport(SSHTCPTransportFlowPolicy)
    case sshConnection(transportEdgeID: SSHRouteLifecycleGraph.EdgeID?)
    case sshChannel(parentConnectionEdgeID: SSHRouteLifecycleGraph.EdgeID?)
}
