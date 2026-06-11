// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

struct SSHConnectionFlowGraph: Sendable {
    let routeFlowGraph: SSHRouteFlowGraph
    let forwardingFlowGraphs: [SSHForwardingFlowGraph]

    init(
        routeFlowGraph: SSHRouteFlowGraph,
        forwardingFlowGraphs: [SSHForwardingFlowGraph] = []
    ) {
        self.routeFlowGraph = routeFlowGraph
        self.forwardingFlowGraphs = forwardingFlowGraphs
    }

    var rootTransportPolicy: SSHTCPTransportFlowPolicy {
        self.routeFlowGraph.rootTransportPolicy
    }

    var rootTransportOwnership: SSHConnectionRootTransportOwnership {
        let policy = self.rootTransportPolicy

        switch policy.ownershipModel {
        case .explicitCancellationHandle:
            return .explicitCancellationHandle
        case .structuredScope:
            return .structuredScope
        case .escapedConnectionHandle:
            if policy.needsStructuredRouteOwnerForDeterministicAbort {
                return .escapedConnectionHandleMissingStructuredOwner
            }
            return .escapedConnectionHandle
        }
    }

    var structuredRootScopeExitOrder: [SSHConnectionFlowResource] {
        guard self.rootTransportOwnership == .structuredScope else {
            return []
        }

        let forwardingResources = self.forwardingFlowGraphs.flatMap { graph in
            graph.childBeforeParentTeardownOrder.compactMap { edgeID -> SSHConnectionFlowResource? in
                guard let edge = graph.edge(id: edgeID),
                      edge.resource.kind.participatesInStructuredRootScopeExit
                else {
                    return nil
                }

                return .forwardingResource(
                    forwardingKind: graph.kind,
                    resourceKind: edge.resource.kind
                )
            }
        }

        let routeResources = self.routeFlowGraph.routeGraph.childBeforeParentTeardownOrder()
            .map { edge in
                SSHConnectionFlowResource.routeEdge(edge.id)
            }

        return forwardingResources + routeResources
    }
}

enum SSHConnectionRootTransportOwnership: Equatable, Sendable {
    case explicitCancellationHandle
    case structuredScope
    case escapedConnectionHandle
    case escapedConnectionHandleMissingStructuredOwner
}

enum SSHConnectionFlowResource: Equatable, Sendable {
    case routeEdge(SSHRouteLifecycleGraph.EdgeID)
    case forwardingResource(
        forwardingKind: SSHForwardingFlowKind,
        resourceKind: SSHForwardingFlowResourceKind
    )
}

private extension SSHForwardingFlowResourceKind {
    var participatesInStructuredRootScopeExit: Bool {
        switch self {
        case .parentSSHConnection,
             .callerBody:
            return false
        case .localTCPListener,
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
             .bridgeLocalTCPTransport,
             .bridgeTask:
            return true
        }
    }
}
