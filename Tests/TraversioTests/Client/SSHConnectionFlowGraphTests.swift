import Testing
@testable import Traversio

@Suite("SSH connection flow graph")
struct SSHConnectionFlowGraphTests {
    @Test
    func automaticHandleOwnedRouteRootUsesExplicitCancellationOwnership() {
        let connectionFlowGraph = SSHConnectionFlowGraph(
            routeFlowGraph: self.makeDirectRouteFlowGraph(
                rootTransportRole: .routeRootConnection,
                transportBackendPreference: .automatic,
                modernTransportAvailable: true
            )
        )

        #expect(connectionFlowGraph.rootTransportPolicy.selectedBackend == .legacyNWConnection)
        #expect(connectionFlowGraph.rootTransportOwnership == .explicitCancellationHandle)
        #expect(connectionFlowGraph.structuredRootScopeExitOrder.isEmpty)
    }

    @Test
    func explicitModernHandleOwnedRouteRootRequiresStructuredOwner() {
        let connectionFlowGraph = SSHConnectionFlowGraph(
            routeFlowGraph: self.makeDirectRouteFlowGraph(
                rootTransportRole: .routeRootConnection,
                transportBackendPreference: .modern,
                modernTransportAvailable: true
            )
        )

        #expect(connectionFlowGraph.rootTransportPolicy.selectedBackend == .modernNetworkConnection)
        #expect(connectionFlowGraph.rootTransportPolicy.ownershipModel == .escapedConnectionHandle)
        #expect(connectionFlowGraph.rootTransportOwnership == .escapedConnectionHandleMissingStructuredOwner)
        #expect(connectionFlowGraph.structuredRootScopeExitOrder.isEmpty)
    }

    @Test
    func structuredDirectRouteExitsFinalConnectionBeforeRootTransportScope() throws {
        let routeFlowGraph = self.makeDirectRouteFlowGraph(
            rootTransportRole: .structuredRouteRootConnection,
            transportBackendPreference: .automatic,
            modernTransportAvailable: true
        )
        let connectionFlowGraph = SSHConnectionFlowGraph(routeFlowGraph: routeFlowGraph)

        #expect(connectionFlowGraph.rootTransportOwnership == .structuredScope)
        #expect(
            connectionFlowGraph.structuredRootScopeExitOrder
                == [
                    .routeEdge(routeFlowGraph.routeGraph.finalSSHEdgeID),
                    .routeEdge(routeFlowGraph.routeGraph.rootEdge.id)
                ]
        )
    }

    @Test
    func structuredRemoteBridgeScopeExitsForwardingChildrenBeforeRouteRoot() throws {
        let routeFlowGraph = self.makeDirectRouteFlowGraph(
            rootTransportRole: .structuredRouteRootConnection,
            transportBackendPreference: .automatic,
            modernTransportAvailable: true
        )
        let forwardingFlowGraph = SSHForwardingFlowGraph(
            kind: .remoteTCPBridge,
            transportBackendPreference: .automatic,
            modernTransportAvailable: true
        )
        let connectionFlowGraph = SSHConnectionFlowGraph(
            routeFlowGraph: routeFlowGraph,
            forwardingFlowGraphs: [forwardingFlowGraph]
        )

        let exitOrder = connectionFlowGraph.structuredRootScopeExitOrder

        #expect(connectionFlowGraph.rootTransportOwnership == .structuredScope)
        #expect(
            exitOrder.prefix(4)
                == [
                    .forwardingResource(
                        forwardingKind: .remoteTCPBridge,
                        resourceKind: .bridgeTask
                    ),
                    .forwardingResource(
                        forwardingKind: .remoteTCPBridge,
                        resourceKind: .bridgeLocalTCPTransport
                    ),
                    .forwardingResource(
                        forwardingKind: .remoteTCPBridge,
                        resourceKind: .acceptedForwardedTCPIPChannel
                    ),
                    .forwardingResource(
                        forwardingKind: .remoteTCPBridge,
                        resourceKind: .remoteAcceptLoopTask
                    )
                ]
        )
        #expect(exitOrder.suffix(2) == [
            .routeEdge(routeFlowGraph.routeGraph.finalSSHEdgeID),
            .routeEdge(routeFlowGraph.routeGraph.rootEdge.id)
        ])
    }

    private func makeDirectRouteFlowGraph(
        rootTransportRole: SSHTCPTransportFlowRole,
        transportBackendPreference: SSHTCPTransportBackendPreference,
        modernTransportAvailable: Bool
    ) -> SSHRouteFlowGraph {
        let routeGraph = SSHRouteLifecycleGraph(
            plan: SSHRoutePlan(
                finalEndpoint: SSHSocketEndpoint(host: "example.com", port: 22),
                connectionProxy: nil,
                proxyJumpHosts: []
            )
        )

        return SSHRouteFlowGraph(
            routeGraph: routeGraph,
            rootTransportRole: rootTransportRole,
            transportBackendPreference: transportBackendPreference,
            modernTransportAvailable: modernTransportAvailable
        )
    }
}
