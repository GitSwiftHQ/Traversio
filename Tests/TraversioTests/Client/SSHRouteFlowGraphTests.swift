import Testing
@testable import Traversio

@Suite("SSH route flow graph")
struct SSHRouteFlowGraphTests {
    @Test
    func directRouteModelsRootTransportAndFinalSSHFlow() throws {
        let endpoint = SSHSocketEndpoint(host: "server.example", port: 22)
        let lifecycleGraph = SSHRouteLifecycleGraph(
            plan: SSHRoutePlan(
                finalEndpoint: endpoint,
                connectionProxy: nil,
                proxyJumpHosts: []
            )
        )

        let flowGraph = SSHRouteFlowGraph(
            routeGraph: lifecycleGraph,
            transportBackendPreference: .automatic,
            modernTransportAvailable: true
        )

        #expect(flowGraph.edges.count == 2)
        #expect(flowGraph.rootTransportPolicy.role == .routeRootConnection)
        #expect(flowGraph.rootTransportPolicy.selectedBackend == .legacyNWConnection)
        #expect(flowGraph.rootTransportPolicy.ownershipModel == .explicitCancellationHandle)
        #expect(flowGraph.rootTransportPolicy.terminalCloseEvidence == .explicitCancellation)
        #expect(flowGraph.edgesNeedingStructuredRouteOwner.isEmpty)

        let finalEdge = try #require(flowGraph.edge(id: lifecycleGraph.finalSSHEdgeID))
        #expect(finalEdge.resource == .sshConnection(transportEdgeID: lifecycleGraph.rootEdge.id))
        #expect(finalEdge.owner == .publicConnection)
    }

    @Test
    func explicitModernDirectRouteRecordsStructuredOwnerGapOnRootEdge() throws {
        let endpoint = SSHSocketEndpoint(host: "server.example", port: 22)
        let lifecycleGraph = SSHRouteLifecycleGraph(
            plan: SSHRoutePlan(
                finalEndpoint: endpoint,
                connectionProxy: nil,
                proxyJumpHosts: []
            )
        )

        let flowGraph = SSHRouteFlowGraph(
            routeGraph: lifecycleGraph,
            transportBackendPreference: .modern,
            modernTransportAvailable: true
        )

        #expect(flowGraph.rootTransportPolicy.selectedBackend == .modernNetworkConnection)
        #expect(flowGraph.rootTransportPolicy.ownershipModel == .escapedConnectionHandle)
        #expect(flowGraph.rootTransportPolicy.terminalCloseEvidence == .referenceReleaseOnly)
        #expect(flowGraph.rootTransportPolicy.needsStructuredRouteOwnerForDeterministicAbort)
        #expect(flowGraph.edgesNeedingStructuredRouteOwner.map(\.id) == [
            lifecycleGraph.rootEdge.id
        ])
    }

    @Test
    func structuredDirectRouteRootRecordsStructuredCloseEvidence() throws {
        let endpoint = SSHSocketEndpoint(host: "server.example", port: 22)
        let lifecycleGraph = SSHRouteLifecycleGraph(
            plan: SSHRoutePlan(
                finalEndpoint: endpoint,
                connectionProxy: nil,
                proxyJumpHosts: []
            )
        )

        let flowGraph = SSHRouteFlowGraph(
            routeGraph: lifecycleGraph,
            rootTransportRole: .structuredRouteRootConnection,
            transportBackendPreference: .automatic,
            modernTransportAvailable: true
        )

        #expect(flowGraph.rootTransportPolicy.role == .structuredRouteRootConnection)
        #expect(flowGraph.rootTransportPolicy.selectedBackend == .modernNetworkConnection)
        #expect(flowGraph.rootTransportPolicy.ownershipModel == .structuredScope)
        #expect(flowGraph.rootTransportPolicy.terminalCloseEvidence == .structuredScopeExit)
        #expect(flowGraph.rootTransportPolicy.requiresDeterministicAbort)
        #expect(flowGraph.edgesNeedingStructuredRouteOwner.isEmpty)
    }

    @Test
    func proxyJumpRouteLinksChannelsToParentConnectionsAndFinalTransport() throws {
        let hop = Self.makeProxyJumpHost(host: "jump.example", port: 22, username: "jump")
        let target = SSHSocketEndpoint(host: "server.example", port: 22)
        let lifecycleGraph = SSHRouteLifecycleGraph(
            plan: SSHRoutePlan(
                finalEndpoint: target,
                connectionProxy: nil,
                proxyJumpHosts: [hop]
            )
        )

        let flowGraph = SSHRouteFlowGraph(
            routeGraph: lifecycleGraph,
            transportBackendPreference: .automatic,
            modernTransportAvailable: true
        )

        let hopEdgeID = try #require(lifecycleGraph.sshHopEdgeID(ordinal: 1))
        let channelEdge = try #require(
            flowGraph.edges.first { edge in
                if case .directTCPIP = edge.role {
                    return true
                }

                return false
            }
        )
        let finalEdge = try #require(flowGraph.edge(id: lifecycleGraph.finalSSHEdgeID))

        #expect(flowGraph.rootTransportPolicy.selectedBackend == .legacyNWConnection)
        #expect(flowGraph.edge(id: hopEdgeID)?.resource == .sshConnection(
            transportEdgeID: lifecycleGraph.rootEdge.id
        ))
        #expect(channelEdge.resource == .sshChannel(parentConnectionEdgeID: hopEdgeID))
        #expect(finalEdge.resource == .sshConnection(transportEdgeID: channelEdge.id))
    }

    private static func makeProxyJumpHost(
        host: String,
        port: UInt16,
        username: String
    ) -> SSHProxyJumpHost {
        SSHProxyJumpHost(
            host: host,
            port: port,
            username: username,
            authentication: .password("password"),
            hostKeyPolicy: .acceptAnyVerifiedHostKey
        )
    }
}
