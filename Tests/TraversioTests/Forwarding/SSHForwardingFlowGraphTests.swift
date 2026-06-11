import Testing
@testable import Traversio

@Suite("SSH forwarding flow graph")
struct SSHForwardingFlowGraphTests {
    @Test
    func localForwardingModelsLifecycleControlledListenerAndDirectChannelBridge() throws {
        let graph = SSHForwardingFlowGraph(
            kind: .localTCP,
            transportBackendPreference: .automatic,
            modernTransportAvailable: true
        )

        let listenerPolicy = try #require(graph.localListenerTransportPolicy)
        let directChannelEdge = try #require(graph.edge(withResourceKind: .directTCPIPChannel))
        let bridgeTaskEdge = try #require(graph.edge(withResourceKind: .bridgeTask))

        #expect(listenerPolicy.role == .lifecycleControlledListener)
        #expect(listenerPolicy.selectedBackend == .legacyNWConnection)
        #expect(listenerPolicy.requiresDeterministicAbort)
        #expect(listenerPolicy.supportsDeterministicAbort)
        #expect(graph.edge(withResourceKind: .localTCPListenerTask) != nil)
        #expect(graph.edge(withResourceKind: .acceptedLocalTCPConnection) != nil)
        #expect(graph.edge(withResourceKind: .connectionClosureMonitorTask) != nil)
        #expect(graph.edge(withResourceKind: .fallbackLivenessTask) != nil)
        #expect(graph.childBeforeParentTeardownOrder.last == graph.parentConnectionEdgeID)

        guard case let .directTCPIPChannel(parentConnectionEdgeID) = directChannelEdge.resource else {
            Issue.record("Expected a direct-tcpip channel edge")
            return
        }
        #expect(parentConnectionEdgeID == graph.parentConnectionEdgeID)
        #expect(bridgeTaskEdge.parentID == directChannelEdge.id)
    }

    @Test
    func dynamicForwardingModelsSOCKSNegotiationBeforeDirectChannelBridge() throws {
        let graph = SSHForwardingFlowGraph(
            kind: .dynamicSOCKS5,
            transportBackendPreference: .automatic,
            modernTransportAvailable: true
        )

        let socksEdge = try #require(graph.edge(withResourceKind: .socks5Negotiation))
        let directChannelEdge = try #require(graph.edge(withResourceKind: .directTCPIPChannel))
        let listenerPolicy = try #require(graph.localListenerTransportPolicy)

        #expect(listenerPolicy.role == .lifecycleControlledListener)
        #expect(directChannelEdge.parentID == socksEdge.id)
    }

    @Test
    func remoteTCPBridgeModelsAcceptLoopForwardedChannelAndScopedLocalTransport() throws {
        let graph = SSHForwardingFlowGraph(
            kind: .remoteTCPBridge,
            transportBackendPreference: .automatic,
            modernTransportAvailable: true
        )

        let listenerEdge = try #require(graph.edge(withResourceKind: .remoteTCPListener))
        let acceptLoopEdge = try #require(graph.edge(withResourceKind: .remoteAcceptLoopTask))
        let acceptedChannelEdge = try #require(
            graph.edge(withResourceKind: .acceptedForwardedTCPIPChannel)
        )
        let bridgeLocalTransportPolicy = try #require(graph.bridgeLocalTransportPolicy)
        let bridgeLocalTransportEdge = try #require(
            graph.edge(withResourceKind: .bridgeLocalTCPTransport)
        )
        let bridgeTaskEdge = try #require(graph.edge(withResourceKind: .bridgeTask))

        #expect(listenerEdge.parentID == graph.parentConnectionEdgeID)
        #expect(acceptLoopEdge.parentID == listenerEdge.id)
        guard case let .acceptedForwardedTCPIPChannel(parentConnectionEdgeID) =
                acceptedChannelEdge.resource else {
            Issue.record("Expected a forwarded-tcpip channel edge")
            return
        }
        #expect(parentConnectionEdgeID == graph.parentConnectionEdgeID)
        #expect(acceptedChannelEdge.parentID == acceptLoopEdge.id)
        #expect(bridgeLocalTransportPolicy.role == .scopedConnection)
        #expect(bridgeLocalTransportPolicy.selectedBackend == .modernNetworkConnection)
        #expect(bridgeLocalTransportPolicy.ownershipModel == .structuredScope)
        #expect(bridgeLocalTransportEdge.parentID == acceptedChannelEdge.id)
        #expect(bridgeTaskEdge.parentID == bridgeLocalTransportEdge.id)
        #expect(graph.childBeforeParentTeardownOrder.last == graph.parentConnectionEdgeID)
    }

    @Test
    func remoteStreamLocalListenerModelsRemoteListenerWithoutBridgeResources() {
        let graph = SSHForwardingFlowGraph(
            kind: .remoteStreamLocalListener,
            transportBackendPreference: .automatic,
            modernTransportAvailable: true
        )

        #expect(graph.edge(withResourceKind: .remoteStreamLocalListener) != nil)
        #expect(graph.edge(withResourceKind: .remoteAcceptLoopTask) == nil)
        #expect(graph.edge(withResourceKind: .bridgeLocalTCPTransport) == nil)
        #expect(graph.bridgeLocalTransportPolicy == nil)
    }
}
