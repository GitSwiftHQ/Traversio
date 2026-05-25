import Testing
@testable import Traversio

@Suite("SSH route lifecycle graph")
struct SSHRouteLifecycleGraphTests {
    @Test
    func directRouteModelsRootTransportAndPublicConnection() {
        let endpoint = SSHSocketEndpoint(host: "server.example", port: 22)
        let plan = SSHRoutePlan(
            finalEndpoint: endpoint,
            connectionProxy: nil,
            proxyJumpHosts: []
        )

        let graph = SSHRouteLifecycleGraph(plan: plan)

        #expect(graph.edges.map(\.role) == [
            .tcpRoot(endpoint: endpoint, connectionProxy: nil),
            .finalSSH(endpoint: endpoint)
        ])
        #expect(graph.rootEdge.parentID == nil)
        #expect(graph.finalEdge.parentID == graph.rootEdge.id)
        #expect(graph.rootEdge.owner == .routeScope)
        #expect(graph.finalEdge.owner == .publicConnection)
        #expect(graph.rootEdge.requirements.mayBeStructuredNetworkScopeRoot)
        #expect(graph.childBeforeParentTeardownOrder().map(\.id) == [
            graph.finalEdge.id,
            graph.rootEdge.id
        ])
    }

    @Test
    func connectionProxyRouteKeepsProxyOnRootEdge() {
        let proxy = SSHConnectionProxy.socks5(.init(host: "proxy.example", port: 1080))
        let target = SSHSocketEndpoint(host: "server.example", port: 22)
        let plan = SSHRoutePlan(
            finalEndpoint: target,
            connectionProxy: proxy,
            proxyJumpHosts: []
        )

        let graph = SSHRouteLifecycleGraph(plan: plan)

        #expect(graph.edges.map(\.role) == [
            .tcpRoot(endpoint: proxy.endpoint, connectionProxy: proxy),
            .finalSSH(endpoint: target)
        ])
        #expect(graph.finalEdge.parentID == graph.rootEdge.id)
    }

    @Test
    func oneHopProxyJumpModelsFinalDirectTCPIPAsChildOfHopConnection() {
        let hop = makeProxyJumpHost(host: "jump.example", port: 22, username: "jump")
        let target = SSHSocketEndpoint(host: "server.example", port: 22)
        let plan = SSHRoutePlan(
            finalEndpoint: target,
            connectionProxy: nil,
            proxyJumpHosts: [hop]
        )

        let graph = SSHRouteLifecycleGraph(plan: plan)

        #expect(graph.edges.map(\.role) == [
            .tcpRoot(endpoint: SSHSocketEndpoint(host: hop.host, port: hop.port), connectionProxy: nil),
            .sshHop(ordinal: 1, endpoint: SSHSocketEndpoint(host: hop.host, port: hop.port)),
            .directTCPIP(ordinal: 2, endpoint: target),
            .finalSSH(endpoint: target)
        ])

        let hopEdge = graph.edges[1]
        let finalChannelEdge = graph.edges[2]
        #expect(hopEdge.parentID == graph.rootEdge.id)
        #expect(finalChannelEdge.parentID == hopEdge.id)
        #expect(graph.finalEdge.parentID == finalChannelEdge.id)
        #expect(finalChannelEdge.owner == .parentSSHConnection)
        #expect(graph.childBeforeParentTeardownOrder().map(\.id) == [
            graph.edges[3].id,
            graph.edges[2].id,
            graph.edges[1].id,
            graph.edges[0].id
        ])
    }

    @Test
    func twoHopProxyJumpModelsIntermediateAndFinalChannels() {
        let firstHop = makeProxyJumpHost(host: "jump-1.example", port: 22, username: "jump1")
        let secondHop = makeProxyJumpHost(host: "jump-2.example", port: 2200, username: "jump2")
        let target = SSHSocketEndpoint(host: "server.example", port: 22)
        let plan = SSHRoutePlan(
            finalEndpoint: target,
            connectionProxy: nil,
            proxyJumpHosts: [firstHop, secondHop]
        )

        let graph = SSHRouteLifecycleGraph(plan: plan)

        #expect(graph.edges.map(\.role) == [
            .tcpRoot(endpoint: SSHSocketEndpoint(host: firstHop.host, port: firstHop.port), connectionProxy: nil),
            .sshHop(ordinal: 1, endpoint: SSHSocketEndpoint(host: firstHop.host, port: firstHop.port)),
            .directTCPIP(ordinal: 2, endpoint: SSHSocketEndpoint(host: secondHop.host, port: secondHop.port)),
            .sshHop(ordinal: 2, endpoint: SSHSocketEndpoint(host: secondHop.host, port: secondHop.port)),
            .directTCPIP(ordinal: 3, endpoint: target),
            .finalSSH(endpoint: target)
        ])
        #expect(graph.edges[2].parentID == graph.edges[1].id)
        #expect(graph.edges[3].parentID == graph.edges[2].id)
        #expect(graph.edges[4].parentID == graph.edges[3].id)
        #expect(graph.edges[5].parentID == graph.edges[4].id)
        #expect(graph.childBeforeParentTeardownOrder().map(\.id) == [
            graph.edges[5].id,
            graph.edges[4].id,
            graph.edges[3].id,
            graph.edges[2].id,
            graph.edges[1].id,
            graph.edges[0].id
        ])
    }

    @Test
    func lifecycleOwnerClosesAcquiredConnectionsInGraphOrderAfterFinalClose() async {
        let firstHop = makeProxyJumpHost(host: "jump-1.example", port: 22, username: "jump1")
        let secondHop = makeProxyJumpHost(host: "jump-2.example", port: 2200, username: "jump2")
        let target = SSHSocketEndpoint(host: "server.example", port: 22)
        let graph = SSHRouteLifecycleGraph(
            plan: SSHRoutePlan(
                finalEndpoint: target,
                connectionProxy: nil,
                proxyJumpHosts: [firstHop, secondHop]
            )
        )
        let owner = SSHRouteLifecycleOwner(graph: graph)
        let recorder = RouteLifecycleOwnerEventRecorder()
        let firstHopEdgeID = graph.sshHopEdgeID(ordinal: 1)!
        let secondHopEdgeID = graph.sshHopEdgeID(ordinal: 2)!

        await owner.beginAcquiringConnection(edgeID: firstHopEdgeID)
        await owner.registerConnection(
            makeRouteLifecycleConnection(
                host: "jump-1.example",
                closeEvent: "first-hop-close",
                abortEvent: "first-hop-abort",
                recorder: recorder
            ),
            edgeID: firstHopEdgeID
        )
        await owner.beginAcquiringConnection(edgeID: secondHopEdgeID)
        await owner.registerConnection(
            makeRouteLifecycleConnection(
                host: "jump-2.example",
                closeEvent: "second-hop-close",
                abortEvent: "second-hop-abort",
                recorder: recorder
            ),
            edgeID: secondHopEdgeID
        )
        await owner.registerFinalConnectionEstablished()

        await owner.closeAfterExternalFinalClose()

        #expect(await recorder.events() == ["second-hop-close", "first-hop-close"])
        let snapshot = await owner.snapshot()
        #expect(snapshot.acquiredConnectionEdgeIDs.isEmpty)
        #expect(snapshot.edgeStates[graph.edges[0].id] == .closed)
        #expect(snapshot.edgeStates[graph.edges[1].id] == .closed)
        #expect(snapshot.edgeStates[graph.edges[2].id] == .closed)
        #expect(snapshot.edgeStates[graph.edges[3].id] == .closed)
        #expect(snapshot.edgeStates[graph.edges[4].id] == .closed)
        #expect(snapshot.edgeStates[graph.edges[5].id] == .closed)
    }

    @Test
    func lifecycleOwnerAbortsAcquiredConnectionsInGraphOrderAfterFailedFinalSetup() async {
        let firstHop = makeProxyJumpHost(host: "jump-1.example", port: 22, username: "jump1")
        let secondHop = makeProxyJumpHost(host: "jump-2.example", port: 2200, username: "jump2")
        let target = SSHSocketEndpoint(host: "server.example", port: 22)
        let graph = SSHRouteLifecycleGraph(
            plan: SSHRoutePlan(
                finalEndpoint: target,
                connectionProxy: nil,
                proxyJumpHosts: [firstHop, secondHop]
            )
        )
        let owner = SSHRouteLifecycleOwner(graph: graph)
        let recorder = RouteLifecycleOwnerEventRecorder()
        let firstHopEdgeID = graph.sshHopEdgeID(ordinal: 1)!
        let secondHopEdgeID = graph.sshHopEdgeID(ordinal: 2)!

        await owner.beginAcquiringConnection(edgeID: firstHopEdgeID)
        await owner.registerConnection(
            makeRouteLifecycleConnection(
                host: "jump-1.example",
                closeEvent: "first-hop-close",
                abortEvent: "first-hop-abort",
                recorder: recorder
            ),
            edgeID: firstHopEdgeID
        )
        await owner.beginAcquiringConnection(edgeID: secondHopEdgeID)
        await owner.registerConnection(
            makeRouteLifecycleConnection(
                host: "jump-2.example",
                closeEvent: "second-hop-close",
                abortEvent: "second-hop-abort",
                recorder: recorder
            ),
            edgeID: secondHopEdgeID
        )
        await owner.beginAcquiringConnection(edgeID: graph.finalSSHEdgeID)

        await owner.abortAfterExternalFinalClose()

        #expect(await recorder.events() == ["second-hop-abort", "first-hop-abort"])
        let snapshot = await owner.snapshot()
        #expect(snapshot.acquiredConnectionEdgeIDs.isEmpty)
        #expect(snapshot.edgeStates[graph.edges[0].id] == .failed)
        #expect(snapshot.edgeStates[graph.edges[1].id] == .failed)
        #expect(snapshot.edgeStates[graph.edges[2].id] == .failed)
        #expect(snapshot.edgeStates[graph.edges[3].id] == .failed)
        #expect(snapshot.edgeStates[graph.edges[4].id] == .failed)
        #expect(snapshot.edgeStates[graph.edges[5].id] == .failed)
    }

    @Test
    func lifecycleOwnerMarksAcquiringEdgesFailedWhenSetupTimesOutBeforeConnectionExists() async {
        let hop = makeProxyJumpHost(host: "jump.example", port: 22, username: "jump")
        let target = SSHSocketEndpoint(host: "server.example", port: 22)
        let graph = SSHRouteLifecycleGraph(
            plan: SSHRoutePlan(
                finalEndpoint: target,
                connectionProxy: nil,
                proxyJumpHosts: [hop]
            )
        )
        let owner = SSHRouteLifecycleOwner(graph: graph)

        await owner.beginAcquiringConnection(edgeID: graph.finalSSHEdgeID)
        await owner.abort()

        let snapshot = await owner.snapshot()
        #expect(snapshot.acquiredConnectionEdgeIDs.isEmpty)
        #expect(snapshot.edgeStates[graph.edges[2].id] == .failed)
        #expect(snapshot.edgeStates[graph.edges[3].id] == .failed)
        #expect(snapshot.edgeStates[graph.edges[0].id] == .planned)
        #expect(snapshot.edgeStates[graph.edges[1].id] == .planned)
    }

    private func makeProxyJumpHost(host: String, port: UInt16, username: String) -> SSHProxyJumpHost {
        SSHProxyJumpHost(
            host: host,
            port: port,
            username: username,
            authentication: .password("password"),
            hostKeyPolicy: .acceptAnyVerifiedHostKey
        )
    }

    private func makeRouteLifecycleConnection(
        host: String,
        closeEvent: String,
        abortEvent: String,
        recorder: RouteLifecycleOwnerEventRecorder
    ) -> SSHConnection {
        let transport = ConnectionFixtureMockSSHByteStreamTransport(
            serverPayloadsAfterNewKeys: []
        )
        let client = SSHTransportProtocolClient(transport: transport)
        let lifetime = SSHConnectionLifetime(
            closeOperation: {
                await recorder.record(closeEvent)
            },
            abortOperation: {
                await recorder.record(abortEvent)
            }
        )
        let metadata = SSHConnectionMetadata(
            endpointHost: host,
            endpointPort: 22,
            username: "root",
            clientIdentification: "SSH-2.0-Traversio_Test",
            remoteIdentification: "SSH-2.0-Test",
            preIdentificationLines: [],
            hostKeyAlgorithm: "ssh-ed25519",
            hostKeyFingerprintSHA256: "SHA256:test",
            hostKeyTrustMethod: .acceptAnyVerifiedHostKey
        )
        return SSHConnection(
            metadata: metadata,
            client: client,
            lifetime: lifetime,
            logHandler: .disabled
        )
    }
}

private actor RouteLifecycleOwnerEventRecorder {
    private var recordedEvents: [String] = []

    func record(_ event: String) {
        self.recordedEvents.append(event)
    }

    func events() -> [String] {
        self.recordedEvents
    }
}
