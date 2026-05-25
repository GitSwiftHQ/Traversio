// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

struct SSHRoutePlan: Sendable {
    let rootEndpoint: SSHSocketEndpoint
    let connectionProxy: SSHConnectionProxy?
    let proxyJumpHosts: [SSHProxyJumpHost]
    let finalEndpoint: SSHSocketEndpoint

    var connectionCount: Int {
        self.proxyJumpHosts.count + 1
    }

    init(
        finalEndpoint: SSHSocketEndpoint,
        connectionProxy: SSHConnectionProxy?,
        proxyJumpHosts: [SSHProxyJumpHost]
    ) {
        self.rootEndpoint = SSHRoutePlan.rootEndpoint(
            finalHost: finalEndpoint.host,
            finalPort: finalEndpoint.port,
            connectionProxy: connectionProxy,
            proxyJumpHosts: proxyJumpHosts
        )
        self.connectionProxy = connectionProxy
        self.proxyJumpHosts = proxyJumpHosts
        self.finalEndpoint = finalEndpoint
    }

    init(configuration: SSHClientConfiguration) {
        self.rootEndpoint = SSHRoutePlan.rootEndpoint(
            finalHost: configuration.host,
            finalPort: configuration.port,
            connectionProxy: configuration.connectionProxy,
            proxyJumpHosts: configuration.proxyJumpHosts
        )
        self.connectionProxy = configuration.connectionProxy
        self.proxyJumpHosts = configuration.proxyJumpHosts
        self.finalEndpoint = SSHSocketEndpoint(
            host: configuration.host,
            port: configuration.port
        )
    }

    init(configuration: SSHAuthenticationMethodDiscoveryConfiguration) {
        self.rootEndpoint = SSHRoutePlan.rootEndpoint(
            finalHost: configuration.host,
            finalPort: configuration.port,
            connectionProxy: configuration.connectionProxy,
            proxyJumpHosts: configuration.proxyJumpHosts
        )
        self.connectionProxy = configuration.connectionProxy
        self.proxyJumpHosts = configuration.proxyJumpHosts
        self.finalEndpoint = SSHSocketEndpoint(
            host: configuration.host,
            port: configuration.port
        )
    }

    private static func rootEndpoint(
        finalHost: String,
        finalPort: UInt16,
        connectionProxy: SSHConnectionProxy?,
        proxyJumpHosts: [SSHProxyJumpHost]
    ) -> SSHSocketEndpoint {
        if let connectionProxy {
            return connectionProxy.endpoint
        }
        if let firstHop = proxyJumpHosts.first {
            return SSHSocketEndpoint(host: firstHop.host, port: firstHop.port)
        }
        return SSHSocketEndpoint(host: finalHost, port: finalPort)
    }
}

actor SSHRouteLifecycleOwner {
    let graph: SSHRouteLifecycleGraph

    var plan: SSHRoutePlan {
        self.graph.plan
    }

    private var edgeStates: [SSHRouteLifecycleGraph.EdgeID: SSHRouteLifecycleEdgeState]
    private var acquiredConnectionEdges: [SSHRouteLifecycleGraph.EdgeID: SSHRouteAcquiredConnectionEdge] = [:]
    private var terminalAction: SSHRouteLifecycleTerminationAction?

    init(plan: SSHRoutePlan) {
        self.init(graph: SSHRouteLifecycleGraph(plan: plan))
    }

    init(graph: SSHRouteLifecycleGraph) {
        self.graph = graph
        self.edgeStates = Dictionary(
            uniqueKeysWithValues: graph.edges.map { ($0.id, SSHRouteLifecycleEdgeState.planned) }
        )
    }

    func beginAcquiringConnection(edgeID: SSHRouteLifecycleGraph.EdgeID) {
        guard self.terminalAction == nil else {
            return
        }

        self.mark(edgeID, as: .acquiring)
        if let transportEdgeID = self.graph.transportEdgeID(forConnectionEdgeID: edgeID) {
            self.mark(transportEdgeID, as: .acquiring)
        }
    }

    func registerConnection(
        _ connection: SSHConnection,
        edgeID: SSHRouteLifecycleGraph.EdgeID
    ) async {
        if let terminalAction {
            await self.apply(terminalAction, to: connection)
            return
        }

        let transportEdgeID = self.graph.transportEdgeID(forConnectionEdgeID: edgeID)
        self.acquiredConnectionEdges[edgeID] = SSHRouteAcquiredConnectionEdge(
            edgeID: edgeID,
            transportEdgeID: transportEdgeID,
            connection: connection
        )
        self.mark(edgeID, as: .acquired)
        if let transportEdgeID {
            self.mark(transportEdgeID, as: .acquired)
        }
    }

    func registerFinalConnectionEstablished() {
        guard self.terminalAction == nil else {
            return
        }

        self.mark(self.graph.finalSSHEdgeID, as: .publicConnection)
        if let transportEdgeID = self.graph.transportEdgeID(
            forConnectionEdgeID: self.graph.finalSSHEdgeID
        ) {
            self.mark(transportEdgeID, as: .acquired)
        }
    }

    func lastConnection() -> SSHConnection? {
        self.acquiredConnectionEdges
            .sorted { lhs, rhs in lhs.key < rhs.key }
            .last?
            .value
            .connection
    }

    func closeAfterExternalFinalClose() async {
        await self.terminate(
            action: .close,
            externallyCompletedEdgeIDs: self.graph.externallyClosedFinalEdgeIDs()
        )
    }

    func abortAfterExternalFinalClose() async {
        await self.terminate(
            action: .abort,
            externallyCompletedEdgeIDs: self.graph.externallyClosedFinalEdgeIDs()
        )
    }

    func close() async {
        await self.terminate(action: .close, externallyCompletedEdgeIDs: [])
    }

    func abort() async {
        await self.terminate(action: .abort, externallyCompletedEdgeIDs: [])
    }

    func snapshot() -> SSHRouteLifecycleSnapshot {
        SSHRouteLifecycleSnapshot(
            edgeStates: self.edgeStates,
            acquiredConnectionEdgeIDs: self.acquiredConnectionEdges.keys.sorted(),
            teardownOrder: self.graph.childBeforeParentTeardownOrder().map(\.id)
        )
    }

    func state(of edgeID: SSHRouteLifecycleGraph.EdgeID) -> SSHRouteLifecycleEdgeState? {
        self.edgeStates[edgeID]
    }

    private func terminate(
        action: SSHRouteLifecycleTerminationAction,
        externallyCompletedEdgeIDs: [SSHRouteLifecycleGraph.EdgeID]
    ) async {
        let acquiredEdges = self.claimTermination(
            action: action,
            externallyCompletedEdgeIDs: externallyCompletedEdgeIDs
        )

        for acquiredEdge in acquiredEdges {
            await self.apply(action, to: acquiredEdge.connection)
            self.finish(acquiredEdge, action: action)
        }
    }

    private func claimTermination(
        action: SSHRouteLifecycleTerminationAction,
        externallyCompletedEdgeIDs: [SSHRouteLifecycleGraph.EdgeID]
    ) -> [SSHRouteAcquiredConnectionEdge] {
        guard self.terminalAction == nil else {
            return []
        }

        self.terminalAction = action

        for edgeID in externallyCompletedEdgeIDs {
            self.mark(edgeID, as: action.completedState)
        }

        let teardownOrder = self.graph.childBeforeParentTeardownOrder().map(\.id)
        let acquiredEdges = teardownOrder.compactMap { edgeID -> SSHRouteAcquiredConnectionEdge? in
            guard let acquiredEdge = self.acquiredConnectionEdges.removeValue(forKey: edgeID) else {
                return nil
            }

            self.mark(acquiredEdge.edgeID, as: action.inProgressState)
            if let transportEdgeID = acquiredEdge.transportEdgeID {
                self.mark(transportEdgeID, as: action.inProgressState)
            }
            return acquiredEdge
        }

        for (edgeID, state) in self.edgeStates where state == .acquiring {
            self.mark(edgeID, as: .failed)
        }

        return acquiredEdges
    }

    private func finish(
        _ acquiredEdge: SSHRouteAcquiredConnectionEdge,
        action: SSHRouteLifecycleTerminationAction
    ) {
        self.mark(acquiredEdge.edgeID, as: action.completedState)
        if let transportEdgeID = acquiredEdge.transportEdgeID {
            self.mark(transportEdgeID, as: action.completedState)
        }
    }

    private func mark(
        _ edgeID: SSHRouteLifecycleGraph.EdgeID,
        as state: SSHRouteLifecycleEdgeState
    ) {
        self.edgeStates[edgeID] = state
    }

    private func apply(
        _ action: SSHRouteLifecycleTerminationAction,
        to connection: SSHConnection
    ) async {
        switch action {
        case .close:
            await connection.close()
        case .abort:
            await connection.abort()
        }
    }
}

private struct SSHRouteAcquiredConnectionEdge: Sendable {
    let edgeID: SSHRouteLifecycleGraph.EdgeID
    let transportEdgeID: SSHRouteLifecycleGraph.EdgeID?
    let connection: SSHConnection
}

private enum SSHRouteLifecycleTerminationAction: Sendable {
    case close
    case abort

    var inProgressState: SSHRouteLifecycleEdgeState {
        switch self {
        case .close:
            return .closing
        case .abort:
            return .aborting
        }
    }

    var completedState: SSHRouteLifecycleEdgeState {
        switch self {
        case .close:
            return .closed
        case .abort:
            return .failed
        }
    }
}
