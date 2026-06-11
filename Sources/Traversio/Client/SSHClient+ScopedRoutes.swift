// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

extension SSHClient {
    static func canUseDirectRouteScopedConnection(
        configuration: SSHClientConfiguration
    ) -> Bool {
        configuration.connectionProxy == nil && configuration.proxyJumpHosts.isEmpty
    }

    static func withDirectRouteScopedConnection<Result>(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        try await self.withDirectRouteScopedConnection(
            configuration: configuration,
            logHandler: logHandler,
            transportBackendPreference: transportBackendPreference,
            routeRootTransportRunner: { flowGraph, handler in
                try await SSHTCPByteStreamTransportFactory.withConnected(
                    to: flowGraph.routeGraph.plan.rootEndpoint,
                    policy: flowGraph.rootTransportPolicy,
                    handler
                )
            },
            body
        )
    }

    static func withDirectRouteScopedConnection<Result>(
        configuration: SSHClientConfiguration,
        logHandler: SSHClientLogHandler,
        transportBackendPreference: SSHTCPTransportBackendPreference = .automatic,
        modernTransportAvailable: Bool? = nil,
        routeRootTransportRunner: @escaping (
            _ flowGraph: SSHRouteFlowGraph,
            _ handler: @escaping (any SSHByteStreamTransport) async throws -> Result
        ) async throws -> Result,
        _ body: @escaping (SSHConnection) async throws -> Result
    ) async throws -> Result {
        precondition(
            self.canUseDirectRouteScopedConnection(configuration: configuration),
            "withDirectRouteScopedConnection only supports direct, non-proxy routes"
        )

        let routePlan = SSHRoutePlan(configuration: configuration)
        let routeGraph = SSHRouteLifecycleGraph(plan: routePlan)
        let routeFlowGraph: SSHRouteFlowGraph
        if let modernTransportAvailable {
            routeFlowGraph = SSHRouteFlowGraph(
                routeGraph: routeGraph,
                rootTransportRole: .structuredRouteRootConnection,
                transportBackendPreference: transportBackendPreference,
                modernTransportAvailable: modernTransportAvailable
            )
        } else {
            routeFlowGraph = SSHRouteFlowGraph(
                routeGraph: routeGraph,
                rootTransportRole: .structuredRouteRootConnection,
                transportBackendPreference: transportBackendPreference
            )
        }
        let routeLifecycle = SSHRouteLifecycleOwner(graph: routeGraph)
        let endpoint = routePlan.finalEndpoint

        logHandler.logConnectionStarted(
            endpoint: endpoint,
            username: configuration.username,
            authentication: configuration.authentication
        )

        return try await routeRootTransportRunner(routeFlowGraph) { transport in
            await routeLifecycle.beginAcquiringConnection(edgeID: routeGraph.finalSSHEdgeID)
            let connection = try await self.makeConnection(
                configuration: configuration,
                endpoint: endpoint,
                transportHandle: SSHClientTransportHandle(transport: transport),
                dependentCloseOperation: {
                    await routeLifecycle.closeAfterExternalFinalClose()
                },
                failedSetupDependentCloseOperation: {
                    await routeLifecycle.abortAfterExternalFinalClose()
                },
                transportBackendPreference: transportBackendPreference,
                logHandler: logHandler
            )
            await routeLifecycle.registerFinalConnectionEstablished()

            do {
                let result = try await body(connection)
                await connection.close()
                return result
            } catch {
                await connection.close()
                throw error
            }
        }
    }
}
