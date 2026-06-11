// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Foundation

extension SSHClient {
    private static func publicAuthenticationBanners(
        _ banners: [SSHUserAuthenticationBannerMessage]
    ) -> [SSHAuthenticationBanner] {
        banners.map {
            SSHAuthenticationBanner(
                message: $0.message,
                languageTag: $0.languageTag
            )
        }
    }

    private static func authenticationRejectedError(
        methodName: String,
        failure: SSHUserAuthenticationFailureMessage,
        banners: [SSHUserAuthenticationBannerMessage]
    ) -> SSHClientError {
        SSHClientError.authenticationRejected(
            methodName: methodName,
            availableMethods: failure.authenticationsThatCanContinue,
            partialSuccess: failure.partialSuccess,
            banners: self.publicAuthenticationBanners(banners)
        )
    }

    private static func passwordChangeRequiredError(
        _ changeRequest: SSHUserAuthenticationPasswordChangeRequestMessage,
        banners: [SSHUserAuthenticationBannerMessage]
    ) -> SSHClientError {
        SSHClientError.passwordChangeRequired(
            prompt: changeRequest.prompt,
            languageTag: changeRequest.languageTag,
            banners: self.publicAuthenticationBanners(banners)
        )
    }

    private static func authenticatePassword(
        password: String,
        passwordChangeResponseProvider: (@Sendable (SSHPasswordChangeChallenge) async throws -> String)?,
        username: String,
        client: SSHTransportProtocolClient,
        endpoint: SSHSocketEndpoint,
        authentication: SSHAuthenticationMethod,
        logHandler: SSHClientLogHandler
    ) async throws -> [SSHAuthenticationBanner] {
        let initialResult = try await client.authenticatePassword(
            username: username,
            password: password
        )
        switch initialResult.outcome {
        case .success:
            logHandler.logAuthenticationSucceeded(
                method: authentication,
                endpoint: endpoint
            )
            return self.publicAuthenticationBanners(initialResult.banners)
        case let .failure(failure):
            logHandler.logAuthenticationRejected(
                method: authentication,
                endpoint: endpoint,
                availableMethods: failure.authenticationsThatCanContinue,
                partialSuccess: failure.partialSuccess,
                bannerCount: initialResult.banners.count
            )
            throw self.authenticationRejectedError(
                methodName: "password",
                failure: failure,
                banners: initialResult.banners
            )
        case let .passwordChangeRequired(changeRequest):
            guard let passwordChangeResponseProvider else {
                logHandler.logPasswordChangeRequired(endpoint: endpoint)
                throw self.passwordChangeRequiredError(
                    changeRequest,
                    banners: initialResult.banners
                )
            }

            let initialPublicBanners = self.publicAuthenticationBanners(initialResult.banners)
            let newPassword: String
            do {
                newPassword = try await passwordChangeResponseProvider(
                    SSHPasswordChangeChallenge(
                        username: initialResult.username,
                        serviceName: initialResult.serviceName,
                        prompt: changeRequest.prompt,
                        languageTag: changeRequest.languageTag,
                        banners: initialPublicBanners
                    )
                )
            } catch {
                throw SSHUserCallbackFailure(
                    source: .passwordChangeResponse,
                    error: error
                )
            }

            let changedResult = try await client.authenticatePasswordChange(
                username: username,
                oldPassword: password,
                newPassword: newPassword
            )
            let combinedBanners = initialResult.banners + changedResult.banners

            switch changedResult.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(combinedBanners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: combinedBanners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "password",
                    failure: failure,
                    banners: combinedBanners
                )
            case let .passwordChangeRequired(changeRequest):
                logHandler.logPasswordChangeRequired(endpoint: endpoint)
                throw self.passwordChangeRequiredError(
                    changeRequest,
                    banners: combinedBanners
                )
            }
        }
    }

    private static func authenticate(
        _ authentication: SSHAuthenticationMethod,
        username: String,
        client: SSHTransportProtocolClient,
        endpoint: SSHSocketEndpoint,
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions,
        logHandler: SSHClientLogHandler
    ) async throws -> [SSHAuthenticationBanner] {
        switch authentication {
        case let .password(password):
            return try await self.authenticatePassword(
                password: password,
                passwordChangeResponseProvider: nil,
                username: username,
                client: client,
                endpoint: endpoint,
                authentication: authentication,
                logHandler: logHandler
            )
        case let .passwordWithChangeResponse(password, responseProvider):
            return try await self.authenticatePassword(
                password: password,
                passwordChangeResponseProvider: responseProvider,
                username: username,
                client: client,
                endpoint: endpoint,
                authentication: authentication,
                logHandler: logHandler
            )
        case let .ed25519PrivateKey(rawRepresentation):
            let privateKey = try SSHEd25519PrivateKey(rawRepresentation: rawRepresentation)
            let result = try await client.authenticatePublicKey(
                username: username,
                privateKey: privateKey
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "publickey",
                    failure: failure,
                    banners: result.banners
                )
            }
        case let .rsaPrivateKey(pkcs1DERRepresentation):
            let privateKey = try SSHRSAPrivateKey(
                pkcs1DERRepresentation: pkcs1DERRepresentation
            )
            let result = try await self.authenticateRSAPublicKey(
                username: username,
                privateKey: privateKey,
                authentication: authentication,
                client: client,
                endpoint: endpoint,
                legacyAlgorithmOptions: legacyAlgorithmOptions,
                logHandler: logHandler
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "publickey",
                    failure: failure,
                    banners: result.banners
                )
            }
        case let .ecdsaP256PrivateKey(rawRepresentation):
            let result = try await client.authenticatePublicKey(
                username: username,
                privateKey: SSHECDSAPrivateKey.nistp256(rawRepresentation: rawRepresentation)
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "publickey",
                    failure: failure,
                    banners: result.banners
                )
            }
        case let .ecdsaP384PrivateKey(rawRepresentation):
            let result = try await client.authenticatePublicKey(
                username: username,
                privateKey: SSHECDSAPrivateKey.nistp384(rawRepresentation: rawRepresentation)
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "publickey",
                    failure: failure,
                    banners: result.banners
                )
            }
        case let .ecdsaP521PrivateKey(rawRepresentation):
            let result = try await client.authenticatePublicKey(
                username: username,
                privateKey: SSHECDSAPrivateKey.nistp521(rawRepresentation: rawRepresentation)
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "publickey",
                    failure: failure,
                    banners: result.banners
                )
            }
        case let .publicKey(algorithmNames, publicKey, signatureProvider):
            guard !algorithmNames.isEmpty else {
                throw SSHAuthenticationMethodError.emptyPublicKeyAuthenticationAlgorithmList
            }
            let effectiveAlgorithmNames = self.publicKeyAuthenticationAlgorithmNames(
                algorithmNames,
                legacyAlgorithmOptions: legacyAlgorithmOptions
            )
            guard !effectiveAlgorithmNames.isEmpty else {
                throw SSHAuthenticationMethodError.emptyPublicKeyAuthenticationAlgorithmList
            }
            guard !publicKey.isEmpty else {
                throw SSHAuthenticationMethodError.emptyPublicKeyAuthenticationPublicKey
            }

            let result = try await client.authenticatePublicKey(
                username: username,
                algorithmNames: effectiveAlgorithmNames,
                publicKey: publicKey,
                signatureProvider: { request in
                    do {
                        return try await signatureProvider(request)
                    } catch let error as SSHAuthenticationMethodError {
                        throw error
                    } catch {
                        throw SSHUserCallbackFailure(
                            source: .publicKeySignature,
                            error: error
                        )
                    }
                }
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "publickey",
                    failure: failure,
                    banners: result.banners
                )
            }
        case let .keyboardInteractive(submethods, responseProvider):
            let result = try await client.authenticateKeyboardInteractive(
                username: username,
                submethods: submethods,
                responseProvider: { challenge in
                    do {
                        return try await responseProvider(challenge)
                    } catch let error as SSHAuthenticationMethodError {
                        throw error
                    } catch {
                        throw SSHUserCallbackFailure(
                            source: .keyboardInteractiveResponse,
                            error: error
                        )
                    }
                }
            )
            switch result.outcome {
            case .success:
                logHandler.logAuthenticationSucceeded(
                    method: authentication,
                    endpoint: endpoint
                )
                return self.publicAuthenticationBanners(result.banners)
            case let .failure(failure):
                logHandler.logAuthenticationRejected(
                    method: authentication,
                    endpoint: endpoint,
                    availableMethods: failure.authenticationsThatCanContinue,
                    partialSuccess: failure.partialSuccess,
                    bannerCount: result.banners.count
                )
                throw self.authenticationRejectedError(
                    methodName: "keyboard-interactive",
                    failure: failure,
                    banners: result.banners
                )
            }
        }
    }

    private static func publicKeyAuthenticationAlgorithmNames(
        _ algorithmNames: [String],
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions
    ) -> [String] {
        guard !legacyAlgorithmOptions.allowsSSHRSA else {
            return algorithmNames
        }

        return algorithmNames.filter { $0 != "ssh-rsa" }
    }

    static func authenticateAny(
        _ authentications: [SSHAuthenticationMethod],
        username: String,
        client: SSHTransportProtocolClient,
        endpoint: SSHSocketEndpoint,
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions,
        logHandler: SSHClientLogHandler
    ) async throws -> [SSHAuthenticationBanner] {
        precondition(!authentications.isEmpty, "authentications must not be empty")

        var accumulatedBanners: [SSHAuthenticationBanner] = []
        var lastRejection: SSHClientError?

        for authentication in authentications {
            do {
                let banners = try await self.authenticate(
                    authentication,
                    username: username,
                    client: client,
                    endpoint: endpoint,
                    legacyAlgorithmOptions: legacyAlgorithmOptions,
                    logHandler: logHandler
                )
                return accumulatedBanners + banners
            } catch let error as SSHClientError {
                guard case let .authenticationRejected(
                    methodName,
                    availableMethods,
                    partialSuccess,
                    banners
                ) = error else {
                    throw error
                }

                accumulatedBanners += banners
                lastRejection = .authenticationRejected(
                    methodName: methodName,
                    availableMethods: availableMethods,
                    partialSuccess: partialSuccess,
                    banners: accumulatedBanners
                )
                continue
            }
        }

        if let lastRejection {
            throw lastRejection
        }

        preconditionFailure("authentications must not be empty")
    }

    private static func authenticateRSAPublicKey(
        username: String,
        privateKey: SSHRSAPrivateKey,
        authentication: SSHAuthenticationMethod,
        client: SSHTransportProtocolClient,
        endpoint: SSHSocketEndpoint,
        legacyAlgorithmOptions: SSHLegacyAlgorithmOptions,
        logHandler: SSHClientLogHandler
    ) async throws -> SSHPublicKeyAuthenticationResult {
        let preferredAlgorithms = legacyAlgorithmOptions.preferredRSAPublicKeyAuthenticationAlgorithms
        let initialResult = try await client.authenticatePublicKey(
            username: username,
            privateKey: privateKey,
            preferredAlgorithmNames: preferredAlgorithms
        )

        guard legacyAlgorithmOptions.allowsSSHRSA,
              initialResult.algorithmName != "ssh-rsa",
              case let .failure(failure) = initialResult.outcome,
              failure.authenticationsThatCanContinue.contains("publickey") else {
            return initialResult
        }

        let fallbackResult = try await client.authenticatePublicKey(
            username: username,
            privateKey: privateKey,
            preferredAlgorithmNames: ["ssh-rsa"]
        )

        guard !initialResult.banners.isEmpty else {
            return fallbackResult
        }

        return SSHPublicKeyAuthenticationResult(
            username: fallbackResult.username,
            serviceName: fallbackResult.serviceName,
            algorithmName: fallbackResult.algorithmName,
            banners: initialResult.banners + fallbackResult.banners,
            outcome: fallbackResult.outcome
        )
    }

}
